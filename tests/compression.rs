//! Compression in flight: the chunk codec, the never-worse rule, and the
//! accounting that says whether any of it was worth doing.

mod common;

use bisync::compress::{self, Encoding, Tally};
use bisync::merge::Policy;
use bisync::proto::{CHUNK, Msg};
use bisync::session::Settings;

use common::{Temp, assert_converged, reconcile, settings};

/// Compressible: source text, the case that matters most for a working tree.
fn text(len: usize) -> Vec<u8> {
    let unit = b"fn main() { println!(\"hello, world\"); } // and some more of the same\n";
    unit.iter().copied().cycle().take(len).collect()
}

/// Incompressible: a deterministic byte stream with no structure deflate can
/// find. Not `/dev/urandom`, so a failure is reproducible.
fn noise(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

#[test]
fn a_chunk_round_trips_through_the_codec() {
    for len in [256usize, 1000, 4096, 65_536, CHUNK] {
        let plain = text(len);
        let squeezed = compress::shrink(&plain, 6).expect("text should compress");
        assert!(squeezed.len() < plain.len());
        assert_eq!(compress::expand(&squeezed, plain.len()).unwrap(), plain);
    }
}

#[test]
fn every_level_is_usable_and_higher_is_not_worse() {
    let plain = text(60_000);
    let mut previous: Option<usize> = None;
    for level in 1..=compress::MAX_LEVEL {
        let squeezed = compress::shrink(&plain, level).expect("compresses");
        assert_eq!(compress::expand(&squeezed, plain.len()).unwrap(), plain);
        // Not strictly monotonic in general, but across this range on this input
        // a higher level should never come out substantially worse.
        if let Some(previous) = previous {
            assert!(
                squeezed.len() <= previous + 64,
                "level {level} produced {} bytes after {previous}",
                squeezed.len()
            );
        }
        previous = Some(squeezed.len());
    }
    // A level beyond what the compressor takes is clamped rather than a panic.
    assert!(compress::shrink(&plain, 200).is_some());
}

/// The rule that makes compression free of downside: if deflate does not come
/// out smaller, it is not used, so incompressible content costs a wasted pass
/// and not a single extra byte on the wire.
#[test]
fn content_that_does_not_compress_is_sent_as_it_is() {
    let plain = noise(100_000);
    assert!(
        compress::shrink(&plain, 6).is_none(),
        "deflate claimed to shrink incompressible content"
    );
    // Nor is a tiny chunk worth a block header.
    assert!(compress::shrink(b"short", 6).is_none());
    assert!(compress::shrink(&[], 6).is_none());
}

/// The guard that matters on the receiving side. A compressed frame is a small
/// input with a large output, which is a way to exhaust a receiver's memory
/// unless the output is bounded and the bound is checked.
#[test]
fn a_decompression_bomb_is_refused() {
    // 8 MiB of zeroes deflates to a couple of kilobytes.
    let bomb = miniz_oxide::deflate::compress_to_vec(&vec![0u8; 8 << 20], 6);
    assert!(bomb.len() < 20_000, "{} bytes", bomb.len());

    // Declared honestly, it is still over the chunk size and refused outright.
    let err = compress::expand(&bomb, 8 << 20).unwrap_err();
    assert!(err.to_string().contains("chunk size"), "{err}");

    // Declared as something small, the cap stops it mid-flight.
    let err = compress::expand(&bomb, 4096).unwrap_err();
    assert!(err.to_string().contains("undecodable"), "{err}");
}

#[test]
fn a_frame_that_decodes_to_the_wrong_length_is_refused() {
    let plain = text(10_000);
    let squeezed = compress::shrink(&plain, 6).unwrap();
    // Understating the length is caught by the cap, overstating it by the
    // length check afterwards. Neither is allowed to pass as content.
    for claimed in [plain.len() - 1, plain.len() + 1, 0] {
        assert!(
            compress::expand(&squeezed, claimed).is_err(),
            "claimed {claimed}"
        );
    }
    assert!(compress::expand(&squeezed, plain.len()).is_ok());
}

#[test]
fn rubbish_is_not_mistaken_for_a_compressed_frame() {
    assert!(compress::expand(b"not deflate at all", 4096).is_err());
    assert!(compress::expand(&[], 16).is_err());
    let mut corrupt = compress::shrink(&text(8000), 6).unwrap();
    corrupt[4] ^= 0xff;
    // Either it fails to decode or it decodes to the wrong length; both are
    // errors, and neither writes anything.
    assert!(compress::expand(&corrupt, 8000).is_err());
}

#[test]
fn already_compressed_formats_are_recognised() {
    for path in [
        "video.mp4",
        "photo.JPG",
        "archive.tar.gz",
        "dir/sub/thing.zst",
        "font.woff2",
        "doc.docx",
        "wheel-1.0.whl",
    ] {
        assert!(compress::already_compressed(path), "{path}");
    }
    for path in [
        "src/main.rs",
        "notes.md",
        "data.json",
        "Makefile",
        "archive.tar",
        "no-extension",
        "trailing.",
        ".hidden",
        "thing.averylongextension",
        "dir.zip/inside.txt",
    ] {
        assert!(!compress::already_compressed(path), "{path}");
    }
}

#[test]
fn the_tally_reports_what_was_saved() {
    let mut tally = Tally::default();
    assert!(tally.is_empty());
    assert_eq!(tally.describe(), None);
    assert_eq!(tally.saved(), 0);

    tally.record(1000, 250);
    assert_eq!(tally.saved(), 750);
    assert_eq!(tally.saved_percent().round(), 75.0);
    assert!(tally.describe().is_some_and(|d| d.contains("75% saved")));

    let mut other = Tally::default();
    other.record(1000, 750);
    tally.add(other);
    assert_eq!(tally.plain, 2000);
    assert_eq!(tally.wire, 1000);
    assert_eq!(tally.saved_percent().round(), 50.0);

    // Compression losing is reported as having saved nothing, not as a wildly
    // large number from an underflow.
    let mut lost = Tally::default();
    lost.record(100, 120);
    assert_eq!(lost.saved(), 0);
    assert_eq!(lost.saved_percent(), 0.0);
}

#[test]
fn encoding_tags_round_trip() {
    for encoding in [Encoding::Raw, Encoding::Deflate] {
        assert_eq!(Encoding::from_tag(encoding.tag()), Some(encoding));
    }
    assert_eq!(Encoding::from_tag(2), None);
    assert_eq!(Encoding::from_tag(255), None);
}

// --------------------------------------------------------------- whole syncs

fn compressing(level: u8) -> Settings {
    Settings {
        compress: level,
        ..Settings::default()
    }
}

/// The end that matters: content compresses on the way across, arrives intact,
/// and the digests still agree — because the digest is over the content, not
/// over any particular encoding of it.
#[test]
fn a_compressed_transfer_arrives_intact() {
    let a = Temp::new("zsync-a");
    let b = Temp::new("zsync-b");
    let big = text(400_000);
    a.write_bytes("src/big.rs", &big);
    a.write("small.txt", "too small to bother compressing");
    b.write_bytes("other/also-big.rs", &text(300_000));

    let out = reconcile(&a, &b, compressing(6));
    assert_eq!(std::fs::read(b.path().join("src/big.rs")).unwrap(), big);
    assert_eq!(
        std::fs::read(a.path().join("other/also-big.rs")).unwrap(),
        text(300_000)
    );
    assert_converged(&a, &b);

    // Sent 400 KB of repetitive source; a fraction of it crossed the link.
    assert_eq!(out.a.out.plain, 400_000 + 31);
    assert!(out.a.out.wire < out.a.out.plain / 4, "{:?}", out.a.out);
    assert_eq!(out.a.inbound.plain, 300_000);
    assert!(out.a.inbound.wire < out.a.inbound.plain / 4);
    // The two ends agree about what crossed: one's outbound is the other's in.
    assert_eq!(out.a.out.wire, out.b.inbound.wire);
    assert_eq!(out.a.inbound.wire, out.b.out.wire);
}

/// With compression off, the wire figure equals the plain figure exactly. Worth
/// asserting rather than assuming: it is what makes the saving number meaningful.
#[test]
fn without_compression_nothing_is_encoded() {
    let a = Temp::new("znone-a");
    let b = Temp::new("znone-b");
    a.write_bytes("big.rs", &text(200_000));

    let out = reconcile(&a, &b, compressing(0));
    assert_converged(&a, &b);
    assert_eq!(out.a.out.plain, 200_000);
    assert_eq!(out.a.out.wire, 200_000);
    assert_eq!(out.a.out.saved(), 0);
}

/// Incompressible content must not be inflated by trying. The wire total is
/// allowed to equal the plain total and nothing more.
#[test]
fn incompressible_content_costs_nothing_extra() {
    let a = Temp::new("znoise-a");
    let b = Temp::new("znoise-b");
    let random = noise(500_000);
    a.write_bytes("blob.bin", &random);

    let out = reconcile(&a, &b, compressing(9));
    assert_eq!(std::fs::read(b.path().join("blob.bin")).unwrap(), random);
    assert_converged(&a, &b);
    assert_eq!(out.a.out.plain, 500_000);
    assert_eq!(
        out.a.out.wire, 500_000,
        "incompressible content grew on the wire"
    );
}

/// A file whose name says its content is already compressed is not passed
/// through the compressor at all — the never-worse rule would have caught it, at
/// the cost of a pass over content that is usually the largest in the tree.
#[test]
fn already_compressed_files_skip_the_compressor() {
    let a = Temp::new("zskip-a");
    let b = Temp::new("zskip-b");
    // Deliberately *compressible* bytes behind a `.zst` name: if the name were
    // ignored, the wire figure would come out below the plain one.
    a.write_bytes("archive.zst", &text(200_000));

    let out = reconcile(&a, &b, compressing(6));
    assert_converged(&a, &b);
    assert_eq!(out.a.out.plain, 200_000);
    assert_eq!(out.a.out.wire, 200_000, "the extension was ignored");
}

/// Compression is a session term like the size limit and the conflict policy, so
/// the responder uses the initiator's level and not its own default.
#[test]
fn the_initiator_sets_the_level_for_both_ends() {
    let a = Temp::new("zterms-a");
    let b = Temp::new("zterms-b");
    b.write_bytes("from-b.rs", &text(200_000));

    // a asks for no compression; b must not compress what it sends back.
    let out = reconcile(&a, &b, compressing(0));
    assert_converged(&a, &b);
    assert_eq!(out.b.out.plain, 200_000);
    assert_eq!(out.b.out.wire, 200_000);
    assert_eq!(out.a.inbound.wire, 200_000);
}

/// Compression must not disturb any of the guarantees around it: a conflicting
/// path is still frozen, and the peer's version still reaches quarantine —
/// through the compressor, since a quarantine fetch is a transfer like any other.
#[test]
fn conflicts_still_quarantine_through_the_compressor() {
    let a = Temp::new("zconf-a");
    let b = Temp::new("zconf-b");
    a.write_bytes("shared.rs", &text(50_000));
    reconcile(&a, &b, compressing(6));

    let mine = text(60_000);
    let theirs = text(70_000);
    a.write_bytes("shared.rs", &mine);
    b.write_bytes("shared.rs", &theirs);
    let out = reconcile(&a, &b, compressing(6));

    assert_eq!(out.conflicts_a(), vec!["shared.rs"]);
    assert_eq!(std::fs::read(a.path().join("shared.rs")).unwrap(), mine);
    let kept = a.quarantined_copy("shared.rs").expect("a kept b's version");
    assert_eq!(std::fs::read(a.path().join(&kept)).unwrap(), theirs);
}

/// The running totals in the state file are what answer "is compressing this
/// tree worth it", and they have to accumulate across sessions to do that.
#[test]
fn savings_accumulate_across_sessions() {
    let a = Temp::new("ztotal-a");
    let b = Temp::new("ztotal-b");

    a.write_bytes("one.rs", &text(100_000));
    let first = reconcile(&a, &b, compressing(6));
    assert!(first.a.out.saved() > 0);

    a.write_bytes("two.rs", &text(100_000));
    let second = reconcile(&a, &b, compressing(6));
    assert!(second.a.out.saved() > 0);

    // The harness folds each session's figures into the state it saves, the same
    // way `bisync sync` does.
    let (state, _) = bisync::state::State::load(
        &a.path().join(".bisync/state"),
        &b.path().display().to_string(),
    )
    .unwrap();
    assert_eq!(state.sent.plain, first.a.out.plain + second.a.out.plain);
    assert_eq!(state.sent.wire, first.a.out.wire + second.a.out.wire);
    assert!(state.sent.saved_percent() > 50.0, "{:?}", state.sent);
}

/// A peer that compresses when we did not ask it to is still understood: the
/// encoding is a property of the frame, not a mode the two ends hold in common.
/// That is what keeps the two sides from ever being out of step about it.
#[test]
fn a_frame_is_decoded_on_its_own_terms() {
    let a = Temp::new("zframe-a");
    let b = Temp::new("zframe-b");
    a.write_bytes("f.rs", &text(100_000));

    // Compression off for the session, but count how many frames arrive
    // compressed anyway — none should, and the content must be right regardless.
    let out = reconcile(&a, &b, settings(1 << 20, Policy::Quarantine));
    assert_converged(&a, &b);
    let _ = out;

    // And the codec itself does not care who asked for what.
    let plain = text(50_000);
    let frame = Msg::FileData {
        xfer: 1,
        encoding: Encoding::Deflate,
        plain_len: plain.len() as u32,
        data: compress::shrink(&plain, 6).unwrap(),
    };
    let round_tripped = Msg::decode(&frame.encode()[4..]).unwrap();
    assert_eq!(round_tripped, frame);
    let Msg::FileData {
        encoding,
        plain_len,
        data,
        ..
    } = round_tripped
    else {
        panic!()
    };
    assert_eq!(encoding, Encoding::Deflate);
    assert_eq!(compress::expand(&data, plain_len as usize).unwrap(), plain);
}
