//! Scanning a real directory, and the guarded mutations in `store`.

mod common;

use bisync::hash::file_digest;
use bisync::ignore::IgnoreSet;
use bisync::proto::Dest;
use bisync::scan::{refresh, scan};
use bisync::store::{Guarded, Placement, Store};
use bisync::tree::{Kind, PathState, Stamp};

use common::Temp;

const BIG: u64 = 1 << 20;

fn defaults() -> IgnoreSet {
    IgnoreSet::defaults()
}

#[test]
fn a_scan_records_files_directories_and_symlinks() {
    let t = Temp::new("scan");
    t.write("a.txt", "alpha");
    t.write("dir/b.txt", "beta");
    t.mkdir("empty");
    t.symlink("link", "a.txt");

    let report = scan(t.path(), &defaults(), BIG, None).unwrap();
    let index = &report.index;
    assert_eq!(index.count_of(Kind::File), 2);
    assert_eq!(index.count_of(Kind::Dir), 2);
    assert_eq!(index.count_of(Kind::Symlink), 1);
    assert_eq!(index.get("a.txt").unwrap().digest, file_digest(b"alpha"));
    assert_eq!(index.get("a.txt").unwrap().size, 5);
    assert_eq!(report.hashed, 2);
    assert_eq!(report.reused, 0);

    // A symlink is recorded as a link, not followed into a second copy of its
    // target. Its digest is over the target text.
    let link = index.get("link").unwrap();
    assert_eq!(link.kind, Kind::Symlink);
    assert_eq!(link.target, "a.txt");
    assert_eq!(link.digest, bisync::hash::symlink_digest(b"a.txt"));
    assert_ne!(link.digest, index.get("a.txt").unwrap().digest);
}

/// The fast path is what makes startup on a large tree affordable: a file whose
/// metadata is unchanged is not read at all.
#[test]
fn unchanged_files_are_not_read_again() {
    let t = Temp::new("reuse");
    t.write("one.txt", "content");
    t.write("two.txt", "more");
    let first = scan(t.path(), &defaults(), BIG, None).unwrap();
    assert_eq!(first.hashed, 2);

    let second = scan(t.path(), &defaults(), BIG, Some(&first.index)).unwrap();
    assert_eq!(second.hashed, 0);
    assert_eq!(second.reused, 2);
    assert_eq!(second.index.root_digest(), first.index.root_digest());

    // Content changed: read again, and the digest moves.
    t.write("one.txt", "different content");
    let third = scan(t.path(), &defaults(), BIG, Some(&second.index)).unwrap();
    assert_eq!(third.hashed, 1);
    assert_eq!(third.reused, 1);
    assert_ne!(third.index.root_digest(), first.index.root_digest());
}

/// A `chmod` changes no bytes, so the fast path keeps the digest — but it must
/// still notice the mode, or a permission change would never sync.
#[test]
fn the_fast_path_still_notices_a_chmod() {
    let t = Temp::new("chmod");
    t.write("x.sh", "#!/bin/sh\n");
    let first = scan(t.path(), &defaults(), BIG, None).unwrap();
    assert_eq!(first.index.get("x.sh").unwrap().mode, 0o644);

    t.chmod("x.sh", 0o755);
    let second = scan(t.path(), &defaults(), BIG, Some(&first.index)).unwrap();
    assert_eq!(second.index.get("x.sh").unwrap().mode, 0o755);
    assert_eq!(
        second.index.get("x.sh").unwrap().digest,
        first.index.get("x.sh").unwrap().digest
    );
    assert_ne!(second.index.root_digest(), first.index.root_digest());
}

/// The setuid bit is authority on one machine, not a property of the content.
/// Carrying it across a link would let a change on the weaker end install a
/// setuid binary on the stronger one.
#[test]
fn the_setuid_bits_are_not_recorded() {
    let t = Temp::new("setuid");
    t.write("s", "x");
    t.chmod("s", 0o4755);
    let report = scan(t.path(), &defaults(), BIG, None).unwrap();
    assert_eq!(report.index.get("s").unwrap().mode, 0o755);
}

#[test]
fn ignored_directories_are_not_walked() {
    let t = Temp::new("ignore");
    t.write("src/main.rs", "fn main() {}");
    t.write("target/debug/blob", "junk");
    t.write("target/debug/deps/more", "junk");
    t.write(".git/config", "gitstuff");
    t.write("notes.txt.swp", "swap");

    let report = scan(t.path(), &defaults(), BIG, None).unwrap();
    let paths: Vec<&String> = report.index.paths().collect();
    assert_eq!(paths, vec!["src", "src/main.rs"]);
    assert!(report.ignored >= 3);
    // Nothing under an ignored directory was even hashed.
    assert_eq!(report.hashed, 1);
}

/// A `!` rule means an ignored directory may still hold something wanted, so the
/// walk goes in — but an ignored directory that turns out to hold nothing wanted
/// does not end up in the tree.
#[test]
fn a_negation_reaches_inside_an_ignored_directory() {
    let t = Temp::new("negate");
    t.write("target/release/tool", "binary");
    t.write("target/debug/junk", "junk");
    t.write("build/nothing-wanted", "junk");
    let ignore = IgnoreSet::new(["target/", "build/", "!target/release/tool"]);

    let report = scan(t.path(), &ignore, BIG, None).unwrap();
    let paths: Vec<&String> = report.index.paths().collect();
    assert_eq!(
        paths,
        vec!["target", "target/release", "target/release/tool"]
    );
    assert!(!report.index.contains("build"));
    assert!(!report.index.contains("target/debug"));
}

#[test]
fn files_over_the_limit_are_recorded_but_left_out_of_the_tree() {
    let t = Temp::new("oversize");
    t.write_bytes("small.bin", &[7u8; 100]);
    t.write_bytes("big.bin", &[7u8; 5000]);

    let report = scan(t.path(), &defaults(), 1000, None).unwrap();
    assert!(report.index.contains("small.bin"));
    assert!(!report.index.contains("big.bin"));
    assert_eq!(report.index.oversize().get("big.bin"), Some(&5000));
    // And raising the limit brings it in.
    let report = scan(t.path(), &defaults(), 10_000, None).unwrap();
    assert!(report.index.contains("big.bin"));
    assert!(report.index.oversize().is_empty());
}

/// A targeted refresh must leave the index exactly as a full scan would. It is
/// what every watcher event goes through, so a divergence here is a tree that
/// drifts from reality without anyone noticing.
#[test]
fn a_targeted_refresh_matches_a_full_scan() {
    let t = Temp::new("refresh");
    t.write("keep.txt", "keep");
    t.write("dir/a.txt", "a");
    t.write("dir/sub/b.txt", "b");
    let mut index = scan(t.path(), &defaults(), BIG, None).unwrap().index;

    // An edit, a creation, a deletion and a new subtree, all at once.
    t.write("dir/a.txt", "edited");
    t.write("new.txt", "new");
    t.remove("dir/sub/b.txt");
    t.write("fresh/deep/c.txt", "c");
    refresh(
        t.path(),
        &defaults(),
        BIG,
        &mut index,
        &[
            "dir/a.txt".into(),
            "new.txt".into(),
            "dir/sub/b.txt".into(),
            "fresh".into(),
        ],
    )
    .unwrap();

    let full = scan(t.path(), &defaults(), BIG, None).unwrap().index;
    assert_eq!(index.root_digest(), full.root_digest());
    let refreshed: Vec<&String> = index.paths().collect();
    let scanned: Vec<&String> = full.paths().collect();
    assert_eq!(refreshed, scanned);
}

/// A file replaced by a directory of the same name, and the reverse. The refresh
/// has to clear whatever was there rather than leave half of it behind.
#[test]
fn a_refresh_handles_a_path_changing_kind() {
    let t = Temp::new("kindswap");
    t.write("thing", "was a file");
    let mut index = scan(t.path(), &defaults(), BIG, None).unwrap().index;
    assert_eq!(index.get("thing").unwrap().kind, Kind::File);

    t.remove("thing");
    t.write("thing/inside.txt", "now a directory");
    refresh(t.path(), &defaults(), BIG, &mut index, &["thing".into()]).unwrap();
    assert_eq!(index.get("thing").unwrap().kind, Kind::Dir);
    assert!(index.contains("thing/inside.txt"));
    assert_eq!(
        index.root_digest(),
        scan(t.path(), &defaults(), BIG, None)
            .unwrap()
            .index
            .root_digest()
    );

    t.remove("thing");
    t.write("thing", "a file again");
    refresh(t.path(), &defaults(), BIG, &mut index, &["thing".into()]).unwrap();
    assert_eq!(index.get("thing").unwrap().kind, Kind::File);
    assert!(!index.contains("thing/inside.txt"));
    assert_eq!(
        index.root_digest(),
        scan(t.path(), &defaults(), BIG, None)
            .unwrap()
            .index
            .root_digest()
    );
}

/// The empty path means "everything", which is what a dropped watcher event or
/// an expired heartbeat comes to.
#[test]
fn refreshing_the_empty_path_rescans_the_lot() {
    let t = Temp::new("refresh-all");
    t.write("a.txt", "a");
    let mut index = scan(t.path(), &defaults(), BIG, None).unwrap().index;
    t.write("b.txt", "b");
    t.remove("a.txt");
    refresh(t.path(), &defaults(), BIG, &mut index, &[String::new()]).unwrap();
    assert!(index.contains("b.txt"));
    assert!(!index.contains("a.txt"));
}

/// The control directory is never a sync candidate, whatever is in it.
#[test]
fn the_control_directory_is_never_scanned() {
    let t = Temp::new("control");
    t.write("real.txt", "real");
    t.write(".bisync/state", "not for syncing");
    t.write(".bisync/quarantine/old/real.txt", "an old conflict");
    let report = scan(t.path(), &defaults(), BIG, None).unwrap();
    assert_eq!(report.index.paths().collect::<Vec<_>>(), vec!["real.txt"]);
}

/// A name that is not UTF-8 cannot be put on the wire. Reported, not mangled
/// into something that would sync back as a different file.
///
/// Linux only, because it needs such a name to exist: APFS and HFS+ validate
/// filenames as UTF-8 and refuse to create one, which is a fine reason not to
/// run the test and no reason at all to drop the handling — a Linux peer can
/// perfectly well have one.
#[cfg(target_os = "linux")]
#[test]
fn names_that_are_not_utf8_are_reported_and_skipped() {
    use std::os::unix::ffi::OsStrExt;
    let t = Temp::new("nonutf8");
    t.write("fine.txt", "fine");
    let bad = t
        .path()
        .join(std::ffi::OsStr::from_bytes(b"broken-\xff\xfe"));
    std::fs::write(&bad, "content").unwrap();

    let report = scan(t.path(), &defaults(), BIG, None).unwrap();
    assert_eq!(report.index.paths().collect::<Vec<_>>(), vec!["fine.txt"]);
    assert_eq!(report.non_utf8.len(), 1);
    assert!(report.warnings().iter().any(|w| w.contains("not UTF-8")));
}

// ------------------------------------------------------------------- the store

/// Nothing is written in place. A transfer lands in `.bisync/tmp`, is hashed on
/// the way in, and is renamed over the destination only once it checks out.
#[test]
fn a_transfer_is_verified_before_it_is_placed() {
    let t = Temp::new("place");
    let store = Store::open(t.path()).unwrap();
    let content = b"the real content";
    let digest = file_digest(content);

    let mut incoming = store
        .receive(
            1,
            "sub/new.txt",
            Dest::Live,
            digest,
            content.len() as u64,
            0o640,
            Stamp::default(),
        )
        .unwrap();
    for chunk in content.chunks(5) {
        incoming.write(chunk).unwrap();
    }
    assert_eq!(incoming.received(), content.len() as u64);
    // Not there yet.
    assert!(!t.exists("sub/new.txt"));

    let sealed = store.seal(incoming).unwrap();
    let Placement::Done(landed) = store.place(sealed, &PathState::Absent).unwrap() else {
        panic!("expected the file to land");
    };
    assert_eq!(landed.digest, digest);
    assert_eq!(t.read("sub/new.txt"), "the real content");
    assert_eq!(t.mode("sub/new.txt"), 0o640);
    // And nothing was left behind in the temporary area.
    assert_eq!(
        std::fs::read_dir(t.path().join(".bisync/tmp"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn content_that_does_not_match_its_digest_never_reaches_the_tree() {
    let t = Temp::new("corrupt");
    let store = Store::open(t.path()).unwrap();
    let promised = file_digest(b"what was promised");

    let mut incoming = store
        .receive(1, "f.txt", Dest::Live, promised, 8, 0o644, Stamp::default())
        .unwrap();
    incoming.write(b"not that").unwrap();
    match store.seal(incoming) {
        Err(Guarded::Refused(why)) => assert!(why.contains("expected"), "{why}"),
        other => panic!("corrupt content was accepted: {other:?}"),
    }
    assert!(!t.exists("f.txt"));
    assert_eq!(
        std::fs::read_dir(t.path().join(".bisync/tmp"))
            .unwrap()
            .count(),
        0
    );
}

/// A peer that announces eight bytes and then never stops sending must not be
/// able to fill the receiver's disk.
#[test]
fn a_sender_cannot_exceed_what_it_announced() {
    let t = Temp::new("overrun");
    let store = Store::open(t.path()).unwrap();
    let mut incoming = store
        .receive(
            1,
            "f.txt",
            Dest::Live,
            file_digest(b"12345678"),
            8,
            0o644,
            Stamp::default(),
        )
        .unwrap();
    incoming.write(b"12345678").unwrap();
    let err = incoming.write(b"and more").unwrap_err();
    assert!(err.to_string().contains("announced"), "{err}");
    store.discard(incoming);
}

/// The destination is re-read immediately before the rename. If it is not what
/// the decision was made about, the verified copy is handed back rather than
/// written over someone's work.
#[test]
fn a_destination_that_changed_is_not_overwritten() {
    let t = Temp::new("guard");
    let store = Store::open(t.path()).unwrap();
    t.write("f.txt", "as it was");
    let expected = store.current_state("f.txt").unwrap();

    let content = b"from the peer";
    let mut incoming = store
        .receive(
            1,
            "f.txt",
            Dest::Live,
            file_digest(content),
            content.len() as u64,
            0o644,
            Stamp::default(),
        )
        .unwrap();
    incoming.write(content).unwrap();
    let sealed = store.seal(incoming).unwrap();

    // Someone edits it while the transfer is in flight.
    t.write("f.txt", "edited meanwhile");

    let Placement::Changed { actual, sealed } = store.place(sealed, &expected).unwrap() else {
        panic!("the guard let it through");
    };
    assert_eq!(t.read("f.txt"), "edited meanwhile");
    assert_eq!(actual, store.current_state("f.txt").unwrap());
    // The peer's copy is intact and can go somewhere safe.
    let at = store.place_aside(sealed).unwrap();
    assert_eq!(t.read(&at), "from the peer");
    assert_eq!(t.read("f.txt"), "edited meanwhile");
}

/// The check that catches a file edited during its own transfer. No amount of
/// stat'ing beforehand can rule it out, and the bytes had to be hashed anyway.
#[test]
fn a_file_changed_while_being_sent_is_withdrawn() {
    let t = Temp::new("changed-mid-send");
    let store = Store::open(t.path()).unwrap();
    let original = "a".repeat(200_000);
    t.write("f.bin", &original);
    let promised = file_digest(original.as_bytes());

    let mut outgoing = store.send("f.bin", promised).unwrap();
    let mut buf = vec![0u8; 4096];
    // One chunk read, then the file is rewritten under us.
    let n = outgoing.next(&mut buf).unwrap();
    assert!(n > 0);
    t.write("f.bin", &"b".repeat(200_000));
    loop {
        if outgoing.next(&mut buf).unwrap() == 0 {
            break;
        }
    }
    let mismatch = outgoing.verify().unwrap_err();
    assert!(
        mismatch.to_string().contains("changed while being sent"),
        "{mismatch}"
    );

    // And an untouched file verifies.
    let outgoing = store
        .send("f.bin", file_digest("b".repeat(200_000).as_bytes()))
        .unwrap();
    let mut outgoing = outgoing;
    while outgoing.next(&mut buf).unwrap() != 0 {}
    assert!(outgoing.verify().is_ok());
}

#[test]
fn deletion_is_refused_when_the_target_is_not_what_was_agreed() {
    let t = Temp::new("delete-guard");
    let store = Store::open(t.path()).unwrap();
    t.write("f.txt", "original");
    let expected = store.current_state("f.txt").unwrap();
    t.write("f.txt", "someone else's work");

    assert!(matches!(
        store.remove("f.txt", &expected).unwrap(),
        Guarded::Changed(_)
    ));
    assert!(t.exists("f.txt"));

    // With the right expectation, it goes.
    let now = store.current_state("f.txt").unwrap();
    assert!(matches!(
        store.remove("f.txt", &now).unwrap(),
        Guarded::Applied { .. }
    ));
    assert!(!t.exists("f.txt"));
    // And removing what is already gone is not an error.
    assert!(matches!(
        store.remove("f.txt", &now).unwrap(),
        Guarded::Applied { .. }
    ));
}

/// A directory only goes when it is empty. A peer that deleted a tree announces
/// every path in it and the children are applied first; if something is still
/// there, it is something nobody agreed to delete.
#[test]
fn a_directory_with_something_in_it_is_not_removed() {
    let t = Temp::new("rmdir");
    let store = Store::open(t.path()).unwrap();
    t.write("d/unexpected.txt", "not agreed");

    match store.remove("d", &PathState::Dir).unwrap() {
        Guarded::Refused(why) => assert!(why.contains("not empty"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(t.exists("d/unexpected.txt"));

    t.remove("d/unexpected.txt");
    assert!(matches!(
        store.remove("d", &PathState::Dir).unwrap(),
        Guarded::Applied { .. }
    ));
    assert!(!t.exists("d"));
}

#[test]
fn symlinks_are_replaced_atomically_and_only_when_expected() {
    let t = Temp::new("symlink");
    let store = Store::open(t.path()).unwrap();

    assert!(matches!(
        store
            .set_symlink("l", "target-one", &PathState::Absent)
            .unwrap(),
        Guarded::Applied { .. }
    ));
    assert_eq!(
        store.current_state("l").unwrap(),
        PathState::Symlink {
            target: "target-one".into()
        }
    );

    // Repointing it needs the current target to be what was expected.
    let stale = PathState::Symlink {
        target: "something-else".into(),
    };
    assert!(matches!(
        store.set_symlink("l", "target-two", &stale).unwrap(),
        Guarded::Changed(_)
    ));
    assert_eq!(
        store.current_state("l").unwrap(),
        PathState::Symlink {
            target: "target-one".into()
        }
    );

    let current = store.current_state("l").unwrap();
    assert!(matches!(
        store.set_symlink("l", "target-two", &current).unwrap(),
        Guarded::Applied { .. }
    ));
    assert_eq!(
        store.current_state("l").unwrap(),
        PathState::Symlink {
            target: "target-two".into()
        }
    );
    // No staging file left behind.
    assert!(!t.exists(".bisync-link-l"));
}

#[test]
fn saving_aside_preserves_files_and_symlinks_without_moving_them() {
    let t = Temp::new("aside");
    let store = Store::open(t.path()).unwrap();
    t.write("dir/f.txt", "precious");
    t.symlink("dir/l", "f.txt");

    let at = store.save_aside("dir/f.txt").unwrap().unwrap();
    assert!(at.starts_with(".bisync/quarantine/"));
    assert_eq!(t.read(&at), "precious");
    // The live file is untouched: it is the one being worked in.
    assert_eq!(t.read("dir/f.txt"), "precious");

    let at = store.save_aside("dir/l").unwrap().unwrap();
    assert_eq!(
        std::fs::read_link(t.path().join(&at)).unwrap().to_str(),
        Some("f.txt")
    );

    // A directory has nothing to save on its own account.
    assert_eq!(store.save_aside("dir").unwrap(), None);
    assert_eq!(store.save_aside("nowhere").unwrap(), None);
}

#[test]
fn restoring_moves_a_quarantined_copy_back() {
    let t = Temp::new("restore");
    let store = Store::open(t.path()).unwrap();
    t.write("f.txt", "current");
    let at = store.save_aside("f.txt").unwrap().unwrap();
    t.write("f.txt", "newer");

    store.restore(&at, "f.txt").unwrap();
    assert_eq!(t.read("f.txt"), "current");
    assert!(!t.exists(&at));
}

/// Unverified leftovers from a killed run have nothing to salvage: the digest
/// check never ran on them.
#[test]
fn stale_temporaries_are_cleared_on_open() {
    let t = Temp::new("stale");
    t.write(".bisync/tmp/7.abcdef", "half a file");
    let _store = Store::open(t.path()).unwrap();
    assert!(!t.exists(".bisync/tmp/7.abcdef"));
}

#[test]
fn current_state_reads_content_rather_than_trusting_metadata() {
    let t = Temp::new("current");
    let store = Store::open(t.path()).unwrap();
    assert_eq!(store.current_state("nothing").unwrap(), PathState::Absent);
    t.mkdir("d");
    assert_eq!(store.current_state("d").unwrap(), PathState::Dir);
    t.write("f", "body");
    assert_eq!(
        store.current_state("f").unwrap(),
        PathState::File {
            digest: file_digest(b"body"),
            size: 4,
            mode: 0o644
        }
    );
    t.symlink("l", "f");
    assert_eq!(
        store.current_state("l").unwrap(),
        PathState::Symlink { target: "f".into() }
    );
}
