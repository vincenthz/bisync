//! Compressing content in flight.
//!
//! One `FileData` frame at a time, independently, and only when the result is
//! actually smaller: the frame carries which of the two it is, so a chunk that
//! deflate cannot improve on travels as it was. That makes compression never
//! worse than not compressing, chunk by chunk, without any need to buffer a
//! whole file or to negotiate anything beyond "try, or don't".
//!
//! Per chunk rather than per file is a deliberate choice, and it costs almost
//! nothing: DEFLATE's window is 32 KiB and a chunk is [`CHUNK`] — four times
//! that — so a chunk boundary discards no back-references that a whole-file
//! stream would have found. What is repeated per chunk is the Huffman table, on
//! the order of a hundred bytes against 128 KiB. In exchange, each frame decodes
//! on its own: nothing carries over, an aborted transfer leaves no half-consumed
//! decompressor, and the digest and size guards still see plain content.
//!
//! What is *not* compressed is anything else on the wire. Announcements, digests
//! and directory listings are small and already dense, and ssh will squeeze them
//! if asked. Content is where the bytes are.

use std::io;

use crate::proto::CHUNK;
use crate::util;

/// Chunks smaller than this are sent as they are.
///
/// A deflate block costs a header and a Huffman table before it saves anything,
/// so on a hundred bytes the arithmetic rarely comes out ahead — and when it
/// does, it saves a hundred bytes.
const FLOOR: usize = 256;

/// Default compression level. `miniz_oxide` takes 0–10; 6 is the usual
/// middle — most of the ratio for a fraction of the time that 9 and 10 spend
/// hunting for the last percent, which on a link is not a good trade.
pub const DEFAULT_LEVEL: u8 = 6;

/// Highest level `miniz_oxide` accepts.
pub const MAX_LEVEL: u8 = 10;

/// How the bytes in a frame are encoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Encoding {
    /// Content as it is.
    Raw,
    /// Raw DEFLATE — no zlib or gzip wrapper. The wrapper's checksum would be
    /// redundant: every transfer is verified against a BLAKE2b digest of the
    /// whole file, which is a stronger statement than a per-chunk CRC.
    Deflate,
}

impl Encoding {
    pub fn tag(self) -> u8 {
        match self {
            Encoding::Raw => 0,
            Encoding::Deflate => 1,
        }
    }

    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Encoding::Raw),
            1 => Some(Encoding::Deflate),
            _ => None,
        }
    }
}

/// Deflate `plain`, and return it only if it came out smaller.
///
/// `None` means "send it as it is" — because the chunk is too small to be worth
/// a block header, or because deflate made no headway on it. Incompressible
/// content therefore costs one pass of the compressor and no bytes on the wire,
/// rather than deflate's small expansion.
pub fn shrink(plain: &[u8], level: u8) -> Option<Vec<u8>> {
    if plain.len() < FLOOR {
        return None;
    }
    let squeezed = miniz_oxide::deflate::compress_to_vec(plain, level.min(MAX_LEVEL));
    if squeezed.len() < plain.len() {
        Some(squeezed)
    } else {
        None
    }
}

/// Inflate a frame that arrived deflated.
///
/// `plain_len` is what the sender said it would come to, and it is enforced
/// rather than trusted: the output is capped, and a stream that decodes to a
/// different length than announced is refused. Without that a peer could send a
/// few hundred bytes that expand to fill the receiver's memory, which is the one
/// way compression can make a receiver less safe than it was.
pub fn expand(data: &[u8], plain_len: usize) -> io::Result<Vec<u8>> {
    if plain_len > CHUNK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame claims {plain_len} bytes of content, over the {CHUNK}-byte chunk size"),
        ));
    }
    let plain =
        miniz_oxide::inflate::decompress_to_vec_with_limit(data, plain_len).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("undecodable compressed frame: {e:?}"),
            )
        })?;
    if plain.len() != plain_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "frame decoded to {} bytes, not the {plain_len} announced",
                plain.len()
            ),
        ));
    }
    Ok(plain)
}

/// Is this path's content already compressed?
///
/// Purely a way to save the compressor a wasted pass — the never-worse rule in
/// [`shrink`] would catch these anyway. It matters because these are exactly the
/// files that are large: trying to deflate a video wastes far more time than
/// trying to deflate the source file next to it.
pub fn already_compressed(path: &str) -> bool {
    /// Formats whose content is compressed or encrypted by construction. Sorted,
    /// so the list stays easy to add to without duplicating an entry.
    const DENSE: &[&str] = &[
        "7z", "aac", "avi", "br", "bz2", "cab", "deb", "dmg", "docx", "flac", "flv", "gif", "gpg",
        "gz", "heic", "jar", "jpeg", "jpg", "lz4", "lzma", "m4a", "m4v", "mkv", "mov", "mp3",
        "mp4", "odp", "ods", "odt", "ogg", "opus", "png", "pptx", "rar", "rpm", "tgz", "webm",
        "webp", "whl", "woff", "woff2", "xlsx", "xz", "zip", "zst", "zstd",
    ];
    let name = crate::relpath::basename(path);
    let Some((_, extension)) = name.rsplit_once('.') else {
        return false;
    };
    if extension.is_empty() || extension.len() > 5 {
        return false;
    }
    // Only allocates for a name that has a short extension at all, and only to
    // fold its case.
    let extension = extension.to_ascii_lowercase();
    DENSE.binary_search(&extension.as_str()).is_ok()
}

/// Plain bytes against bytes on the wire.
///
/// Kept for the session and accumulated in the state file, because "compression
/// is on" is not the interesting fact — what it saved on this tree is, and it is
/// the only way to tell a link that is helped by compression from one that is
/// merely spending CPU on it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// Content bytes, before compression and after decompression.
    pub plain: u64,
    /// Bytes that actually crossed the link.
    pub wire: u64,
}

impl Tally {
    pub fn record(&mut self, plain: u64, wire: u64) {
        self.plain += plain;
        self.wire += wire;
    }

    pub fn add(&mut self, other: Tally) {
        self.plain += other.plain;
        self.wire += other.wire;
    }

    /// Bytes not sent. Saturating: a tally where compression lost is reported as
    /// having saved nothing rather than as a very large number.
    pub fn saved(&self) -> u64 {
        self.plain.saturating_sub(self.wire)
    }

    /// Proportion of the content that did not have to travel, as a percentage.
    pub fn saved_percent(&self) -> f64 {
        if self.plain == 0 {
            return 0.0;
        }
        self.saved() as f64 * 100.0 / self.plain as f64
    }

    /// The same, floored to a whole percent, for display.
    ///
    /// Floored rather than rounded on purpose: something that saved 99.7% is not
    /// "100% saved", and a reader who sees that number rightly stops believing
    /// the rest of them.
    pub fn percent(&self) -> u64 {
        if self.plain == 0 {
            return 0;
        }
        self.saved() * 100 / self.plain
    }

    pub fn is_empty(&self) -> bool {
        self.plain == 0
    }

    /// `3.4M plain, 1.1M on the wire, 68% saved`. `None` when nothing moved, so
    /// a caller can leave the line out rather than print zeroes.
    pub fn describe(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        Some(format!(
            "{} plain, {} on the wire, {}% saved",
            util::format_size(self.plain),
            util::format_size(self.wire),
            self.percent()
        ))
    }
}
