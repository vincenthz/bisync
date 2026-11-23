//! Content and tree digests.
//!
//! Everything bisync decides is a comparison of two 32-byte BLAKE2b digests: a
//! file's digest covers its bytes, a directory's digest covers the digests of
//! its children, and the digest at the root therefore covers the whole tree.
//! Equal roots mean equal trees, so a session that reconnects to an unchanged
//! peer exchanges two messages and stops; an unequal root is descended child by
//! child, which is what keeps the amount of metadata on the wire proportional to
//! what actually changed rather than to the size of the tree.
//!
//! Each kind of thing hashed is prefixed with a distinct tag, so no directory
//! digest can ever be produced by a file whose contents happen to look like a
//! child listing.

use std::fmt;
use std::io::{self, Read};

use cryptoxide::hashing::blake2b::Blake2b;

/// Tag bytes keeping the three digest domains apart.
const TAG_FILE: u8 = 0x01;
const TAG_SYMLINK: u8 = 0x02;
const TAG_DIR: u8 = 0x03;

/// Size of the buffer files are hashed through. Large enough that the syscall
/// overhead disappears, small enough to stay in L2.
const CHUNK: usize = 64 * 1024;

/// A BLAKE2b-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Digest([u8; 32]);

impl Digest {
    pub const LEN: usize = 32;

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Digest(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse the 64-character lowercase hex form written by [`fmt::Display`].
    pub fn parse_hex(s: &str) -> Option<Self> {
        let s = s.as_bytes();
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (nibble(s[i * 2])? << 4) | nibble(s[i * 2 + 1])?;
        }
        Some(Digest(out))
    }

    /// The leading 12 hex characters, for logs and error messages. Short enough
    /// to read, long enough that two of them are never confused in practice.
    pub fn short(&self) -> String {
        let full = self.to_string();
        full[..12].to_string()
    }
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}

/// Digest of a byte slice, in the file domain.
pub fn file_digest(content: &[u8]) -> Digest {
    let mut ctx = Blake2b::<256>::new();
    ctx.update_mut(&[TAG_FILE]);
    ctx.update_mut(content);
    Digest(ctx.finalize())
}

/// Digest of a symlink, over its target rather than the bytes it resolves to.
/// A link is synced as a link; whether the target exists is the far side's
/// business, and following it would turn one link into a second copy.
pub fn symlink_digest(target: &[u8]) -> Digest {
    let mut ctx = Blake2b::<256>::new();
    ctx.update_mut(&[TAG_SYMLINK]);
    ctx.update_mut(target);
    Digest(ctx.finalize())
}

/// Streaming file digest, for the case where the content is not already in
/// memory. Returns the digest and the number of bytes consumed.
pub fn digest_reader<R: Read>(mut r: R) -> io::Result<(Digest, u64)> {
    let mut ctx = Blake2b::<256>::new();
    ctx.update_mut(&[TAG_FILE]);
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                ctx.update_mut(&buf[..n]);
                total += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok((Digest(ctx.finalize()), total))
}

/// An incremental file digest, for content that arrives or departs in chunks.
///
/// Same domain tag as [`file_digest`], so a file streamed through this and the
/// same bytes hashed in one go give the same answer — which is the whole point:
/// the sender hashes as it reads, the receiver hashes as it writes, and both
/// compare against the digest that was announced.
pub struct Hasher {
    ctx: cryptoxide::hashing::blake2b::Context<256>,
    len: u64,
}

impl Hasher {
    pub fn new() -> Self {
        let mut ctx = Blake2b::<256>::new();
        ctx.update_mut(&[TAG_FILE]);
        Hasher { ctx, len: 0 }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.ctx.update_mut(data);
        self.len += data.len() as u64;
    }

    /// Bytes hashed so far, excluding the domain tag.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn finish(self) -> Digest {
        Digest(self.ctx.finalize())
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Hasher::new()
    }
}

/// What a directory child is, as far as the tree digest is concerned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChildKind {
    File = 1,
    Symlink = 2,
    Dir = 3,
}

/// One child as its parent's digest sees it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Child {
    pub name: Vec<u8>,
    pub kind: ChildKind,
    /// Content digest for a file, target digest for a symlink, subtree digest
    /// for a directory.
    pub digest: Digest,
    /// Permission bits, for files only; zero for anything else.
    ///
    /// Here rather than left out because a `chmod` changes no bytes: if the mode
    /// were absent from the tree, making a script executable would not move any
    /// digest, the descent would never find it, and the two ends would compare
    /// equal while disagreeing about whether the file can be run.
    ///
    /// Zero for directories on purpose. A directory's permissions are far more
    /// often a local decision — a umask, a deliberate `chmod 700` on a laptop —
    /// than something to force on a peer, and including them means the two ends
    /// fight over every directory forever.
    pub mode: u32,
}

impl Child {
    pub fn new(name: &[u8], kind: ChildKind, digest: Digest, mode: u32) -> Child {
        let mode = if kind == ChildKind::File { mode } else { 0 };
        Child {
            name: name.to_vec(),
            kind,
            digest,
            mode,
        }
    }
}

/// Digest of a directory over its children.
///
/// The caller passes children in any order; they are sorted by name here, since
/// two peers must agree on the digest and no two filesystems agree on readdir
/// order. Names are length-prefixed so that `("ab", "c")` and `("a", "bc")`
/// cannot hash alike.
pub fn dir_digest(children: &mut [Child]) -> Digest {
    children.sort_by(|a, b| a.name.cmp(&b.name));
    let mut ctx = Blake2b::<256>::new();
    ctx.update_mut(&[TAG_DIR]);
    for child in children.iter() {
        ctx.update_mut(&(child.name.len() as u32).to_le_bytes());
        ctx.update_mut(&child.name);
        ctx.update_mut(&[child.kind as u8]);
        ctx.update_mut(child.digest.as_bytes());
        ctx.update_mut(&child.mode.to_le_bytes());
    }
    Digest(ctx.finalize())
}

/// The digest of a directory with no syncable children. Worth naming: it is what
/// an empty tree, a tree of nothing but ignored files, and a tree of nothing but
/// oversized files all hash to, and a peer reporting it is reporting "nothing
/// here for you".
pub fn empty_dir_digest() -> Digest {
    dir_digest(&mut [])
}
