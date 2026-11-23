//! The tree model: what is in a sync root, and its Merkle digest.
//!
//! An [`Index`] is a scan result — one [`Entry`] per file, symlink and directory
//! — plus the directory digests derived from it. Two things are built on top:
//! [`PathState`], the unit that sync decisions are made about, and the
//! child-listing used to descend a divergent tree one level at a time.
//!
//! Files above the configured size limit are held in a separate list and take no
//! part in the digests. That is deliberate rather than incidental: were they
//! counted, a tree containing one 4 GiB file that will never be transferred
//! would have a root digest that never matched, and every session would descend
//! the whole tree to rediscover the same thing.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::hash::{self, ChildKind, Digest, dir_digest, empty_dir_digest};
use crate::relpath::{self, parent};
use crate::wire::{DecodeError, Reader, Writer};

/// What an index entry is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    File,
    Symlink,
    Dir,
}

impl Kind {
    pub fn as_child(self) -> ChildKind {
        match self {
            Kind::File => ChildKind::File,
            Kind::Symlink => ChildKind::Symlink,
            Kind::Dir => ChildKind::Dir,
        }
    }

    fn tag(self) -> u8 {
        self.as_child() as u8
    }

    fn from_tag(tag: u8) -> Result<Self, DecodeError> {
        match tag {
            1 => Ok(Kind::File),
            2 => Ok(Kind::Symlink),
            3 => Ok(Kind::Dir),
            tag => Err(DecodeError::BadTag { field: "kind", tag }),
        }
    }
}

/// A modification time, split so it survives a round trip through the wire
/// without depending on the platform's `SystemTime` representation. Negative
/// seconds are pre-epoch times, which do occur in restored archives.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Stamp {
    pub secs: i64,
    pub nanos: u32,
}

impl Stamp {
    pub fn from_system(t: SystemTime) -> Self {
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => Stamp {
                secs: d.as_secs() as i64,
                nanos: d.subsec_nanos(),
            },
            Err(e) => {
                let d = e.duration();
                // Before the epoch: carry the sub-second part forwards so the
                // pair still reads as (floor seconds, positive remainder).
                if d.subsec_nanos() == 0 {
                    Stamp {
                        secs: -(d.as_secs() as i64),
                        nanos: 0,
                    }
                } else {
                    Stamp {
                        secs: -(d.as_secs() as i64) - 1,
                        nanos: 1_000_000_000 - d.subsec_nanos(),
                    }
                }
            }
        }
    }

    pub fn to_system(self) -> SystemTime {
        if self.secs >= 0 {
            UNIX_EPOCH + Duration::new(self.secs as u64, self.nanos)
        } else {
            let back = Duration::new((-self.secs) as u64, 0) - Duration::new(0, self.nanos);
            UNIX_EPOCH - back
        }
    }
}

/// One entry in a scan.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    pub kind: Kind,
    /// Content digest for files, target digest for symlinks, subtree digest for
    /// directories. Directory digests are filled in by [`Index::recompute`].
    pub digest: Digest,
    /// Byte length for files, 0 otherwise.
    pub size: u64,
    /// Permission bits (`0o7777`), 0 on platforms without them.
    pub mode: u32,
    /// Modification time as last seen. Not part of the digest; used to decide
    /// whether a file needs re-reading, and restored on the receiving side so
    /// timestamps do not drift apart with every sync.
    pub mtime: Stamp,
    /// Inode, where the platform has one. Combined with size and mtime it makes
    /// the "unchanged since last scan" test reliable enough to skip a re-read.
    pub ino: u64,
    /// Symlink target, empty otherwise.
    pub target: String,
}

impl Entry {
    pub fn file(digest: Digest, size: u64, mode: u32, mtime: Stamp) -> Self {
        Entry {
            kind: Kind::File,
            digest,
            size,
            mode,
            mtime,
            ino: 0,
            target: String::new(),
        }
    }

    pub fn symlink(digest: Digest, target: String) -> Self {
        Entry {
            kind: Kind::Symlink,
            digest,
            size: 0,
            mode: 0,
            mtime: Stamp::default(),
            ino: 0,
            target,
        }
    }

    pub fn dir(mode: u32) -> Self {
        Entry {
            kind: Kind::Dir,
            digest: empty_dir_digest(),
            size: 0,
            mode,
            mtime: Stamp::default(),
            ino: 0,
            target: String::new(),
        }
    }

    /// Could this be the same content as `other` without re-reading it?
    ///
    /// A scan fast path, and the only place bisync trusts metadata over content.
    /// All four of kind, size, mtime and inode must agree. The inode is what
    /// catches the case metadata alone would miss — a file replaced wholesale by
    /// a rename, which can land with the size and timestamp of the original.
    /// Where the platform has no inode both sides are 0, and the test degrades
    /// to size and a nanosecond-resolution mtime, as rsync's does.
    pub fn looks_unchanged(&self, other: &Entry) -> bool {
        self.kind == other.kind
            && self.size == other.size
            && self.mtime == other.mtime
            && self.ino == other.ino
    }

    /// The state this entry represents, for the merge.
    pub fn state(&self) -> PathState {
        match self.kind {
            Kind::File => PathState::File {
                digest: self.digest,
                size: self.size,
                mode: self.mode,
            },
            Kind::Symlink => PathState::Symlink {
                target: self.target.clone(),
            },
            Kind::Dir => PathState::Dir,
        }
    }
}

/// What sync decisions are made about: the observable state of one path,
/// stripped of everything that should not by itself cause a transfer.
///
/// Notably absent is the modification time. Two files with the same bytes are
/// the same file; propagating a mismatched mtime as a change would make every
/// `touch` a transfer, and two peers whose clocks disagree would ping-pong. The
/// mtime still rides along with a transfer so it can be restored, it just does
/// not decide anything.
///
/// Directories carry no mode either. A directory's permissions are far more
/// often a local decision (umask, a deliberate `chmod 700` on a laptop) than
/// something to force on a peer, and making them part of the state means the
/// two ends fight over every directory forever.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum PathState {
    /// Nothing here — never existed, or deleted.
    #[default]
    Absent,
    File {
        digest: Digest,
        size: u64,
        mode: u32,
    },
    Symlink {
        target: String,
    },
    Dir,
}

impl PathState {
    pub fn is_absent(&self) -> bool {
        matches!(self, PathState::Absent)
    }

    pub fn kind(&self) -> Option<Kind> {
        match self {
            PathState::Absent => None,
            PathState::File { .. } => Some(Kind::File),
            PathState::Symlink { .. } => Some(Kind::Symlink),
            PathState::Dir => Some(Kind::Dir),
        }
    }

    /// The digest identifying this state, for display and for the `from -> to`
    /// pair on the wire. Directories get the empty-directory digest: a directory
    /// either exists or does not, and its contents are the children's business.
    pub fn digest(&self) -> Digest {
        match self {
            PathState::Absent => Digest::default(),
            PathState::File { digest, .. } => *digest,
            PathState::Symlink { target } => crate::hash::symlink_digest(target.as_bytes()),
            PathState::Dir => empty_dir_digest(),
        }
    }

    /// Does applying this state require the peer to send content?
    pub fn needs_content(&self) -> bool {
        matches!(self, PathState::File { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            PathState::Absent => "absent".to_string(),
            PathState::File { digest, size, mode } => {
                format!("file {} {size}b {mode:04o}", digest.short())
            }
            PathState::Symlink { target } => format!("symlink -> {target}"),
            PathState::Dir => "directory".to_string(),
        }
    }

    pub fn encode(&self, w: &mut Writer) {
        match self {
            PathState::Absent => {
                w.u8(0);
            }
            PathState::File { digest, size, mode } => {
                w.u8(1).raw(digest.as_bytes()).u64(*size).u32(*mode);
            }
            PathState::Symlink { target } => {
                w.u8(2).str(target);
            }
            PathState::Dir => {
                w.u8(3);
            }
        }
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            0 => Ok(PathState::Absent),
            1 => {
                let digest = Digest::from_bytes(r.raw(Digest::LEN)?.try_into().unwrap());
                let size = r.u64()?;
                let mode = r.u32()?;
                Ok(PathState::File { digest, size, mode })
            }
            2 => Ok(PathState::Symlink {
                target: r.string("symlink target")?,
            }),
            3 => Ok(PathState::Dir),
            tag => Err(DecodeError::BadTag {
                field: "path state",
                tag,
            }),
        }
    }
}

/// One child of a directory, as listed to a peer descending the tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Child {
    pub name: String,
    pub kind: Kind,
    /// Subtree digest for a directory, content digest otherwise.
    pub digest: Digest,
    pub size: u64,
    pub mode: u32,
    /// Carried although it is not part of any digest, because the `newer`
    /// conflict policy has nothing to compare without it and a descent is
    /// exactly where a conflict tends to be found.
    pub mtime: Stamp,
    pub target: String,
}

/// A scanned tree.
#[derive(Clone, Debug)]
pub struct Index {
    /// Every entry, keyed by path relative to the root. The root itself is not
    /// a member; its digest is [`Index::root_digest`].
    entries: BTreeMap<String, Entry>,
    /// Files skipped for exceeding the size limit, with the size that did it.
    /// Held apart so they affect no digest, and reported so the skip is visible.
    oversize: BTreeMap<String, u64>,
    root: Digest,
}

impl Default for Index {
    fn default() -> Self {
        Index {
            entries: BTreeMap::new(),
            oversize: BTreeMap::new(),
            root: empty_dir_digest(),
        }
    }
}

impl Index {
    pub fn new() -> Self {
        Index::default()
    }

    pub fn insert(&mut self, path: impl Into<String>, entry: Entry) {
        self.entries.insert(path.into(), entry);
    }

    pub fn remove(&mut self, path: &str) -> Option<Entry> {
        self.oversize.remove(path);
        self.entries.remove(path)
    }

    pub fn get(&self, path: &str) -> Option<&Entry> {
        self.entries.get(path)
    }

    pub fn get_mut(&mut self, path: &str) -> Option<&mut Entry> {
        self.entries.get_mut(path)
    }

    pub fn contains(&self, path: &str) -> bool {
        self.entries.contains_key(path)
    }

    pub fn mark_oversize(&mut self, path: impl Into<String>, size: u64) {
        let path = path.into();
        self.entries.remove(&path);
        self.oversize.insert(path, size);
    }

    pub fn oversize(&self) -> &BTreeMap<String, u64> {
        &self.oversize
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Entry)> {
        self.entries.iter()
    }

    pub fn paths(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total bytes of file content in the tree, excluding what was skipped.
    pub fn total_bytes(&self) -> u64 {
        self.entries
            .values()
            .filter(|e| e.kind == Kind::File)
            .map(|e| e.size)
            .sum()
    }

    pub fn count_of(&self, kind: Kind) -> usize {
        self.entries.values().filter(|e| e.kind == kind).count()
    }

    /// The state of `path`, which is [`PathState::Absent`] for anything not in
    /// the index — including a file skipped for its size, since as far as the
    /// protocol is concerned such a file is not there.
    pub fn state(&self, path: &str) -> PathState {
        self.entries.get(path).map(Entry::state).unwrap_or_default()
    }

    /// Digest of the whole tree. Valid only after [`Self::recompute`].
    pub fn root_digest(&self) -> Digest {
        self.root
    }

    /// Digest of one directory's subtree, or `None` if it is not a directory
    /// here. `""` is the root.
    pub fn dir_digest(&self, dir: &str) -> Option<Digest> {
        if dir.is_empty() {
            return Some(self.root);
        }
        self.entries
            .get(dir)
            .filter(|e| e.kind == Kind::Dir)
            .map(|e| e.digest)
    }

    /// The direct children of `dir`, sorted by name.
    ///
    /// A linear scan of the entries under `dir` — the map is ordered, so the
    /// range is contiguous and the cost is the size of the subtree, not of the
    /// tree. Descending a divergent path visits each level once.
    pub fn children(&self, dir: &str) -> Vec<Child> {
        let mut out = Vec::new();
        for (path, entry) in self.range_under(dir) {
            if parent(path) != dir {
                continue;
            }
            out.push(Child {
                name: relpath::basename(path).to_string(),
                kind: entry.kind,
                digest: entry.digest,
                size: entry.size,
                mode: entry.mode,
                mtime: entry.mtime,
                target: entry.target.clone(),
            });
        }
        out
    }

    /// Every entry at or below `dir`, in path order.
    pub fn range_under(&self, dir: &str) -> impl Iterator<Item = (&String, &Entry)> {
        let (start, end) = subtree_bounds(dir);
        self.entries
            .range(start..)
            .take_while(move |(p, _)| match &end {
                Some(end) => p.as_str() < end.as_str(),
                None => true,
            })
    }

    /// Drop `dir` and everything beneath it.
    pub fn remove_subtree(&mut self, dir: &str) -> Vec<String> {
        let victims: Vec<String> = self
            .range_under(dir)
            .map(|(p, _)| p.clone())
            .chain(std::iter::once(dir.to_string()).filter(|d| !d.is_empty()))
            .collect();
        for path in &victims {
            self.entries.remove(path);
        }
        self.oversize
            .retain(|p, _| !(p == dir || relpath::is_under(p, dir)));
        victims
    }

    /// Recompute every directory digest, and the root, from the leaves up.
    ///
    /// Directories are visited in reverse path order, which puts every child
    /// before its parent: a child's path is its parent's path plus a separator
    /// and more, so it sorts after the parent, and reversing puts it first. One
    /// pass therefore suffices, with no recursion and no depth sort.
    pub fn recompute(&mut self) {
        let mut pending: BTreeMap<String, Vec<hash::Child>> = BTreeMap::new();
        let mut fixups: Vec<(String, Digest)> = Vec::new();

        for (path, entry) in self.entries.iter().rev() {
            let digest = if entry.kind == Kind::Dir {
                let mut children = pending.remove(path).unwrap_or_default();
                let d = dir_digest(&mut children);
                fixups.push((path.clone(), d));
                d
            } else {
                entry.digest
            };
            pending
                .entry(parent(path).to_string())
                .or_default()
                .push(hash::Child::new(
                    relpath::basename(path).as_bytes(),
                    entry.kind.as_child(),
                    digest,
                    entry.mode,
                ));
        }

        for (path, digest) in fixups {
            if let Some(entry) = self.entries.get_mut(&path) {
                entry.digest = digest;
            }
        }
        let mut root_children = pending.remove("").unwrap_or_default();
        self.root = dir_digest(&mut root_children);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.entries.len() * 96);
        w.u32(self.entries.len() as u32);
        for (path, entry) in &self.entries {
            w.str(path)
                .u8(entry.kind.tag())
                .raw(entry.digest.as_bytes())
                .u64(entry.size)
                .u32(entry.mode)
                .i64(entry.mtime.secs)
                .u32(entry.mtime.nanos)
                .u64(entry.ino)
                .str(&entry.target);
        }
        w.u32(self.oversize.len() as u32);
        for (path, size) in &self.oversize {
            w.str(path).u64(*size);
        }
        w.raw(self.root.as_bytes());
        w.finish()
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let mut index = Index::new();
        // A file entry cannot occupy fewer than 4 (path len) + 1 + 32 + 8 + 4 +
        // 8 + 4 + 8 + 4 bytes; 60 is a safe floor for the allocation guard.
        let n = r.count("index entries", 60)?;
        for _ in 0..n {
            let path = r.string("path")?;
            relpath::validate(&path)?;
            let kind = Kind::from_tag(r.u8()?)?;
            let digest = Digest::from_bytes(r.raw(Digest::LEN)?.try_into().unwrap());
            let size = r.u64()?;
            let mode = r.u32()?;
            let mtime = Stamp {
                secs: r.i64()?,
                nanos: r.u32()?,
            };
            let ino = r.u64()?;
            let target = r.string("symlink target")?;
            index.entries.insert(
                path,
                Entry {
                    kind,
                    digest,
                    size,
                    mode,
                    mtime,
                    ino,
                    target,
                },
            );
        }
        let n = r.count("oversize entries", 12)?;
        for _ in 0..n {
            let path = r.string("path")?;
            relpath::validate(&path)?;
            index.oversize.insert(path, r.u64()?);
        }
        index.root = Digest::from_bytes(r.raw(Digest::LEN)?.try_into().unwrap());
        Ok(index)
    }
}

/// The half-open key range covering `dir`'s subtree.
///
/// `"a"` covers `["a/", "a0")` — `'0'` is the byte after `'/'`, so the range
/// stops before `a0`, `aa`, and every other sibling that merely starts with
/// `a`, while including everything genuinely below `a/`.
fn subtree_bounds(dir: &str) -> (String, Option<String>) {
    if dir.is_empty() {
        return (String::new(), None);
    }
    let start = format!("{dir}/");
    let mut end = start.into_bytes();
    let last = end.len() - 1;
    end[last] = b'/' + 1;
    (format!("{dir}/"), Some(String::from_utf8(end).unwrap()))
}
