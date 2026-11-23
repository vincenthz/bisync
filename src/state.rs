//! What bisync remembers between runs, in `.bisync/state`.
//!
//! Three things, and each earns its place:
//!
//! * The **index** — the last scan. Lets the next scan skip re-reading files
//!   whose size, mtime and inode are all unchanged, which is the difference
//!   between a startup that hashes a hundred thousand files and one that stats
//!   them.
//! * The **base** — the state each path was in when the two sides last agreed
//!   about it. Without it there is no way to tell "the peer changed this" from
//!   "I deleted this", and a bidirectional sync without that distinction
//!   resurrects every file you delete.
//! * The **conflicts** — paths frozen pending a human decision, and where the
//!   peer's copy of each was put.
//!
//! Plus a running total of what compression has saved on this root, which is
//! there because a per-session figure answers the wrong question: whether
//! compressing this tree is worth the CPU is a fact about the tree, and it takes
//! more than one session to see it.
//!
//! The base is only meaningful with respect to one peer, so it is stamped with
//! the peer it was built against and discarded if that changes. Losing it is not
//! fatal: the next sync falls back to treating every difference as a conflict
//! rather than guessing, which is noisy but never destructive.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use crate::compress::Tally;
use crate::hash::Digest;
use crate::merge::Conflict;
use crate::proto::Change;
use crate::tree::{Index, PathState, Stamp};
use crate::wire::{DecodeError, Reader, Writer};

const MAGIC: &[u8; 8] = b"bisyncS\x02";

/// A path frozen because both sides changed it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConflictRecord {
    pub kind: Conflict,
    /// When it was noticed, so `bisync conflicts` can be listed oldest first.
    pub detected: Stamp,
    /// The version that stayed in the tree.
    pub local: PathState,
    /// The version the peer had.
    pub remote: PathState,
    /// Where the peer's copy was written, relative to the sync root. Empty when
    /// there was nothing to save — the peer's "version" was a deletion.
    pub quarantine: String,
}

/// The persistent side of a sync root.
#[derive(Clone, Debug, Default)]
pub struct State {
    /// The peer this base was built against, as written in the config. A change
    /// invalidates the base: agreements with one peer say nothing about another.
    pub peer: String,
    /// The last scan.
    pub index: Index,
    /// Path to the state both sides last agreed on. Absent from the map means
    /// [`PathState::Absent`]: the two sides last agreed there was nothing there.
    pub base: BTreeMap<String, PathState>,
    pub conflicts: BTreeMap<String, ConflictRecord>,
    /// Content sent from here since this base was established: plain bytes
    /// against bytes on the wire.
    pub sent: Tally,
    /// Content received here, likewise.
    pub received: Tally,
}

impl State {
    /// Load, or return an empty state if the file does not exist.
    ///
    /// A file that exists but cannot be parsed — a different version, a truncated
    /// write from a killed process — is reported as [`LoadOutcome::Reset`]
    /// rather than an error. The state is a cache of agreements, and rebuilding
    /// it costs a full rescan and some conflict reports, which beats refusing to
    /// run.
    pub fn load(path: &Path, peer: &str) -> io::Result<(State, LoadOutcome)> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok((
                    State {
                        peer: peer.to_string(),
                        ..State::default()
                    },
                    LoadOutcome::Fresh,
                ));
            }
            Err(e) => return Err(e),
        };
        match State::decode(&bytes) {
            Ok(state) if state.peer == peer => Ok((state, LoadOutcome::Loaded)),
            Ok(state) => Ok((
                State {
                    peer: peer.to_string(),
                    ..State::default()
                },
                LoadOutcome::Reset(format!(
                    "state belongs to peer {:?}, not {peer:?}",
                    state.peer
                )),
            )),
            Err(e) => Ok((
                State {
                    peer: peer.to_string(),
                    ..State::default()
                },
                LoadOutcome::Reset(format!("unreadable state file: {e}")),
            )),
        }
    }

    /// Write the state out, replacing any previous copy atomically.
    ///
    /// Via a temporary and a rename, so a crash mid-write leaves the old state
    /// intact rather than a half-written one that would read as `Reset`.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let tmp = path.with_extension("tmp");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&tmp, self.encode())?;
        fs::rename(&tmp, path)
    }

    pub fn base_of(&self, path: &str) -> PathState {
        self.base.get(path).cloned().unwrap_or_default()
    }

    pub fn set_base(&mut self, path: &str, state: PathState) {
        if state.is_absent() {
            self.base.remove(path);
        } else {
            self.base.insert(path.to_string(), state);
        }
    }

    pub fn is_held(&self, path: &str) -> bool {
        self.conflicts.contains_key(path)
    }

    /// Changes to announce: every path where the filesystem has moved away from
    /// the base. Held paths are excluded — a frozen path has nothing to say
    /// until someone unfreezes it.
    ///
    /// Ordered by path, which puts a directory before everything in it. That is
    /// the order a receiver needs for creations; deletions it re-sorts itself.
    pub fn changes_vs_base(&self) -> Vec<Change> {
        let mut changes = Vec::new();
        let mut seen: Vec<&String> = Vec::new();
        for (path, entry) in self.index.iter() {
            if self.is_held(path) {
                continue;
            }
            let base = self.base_of(path);
            let to = entry.state();
            if base != to {
                changes.push(Change {
                    path: path.clone(),
                    from: base,
                    to,
                    mtime: entry.mtime,
                });
            }
            seen.push(path);
        }
        // Deletions: in the base, gone from the tree. `seen` is in the same
        // ordering as `base`, so this is a merge rather than a lookup per key.
        let mut seen = seen.into_iter().peekable();
        for (path, base) in &self.base {
            while seen.peek().is_some_and(|p| *p < path) {
                seen.next();
            }
            if seen.peek() == Some(&path) {
                continue;
            }
            if self.is_held(path) {
                continue;
            }
            changes.push(Change {
                path: path.clone(),
                from: base.clone(),
                to: PathState::Absent,
                mtime: Stamp::default(),
            });
        }
        changes.sort_by(|a, b| a.path.cmp(&b.path));
        changes
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.index.len() * 128);
        w.raw(MAGIC).str(&self.peer);
        w.raw(&self.index.encode());
        w.u32(self.base.len() as u32);
        for (path, state) in &self.base {
            w.str(path);
            state.encode(&mut w);
        }
        for tally in [self.sent, self.received] {
            w.u64(tally.plain).u64(tally.wire);
        }
        w.u32(self.conflicts.len() as u32);
        for (path, record) in &self.conflicts {
            w.str(path)
                .u8(conflict_tag(record.kind))
                .i64(record.detected.secs)
                .u32(record.detected.nanos);
            record.local.encode(&mut w);
            record.remote.encode(&mut w);
            w.str(&record.quarantine);
        }
        w.finish()
    }

    fn decode(bytes: &[u8]) -> Result<State, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.raw(MAGIC.len())? != MAGIC {
            return Err(DecodeError::BadTag {
                field: "state magic",
                tag: 0,
            });
        }
        let peer = r.string("peer")?;
        let index = Index::decode(&mut r)?;
        let mut base = BTreeMap::new();
        let n = r.count("base entries", 5)?;
        for _ in 0..n {
            let path = r.string("path")?;
            crate::relpath::validate(&path)?;
            base.insert(path, PathState::decode(&mut r)?);
        }
        let sent = Tally {
            plain: r.u64()?,
            wire: r.u64()?,
        };
        let received = Tally {
            plain: r.u64()?,
            wire: r.u64()?,
        };
        let mut conflicts = BTreeMap::new();
        let n = r.count("conflict entries", 22)?;
        for _ in 0..n {
            let path = r.string("path")?;
            crate::relpath::validate(&path)?;
            let kind = conflict_from_tag(r.u8()?)?;
            let detected = Stamp {
                secs: r.i64()?,
                nanos: r.u32()?,
            };
            let local = PathState::decode(&mut r)?;
            let remote = PathState::decode(&mut r)?;
            let quarantine = r.string("quarantine path")?;
            conflicts.insert(
                path,
                ConflictRecord {
                    kind,
                    detected,
                    local,
                    remote,
                    quarantine,
                },
            );
        }
        r.finish()?;
        Ok(State {
            peer,
            index,
            base,
            conflicts,
            sent,
            received,
        })
    }

    /// Digest over the base, for a cheap "do we agree about what we agreed on"
    /// check in diagnostics.
    pub fn base_digest(&self) -> Digest {
        let mut w = Writer::new();
        for (path, state) in &self.base {
            w.str(path);
            state.encode(&mut w);
        }
        crate::hash::file_digest(&w.finish())
    }
}

/// What loading the state file turned up.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LoadOutcome {
    /// No state file: a first run.
    Fresh,
    /// Loaded and belongs to this peer.
    Loaded,
    /// Discarded, with the reason. Worth telling the user, because the run that
    /// follows will report conflicts it would not otherwise have reported.
    Reset(String),
}

fn conflict_tag(c: Conflict) -> u8 {
    match c {
        Conflict::BothEdited => 0,
        Conflict::DeletedHereEditedThere => 1,
        Conflict::EditedHereDeletedThere => 2,
        Conflict::TypeClash => 3,
        Conflict::Diverged => 4,
    }
}

fn conflict_from_tag(tag: u8) -> Result<Conflict, DecodeError> {
    match tag {
        0 => Ok(Conflict::BothEdited),
        1 => Ok(Conflict::DeletedHereEditedThere),
        2 => Ok(Conflict::EditedHereDeletedThere),
        3 => Ok(Conflict::TypeClash),
        4 => Ok(Conflict::Diverged),
        tag => Err(DecodeError::BadTag {
            field: "conflict kind",
            tag,
        }),
    }
}
