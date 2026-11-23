//! Turning a directory into an [`Index`].
//!
//! Two things make a scan cheap enough to run at startup on a real tree. The
//! first is that a file whose kind, size, mtime and inode all match the previous
//! scan is not read at all — its digest is carried over. The second is that
//! ignored directories are not descended into, so `target/` costs one `stat`
//! rather than a walk of forty thousand object files.
//!
//! Symlinks are recorded, never followed: a link is synced as a link. Sockets,
//! fifos and device nodes are reported and skipped, because there is nothing
//! meaningful to copy and pretending otherwise would produce a file on the far
//! side that only looks like the original.

use std::fs::{self, Metadata};
use std::io;
use std::path::Path;

use crate::hash::{digest_reader, symlink_digest};
use crate::ignore::IgnoreSet;
use crate::relpath;
use crate::tree::{Entry, Index, Kind, Stamp};

/// How many times a file that keeps changing under us is re-read before giving
/// up on it for this scan. A file being written to continuously — a log, a
/// download — would otherwise hold the scan open indefinitely.
const RETRIES: usize = 3;

/// Everything a scan turns up besides the index itself.
#[derive(Debug, Default)]
pub struct ScanReport {
    pub index: Index,
    /// Files read and digested.
    pub hashed: usize,
    pub hashed_bytes: u64,
    /// Files whose digest was carried over from the previous scan.
    pub reused: usize,
    /// Entries an ignore rule excluded, directories counted as one.
    pub ignored: usize,
    /// Files that changed while being read, `RETRIES` times over. Left out of
    /// the index: whatever digest we computed is already stale, and announcing
    /// it would only invite the peer to ask for bytes that no longer exist.
    pub unstable: Vec<String>,
    /// Names that are not valid UTF-8. They cannot be put on the wire, so they
    /// are reported rather than mangled into something that would sync back as a
    /// different file.
    pub non_utf8: Vec<String>,
    /// Sockets, fifos, device nodes.
    pub special: Vec<String>,
    /// Paths that could not be read, with the reason.
    pub errors: Vec<(String, String)>,
}

impl ScanReport {
    /// Fold a subtree scan's tallies and warnings into this one. The index is
    /// not merged here — the caller splices that, since only it knows what the
    /// subtree is replacing.
    fn absorb(&mut self, other: ScanReport) {
        self.hashed += other.hashed;
        self.hashed_bytes += other.hashed_bytes;
        self.reused += other.reused;
        self.ignored += other.ignored;
        self.unstable.extend(other.unstable);
        self.non_utf8.extend(other.non_utf8);
        self.special.extend(other.special);
        self.errors.extend(other.errors);
    }

    /// A one-line summary for the log.
    pub fn summary(&self) -> String {
        let mut s = format!(
            "{} ({} hashed, {} unchanged)",
            crate::util::count(self.index.len(), "entry", "entries"),
            self.hashed,
            self.reused
        );
        let oversize = self.index.oversize().len();
        if oversize > 0 {
            s.push_str(&format!(", {oversize} over the size limit"));
        }
        if !self.errors.is_empty() {
            s.push_str(&format!(", {} unreadable", self.errors.len()));
        }
        if !self.unstable.is_empty() {
            s.push_str(&format!(", {} still changing", self.unstable.len()));
        }
        s
    }

    /// Lines worth showing the user, beyond the summary.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        for path in &self.unstable {
            out.push(format!(
                "{path}: changing while being read, skipped this round"
            ));
        }
        for name in &self.non_utf8 {
            out.push(format!("{name}: name is not UTF-8, cannot be synced"));
        }
        for path in &self.special {
            out.push(format!(
                "{path}: not a regular file, symlink or directory, skipped"
            ));
        }
        for (path, why) in &self.errors {
            out.push(format!("{path}: {why}"));
        }
        out
    }
}

/// Scan `root`, reusing digests from `previous` where the metadata allows.
pub fn scan(
    root: &Path,
    ignore: &IgnoreSet,
    max_size: u64,
    previous: Option<&Index>,
) -> io::Result<ScanReport> {
    let mut report = scan_at(root, "", ignore, max_size, previous)?;
    report.index.recompute();
    Ok(report)
}

/// Scan the subtree at `start` — a path relative to `root`, `""` for the whole
/// tree. Entries come back keyed relative to `root` either way, so a partial
/// result can be spliced into a full index.
///
/// The directory digests are *not* computed: a partial scan cannot know them,
/// since a parent's digest depends on siblings outside the subtree. Callers
/// finish with [`Index::recompute`], which [`scan`] does for them.
pub fn scan_at(
    root: &Path,
    start: &str,
    ignore: &IgnoreSet,
    max_size: u64,
    previous: Option<&Index>,
) -> io::Result<ScanReport> {
    let mut report = ScanReport::default();
    // Directories still to visit. Depth-first, so the memory held is the depth
    // of the tree rather than its breadth.
    let mut stack = vec![start.to_string()];
    // Ignored directories entered anyway, because a `!` rule might re-include
    // something inside. Pruned at the end if nothing was.
    let mut provisional: Vec<String> = Vec::new();
    let prune = ignore.can_prune();

    while let Some(dir) = stack.pop() {
        let abs = relpath::join(root, &dir);
        let read = match fs::read_dir(&abs) {
            Ok(read) => read,
            // The starting directory not existing is the caller's problem;
            // anything below it is one directory's problem and the scan carries
            // on.
            Err(e) if dir == start => return Err(e),
            Err(e) => {
                report.errors.push((dir.clone(), e.to_string()));
                continue;
            }
        };

        for entry in read {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    report.errors.push((dir.clone(), e.to_string()));
                    continue;
                }
            };
            let name = match entry.file_name().into_string() {
                Ok(name) => name,
                Err(raw) => {
                    report
                        .non_utf8
                        .push(format!("{}/{}", abs.display(), raw.to_string_lossy()));
                    continue;
                }
            };
            let rel = if dir.is_empty() {
                name.clone()
            } else {
                format!("{dir}/{name}")
            };

            let kind = match entry.file_type() {
                Ok(t) if t.is_dir() => Kind::Dir,
                Ok(t) if t.is_symlink() => Kind::Symlink,
                Ok(t) if t.is_file() => Kind::File,
                Ok(_) => {
                    report.special.push(rel);
                    continue;
                }
                Err(e) => {
                    report.errors.push((rel, e.to_string()));
                    continue;
                }
            };

            let ignored = ignore.is_ignored(&rel, kind == Kind::Dir);
            if ignored && (prune || kind != Kind::Dir) {
                report.ignored += 1;
                continue;
            }

            match kind {
                Kind::Dir => {
                    let mode = match entry.metadata() {
                        Ok(md) => mode_of(&md),
                        Err(_) => 0o755,
                    };
                    report.index.insert(rel.clone(), Entry::dir(mode));
                    if ignored {
                        provisional.push(rel.clone());
                    }
                    stack.push(rel);
                }
                Kind::Symlink => match fs::read_link(relpath::join(root, &rel)) {
                    Ok(target) => match target.into_os_string().into_string() {
                        Ok(target) => {
                            let digest = symlink_digest(target.as_bytes());
                            report.index.insert(rel, Entry::symlink(digest, target));
                        }
                        Err(raw) => {
                            report
                                .non_utf8
                                .push(format!("{rel} -> {}", raw.to_string_lossy()));
                        }
                    },
                    Err(e) => report.errors.push((rel, e.to_string())),
                },
                Kind::File => {
                    let md = match entry.metadata() {
                        Ok(md) => md,
                        Err(e) => {
                            report.errors.push((rel, e.to_string()));
                            continue;
                        }
                    };
                    if md.len() > max_size {
                        report.index.mark_oversize(rel, md.len());
                        continue;
                    }
                    if let Some(entry) = file_entry(root, &rel, &md, previous, &mut report) {
                        report.index.insert(rel, entry);
                    }
                }
            }
        }
    }

    // An ignored directory that only ever held ignored things does not belong in
    // the tree. Reverse path order visits children before parents, so a chain of
    // empty ignored directories collapses in one pass.
    if !provisional.is_empty() {
        provisional.sort();
        for dir in provisional.iter().rev() {
            if report.index.range_under(dir).next().is_none() {
                report.index.remove(dir);
                report.ignored += 1;
            }
        }
    }

    Ok(report)
}

/// Bring `index` up to date for just the paths a watcher reported.
///
/// The alternative — a full rescan on every filesystem event — costs one `stat`
/// per file in the tree, which for a large checkout is a hundred milliseconds of
/// syscalls for one keystroke's worth of change. This touches only what moved,
/// and finishes with one [`Index::recompute`] pass over the whole index, which is
/// arithmetic on digests already in memory.
///
/// Paths are handled shallowest-first, so a directory replaced by a file is
/// resolved before anything that used to be inside it is looked for.
pub fn refresh(
    root: &Path,
    ignore: &IgnoreSet,
    max_size: u64,
    index: &mut Index,
    paths: &[String],
) -> io::Result<ScanReport> {
    let mut report = ScanReport::default();
    let mut sorted: Vec<&String> = paths.iter().collect();
    sorted.sort();
    sorted.dedup();

    for rel in sorted {
        if rel.is_empty() {
            // The watcher lost track and is asking for everything.
            let full = scan(root, ignore, max_size, Some(index))?;
            *index = full.index.clone();
            return Ok(full);
        }
        let abs = relpath::join(root, rel);
        let md = match fs::symlink_metadata(&abs) {
            Ok(md) => Some(md),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => {
                report.errors.push((rel.clone(), e.to_string()));
                continue;
            }
        };

        // Whatever used to be here is no longer authoritative. Clearing first
        // means a file that became a directory, or vice versa, leaves nothing
        // behind from its previous shape.
        index.remove_subtree(rel);
        index.remove(rel);

        let Some(md) = md else { continue };
        let is_dir = md.is_dir();
        if ignore.is_ignored(rel, is_dir) {
            report.ignored += 1;
            continue;
        }
        // Every directory above it must exist in the index, or the entry has no
        // parent to hang from and the Merkle tree loses it.
        for ancestor in relpath::ancestors(rel) {
            if ancestor.is_empty() || index.contains(ancestor) {
                continue;
            }
            match fs::symlink_metadata(relpath::join(root, ancestor)) {
                Ok(md) if md.is_dir() => index.insert(ancestor, Entry::dir(mode_of(&md))),
                _ => {}
            }
        }

        if is_dir {
            let sub = scan_at(root, rel, ignore, max_size, Some(index))?;
            index.insert(rel.clone(), Entry::dir(mode_of(&md)));
            for (path, entry) in sub.index.iter() {
                index.insert(path.clone(), entry.clone());
            }
            for (path, size) in sub.index.oversize() {
                index.mark_oversize(path.clone(), *size);
            }
            report.absorb(sub);
        } else if md.is_symlink() {
            match fs::read_link(&abs).map(|t| t.into_os_string().into_string()) {
                Ok(Ok(target)) => {
                    let digest = symlink_digest(target.as_bytes());
                    index.insert(rel.clone(), Entry::symlink(digest, target));
                }
                Ok(Err(raw)) => report.non_utf8.push(raw.to_string_lossy().into_owned()),
                Err(e) => report.errors.push((rel.clone(), e.to_string())),
            }
        } else if md.is_file() {
            if md.len() > max_size {
                index.mark_oversize(rel.clone(), md.len());
            } else if let Some(entry) = file_entry(root, rel, &md, Some(index), &mut report) {
                index.insert(rel.clone(), entry);
            }
        } else {
            report.special.push(rel.clone());
        }
    }

    index.recompute();
    report.index = index.clone();
    Ok(report)
}

/// Digest one file, reusing the previous scan's answer when the metadata says
/// nothing can have changed.
fn file_entry(
    root: &Path,
    rel: &str,
    md: &Metadata,
    previous: Option<&Index>,
    report: &mut ScanReport,
) -> Option<Entry> {
    let observed = Entry {
        kind: Kind::File,
        digest: Default::default(),
        size: md.len(),
        mode: mode_of(md),
        mtime: mtime_of(md),
        ino: ino_of(md),
        target: String::new(),
    };

    if let Some(prev) = previous.and_then(|p| p.get(rel)) {
        if prev.looks_unchanged(&observed) {
            report.reused += 1;
            // The mode is taken from this scan, not the last: a `chmod` changes
            // no bytes, so the fast path has to notice it or it never syncs.
            return Some(Entry {
                digest: prev.digest,
                ..observed
            });
        }
    }

    let abs = relpath::join(root, rel);
    for _ in 0..RETRIES {
        let before = match fs::symlink_metadata(&abs) {
            Ok(md) => md,
            Err(e) => {
                report.errors.push((rel.to_string(), e.to_string()));
                return None;
            }
        };
        let file = match fs::File::open(&abs) {
            Ok(f) => f,
            Err(e) => {
                report.errors.push((rel.to_string(), e.to_string()));
                return None;
            }
        };
        let (digest, size) = match digest_reader(file) {
            Ok(pair) => pair,
            Err(e) => {
                report.errors.push((rel.to_string(), e.to_string()));
                return None;
            }
        };
        // The window that matters is between opening the file and finishing the
        // read. Comparing metadata across it is what turns "we hashed something"
        // into "we hashed this file as it stands".
        let after = match fs::symlink_metadata(&abs) {
            Ok(md) => md,
            Err(e) => {
                report.errors.push((rel.to_string(), e.to_string()));
                return None;
            }
        };
        if mtime_of(&before) == mtime_of(&after)
            && before.len() == after.len()
            && ino_of(&before) == ino_of(&after)
            && size == after.len()
        {
            report.hashed += 1;
            report.hashed_bytes += size;
            return Some(Entry {
                digest,
                size,
                mode: mode_of(&after),
                mtime: mtime_of(&after),
                ino: ino_of(&after),
                ..observed
            });
        }
    }
    report.unstable.push(rel.to_string());
    None
}

/// Permission bits, with the setuid, setgid and sticky bits masked off.
///
/// Those three are not properties of the content but grants of authority on one
/// particular machine, and carrying them across a link would let a change on the
/// weaker end install a setuid binary on the stronger one. rsync needs an
/// explicit flag for the same reason; bisync simply does not do it.
pub fn mode_of(md: &Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        if md.permissions().readonly() {
            0o444
        } else {
            0o644
        }
    }
}

pub fn mtime_of(md: &Metadata) -> Stamp {
    md.modified().map(Stamp::from_system).unwrap_or_default()
}

pub fn ino_of(md: &Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        md.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        0
    }
}
