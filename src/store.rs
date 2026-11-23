//! Every filesystem mutation bisync makes, and the guard on each one.
//!
//! Two rules hold throughout, and between them they are why a sync cannot
//! silently destroy work:
//!
//! * **Nothing is written in place.** Incoming content goes to
//!   `.bisync/tmp/`, is hashed as it lands, and is renamed over the destination
//!   only once the digest matches what was promised. A connection that dies
//!   mid-file leaves a temporary to delete, never a half-written file that looks
//!   complete and hashes to nothing anyone has.
//! * **Nothing destructive happens without re-checking the target first.** The
//!   index says what a file was at scan time, which may be seconds or hours ago.
//!   Immediately before an overwrite or an unlink the path is re-stat'ed and, for
//!   a file, re-hashed; if it is not what the decision was made about, the
//!   operation is refused and reported back rather than carried out on a stale
//!   premise.
//! * **Nothing local is destroyed without a copy of it.** A file about to be
//!   overwritten, unlinked, or replaced by a different symlink is first copied to
//!   `.bisync/diffs/<path>.<timestamp>`. The guards above establish that the
//!   change is the right thing to do; this is what makes being wrong about that
//!   survivable. It is done *inside* the operations that do the destroying —
//!   [`Store::place`], [`Store::remove`], [`Store::set_symlink`] — rather than by
//!   their callers, so that the rule holds by construction and a new caller
//!   cannot forget it.
//!
//! Two areas under `.bisync` hold things that are not in the tree, and the
//! distinction between them is worth keeping straight:
//!
//! * `diffs/` — local versions that are **gone from the tree**, replaced or
//!   deleted, each suffixed with the time it happened. The tree's own shape is
//!   kept, so a replaced `src/main.rs` is at
//!   `diffs/src/main.rs.20260821T140311Z` and successive versions of one file
//!   sort together.
//! * `quarantine/` — peer versions that were **not** applied, grouped by the run
//!   that fetched them. A conflicted path's two sides therefore end up one in
//!   each: ours in `diffs/`, theirs in `quarantine/`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::hash::{Digest, Hasher, digest_reader};
use crate::proto::Dest;
use crate::relpath;
use crate::scan::{ino_of, mode_of, mtime_of};
use crate::tree::{PathState, Stamp};
use crate::util;

/// The control directory, relative to the sync root.
pub const CONTROL: &str = ".bisync";

/// The same, for `unisync`, which shares this module and must not share the
/// directory: opening a store empties `tmp`, so a `unisync` run inside a
/// `bisync` root would throw away a running `bisync watch`'s transfers in
/// flight. Both names are forced into every [`crate::ignore::IgnoreSet`], so
/// neither tool ever offers the other's working area to a peer.
pub const UNI_CONTROL: &str = ".unisync";

/// Where local versions that were replaced are kept, relative to the sync root.
pub const DIFFS: &str = ".bisync/diffs";

/// Owns the sync root and the paths under the control directory.
pub struct Store {
    root: PathBuf,
    control: PathBuf,
    tmp: PathBuf,
    /// This run's quarantine directory, named for the time the run started, so
    /// one session's conflicts land together and successive runs do not
    /// interleave.
    quarantine: PathBuf,
    quarantine_rel: String,
    /// `<control>/diffs`, in wire form. Held rather than derived at each use,
    /// because it is what preserved versions are named after and reported as,
    /// and the control directory is no longer one fixed string.
    diffs_rel: String,
    next_xfer: u32,
}

impl Store {
    /// Open a sync root, creating the control directories if needed.
    pub fn open(root: &Path) -> io::Result<Store> {
        Store::open_at(root, CONTROL)
    }

    /// The same, under a named control directory.
    ///
    /// Exists for `unisync`, which reuses every guard in this module and must
    /// keep its temporaries and preserved versions apart from `bisync`'s. The
    /// name is a caller's choice rather than a path, so nothing outside the root
    /// can be made the control directory.
    pub fn open_at(root: &Path, control: &str) -> io::Result<Store> {
        let root = root.canonicalize()?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{} is not a directory", root.display()),
            ));
        }
        relpath::validate(control).map_err(invalid)?;
        let diffs_rel = format!("{control}/diffs");
        let session = util::format_compact(util::now());
        let quarantine_rel = format!("{control}/quarantine/{session}");
        let control = root.join(control);
        let tmp = control.join("tmp");
        let quarantine = control.join("quarantine").join(&session);
        fs::create_dir_all(&tmp)?;
        // Leftovers from a killed run. Their content is unverified by definition
        // — the digest check never ran — so there is nothing to salvage.
        for entry in fs::read_dir(&tmp)?.flatten() {
            let _ = fs::remove_file(entry.path());
        }
        Ok(Store {
            root,
            control,
            tmp,
            quarantine,
            quarantine_rel,
            diffs_rel,
            next_xfer: 1,
        })
    }

    /// Where preserved versions go, relative to the sync root — `.bisync/diffs`
    /// or `.unisync/diffs`, depending on how the store was opened.
    pub fn diffs_rel(&self) -> &str {
        &self.diffs_rel
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn state_path(&self) -> PathBuf {
        self.control.join("state")
    }

    pub fn config_path(&self) -> PathBuf {
        self.control.join("config")
    }

    pub fn log_path(&self) -> PathBuf {
        self.control.join("conflicts.log")
    }

    /// A transfer id unique within this session.
    pub fn next_xfer(&mut self) -> u32 {
        let id = self.next_xfer;
        self.next_xfer = self.next_xfer.wrapping_add(1).max(1);
        id
    }

    /// What is actually at `rel` right now.
    ///
    /// Files are re-read, not just stat'ed. This is the function the guards are
    /// built on, and a guard that trusted a timestamp would not be one.
    pub fn current_state(&self, rel: &str) -> io::Result<PathState> {
        let abs = relpath::join(&self.root, rel);
        let md = match fs::symlink_metadata(&abs) {
            Ok(md) => md,
            // `ENOTDIR` as well as `ENOENT`: a path whose parent is a file does
            // not exist either, and the two are the same answer to the only
            // question being asked. It comes up when one side has replaced a
            // directory with a file and the other is still talking about what
            // used to be inside it.
            Err(e) if is_missing(&e) => return Ok(PathState::Absent),
            Err(e) => return Err(e),
        };
        if md.is_dir() {
            return Ok(PathState::Dir);
        }
        if md.is_symlink() {
            let target = fs::read_link(&abs)?;
            let target = target.into_os_string().into_string().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "symlink target is not UTF-8")
            })?;
            return Ok(PathState::Symlink { target });
        }
        if !md.is_file() {
            // A fifo or a socket. Not `Absent` — something is there and it must
            // not be quietly replaced — but not a state we can describe either.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{rel} is not a regular file, symlink or directory"),
            ));
        }
        let (digest, size) = digest_reader(File::open(&abs)?)?;
        Ok(PathState::File {
            digest,
            size,
            mode: mode_of(&md),
        })
    }

    pub fn mtime_of(&self, rel: &str) -> Stamp {
        fs::symlink_metadata(relpath::join(&self.root, rel))
            .map(|md| mtime_of(&md))
            .unwrap_or_default()
    }

    /// Begin receiving `path`. The bytes go to a temporary in `.bisync/tmp`.
    #[allow(clippy::too_many_arguments)]
    pub fn receive(
        &self,
        xfer: u32,
        path: &str,
        dest: Dest,
        expect: Digest,
        size: u64,
        mode: u32,
        mtime: Stamp,
    ) -> io::Result<Incoming> {
        relpath::validate(path).map_err(invalid)?;
        let tmp = self.tmp.join(format!("{xfer}.{}", expect.short()));
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        Ok(Incoming {
            xfer,
            path: path.to_string(),
            dest,
            expect,
            size,
            mode,
            mtime,
            file: Some(file),
            tmp,
            hasher: Hasher::new(),
            wire: 0,
        })
    }

    /// Begin sending `path`, promising `expect` as its digest.
    pub fn send(&self, path: &str, expect: Digest) -> io::Result<Outgoing> {
        relpath::validate(path).map_err(invalid)?;
        let abs = relpath::join(&self.root, path);
        let md = fs::symlink_metadata(&abs)?;
        if !md.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{path} is not a file"),
            ));
        }
        Ok(Outgoing {
            path: path.to_string(),
            expect,
            size: md.len(),
            mode: mode_of(&md),
            mtime: mtime_of(&md),
            ino: ino_of(&md),
            file: File::open(&abs)?,
            hasher: Hasher::new(),
        })
    }

    /// Check a fully-received transfer against what was promised.
    ///
    /// On success the bytes are still in `.bisync/tmp`; [`Self::place`] moves
    /// them. Splitting it there is what lets a receiver that finds the
    /// destination changed underneath it divert the arrival into quarantine
    /// instead of throwing away a file it already spent the bandwidth on.
    pub fn seal(&self, incoming: Incoming) -> Result<Sealed, Guarded> {
        let Incoming {
            path,
            expect,
            size,
            mode,
            mtime,
            tmp,
            hasher,
            mut file,
            ..
        } = incoming;
        // Close before hashing is compared and before any rename: a handle held
        // open across a rename is legal on Unix and a mistake on Windows.
        drop(file.take());
        let written = hasher.len();
        let digest = hasher.finish();
        if written != size || digest != expect {
            let _ = fs::remove_file(&tmp);
            return Err(Guarded::Refused(format!(
                "{path}: received {written} bytes hashing to {}, expected {size} bytes as {}",
                digest.short(),
                expect.short()
            )));
        }
        Ok(Sealed {
            path,
            tmp,
            digest,
            size,
            mode,
            mtime,
        })
    }

    /// Move a sealed transfer to its real path, if the path is still what the
    /// decision to overwrite was made about.
    ///
    /// Returns the sealed transfer back, untouched, when it is not — the caller
    /// then has a verified copy of the peer's version and a local file that
    /// moved, which is a conflict, and both versions still exist.
    pub fn place(&self, sealed: Sealed, expected: &PathState) -> io::Result<Placement> {
        let actual = self.current_state(&sealed.path)?;
        if actual != *expected {
            return Ok(Placement::Changed { actual, sealed });
        }
        // The guard has passed, so this is going to happen: keep what is there.
        // After the guard rather than before it, so a placement the guard refuses
        // never leaves a copy of a file that is still live.
        let kept = self.preserve(&sealed.path)?;
        let abs = relpath::join(&self.root, &sealed.path);
        self.finalise(&sealed, &abs)?;
        // A directory cannot be renamed over. The guard above passed, so
        // `expected` said `Dir` and the peer means to replace it with a file;
        // `remove_dir` refuses if anything is still inside, and then so does the
        // rename, which is the outcome we want.
        if matches!(expected, PathState::Dir) {
            let _ = fs::remove_dir(&abs);
        }
        if let Err(e) = fs::rename(&sealed.tmp, &abs) {
            self.undo(kept);
            return Err(e);
        }
        Ok(Placement::Done(Landed {
            path: sealed.path,
            digest: sealed.digest,
            size: sealed.size,
            mode: sealed.mode,
            mtime: sealed.mtime,
            kept,
        }))
    }

    /// Move a sealed transfer into this run's quarantine directory, and say
    /// where it went relative to the sync root.
    pub fn place_aside(&self, sealed: Sealed) -> io::Result<String> {
        let (rel, abs) = self.free_quarantine_path(&sealed.path)?;
        self.finalise(&sealed, &abs)?;
        fs::rename(&sealed.tmp, &abs)?;
        Ok(rel)
    }

    /// A quarantine path for `rel` that nothing occupies yet.
    fn free_quarantine_path(&self, rel: &str) -> io::Result<(String, PathBuf)> {
        self.free_path(&format!("{}/{}", self.quarantine_rel, rel))
    }

    /// `base`, or `base.1`, `base.2` … — whichever nothing occupies yet, with its
    /// parent directories created.
    ///
    /// Nothing kept aside is ever overwritten by something else being kept
    /// aside. Both a quarantine directory and a `diffs` suffix are named for the
    /// second they were made in, so two within one second would otherwise
    /// collide — and each copy may be the only remaining version of something,
    /// which makes silently replacing one the exact failure this mechanism exists
    /// to prevent.
    fn free_path(&self, base: &str) -> io::Result<(String, PathBuf)> {
        for attempt in 0..1000 {
            let candidate = if attempt == 0 {
                base.to_string()
            } else {
                format!("{base}.{attempt}")
            };
            let abs = relpath::join(&self.root, &candidate);
            if abs.symlink_metadata().is_err() {
                if let Some(parent) = abs.parent() {
                    fs::create_dir_all(parent)?;
                }
                return Ok((candidate, abs));
            }
        }
        Err(io::Error::other(format!("no free name for {base}")))
    }

    /// Read back a sealed transfer's content, for comparing it with what is in
    /// the tree without putting it there.
    ///
    /// Bounded by the size limit the transfer was accepted under, so this reads a
    /// file bisync was already willing to hold in flight.
    pub fn read_sealed(&self, sealed: &Sealed) -> io::Result<Vec<u8>> {
        fs::read(&sealed.tmp)
    }

    /// Give up on a transfer, received or not.
    pub fn discard(&self, incoming: Incoming) {
        let _ = fs::remove_file(&incoming.tmp);
    }

    pub fn discard_sealed(&self, sealed: Sealed) {
        let _ = fs::remove_file(&sealed.tmp);
    }

    /// Set the permissions and timestamp on the temporary and flush it, so that
    /// the file appears at its destination already complete rather than being
    /// adjusted afterwards in full view of anything watching the tree.
    fn finalise(&self, sealed: &Sealed, dest: &Path) -> io::Result<()> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let handle = OpenOptions::new().write(true).open(&sealed.tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if sealed.mode != 0 {
                handle.set_permissions(fs::Permissions::from_mode(sealed.mode))?;
            }
        }
        // Not every filesystem allows setting times. A timestamp that ends up as
        // "now" is cosmetic; failing the transfer over it would not be.
        let _ = handle.set_times(fs::FileTimes::new().set_modified(sealed.mtime.to_system()));
        handle.sync_all()
    }

    /// Create a directory, if something is not already there.
    pub fn make_dir(&self, rel: &str, mode: u32) -> io::Result<Guarded> {
        match self.current_state(rel)? {
            PathState::Dir => Ok(Guarded::Applied { kept: None }),
            PathState::Absent => {
                let abs = relpath::join(&self.root, rel);
                fs::create_dir_all(&abs)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if mode != 0 {
                        let _ = fs::set_permissions(&abs, fs::Permissions::from_mode(mode));
                    }
                }
                Ok(Guarded::Applied { kept: None })
            }
            actual => Ok(Guarded::Changed(actual)),
        }
    }

    /// Point a symlink at `target`, replacing an existing link only if it is
    /// what the decision was made about.
    pub fn set_symlink(
        &self,
        rel: &str,
        target: &str,
        expected: &PathState,
    ) -> io::Result<Guarded> {
        let actual = self.current_state(rel)?;
        if actual
            == (PathState::Symlink {
                target: target.to_string(),
            })
        {
            return Ok(Guarded::Applied { kept: None });
        }
        if actual != *expected {
            return Ok(Guarded::Changed(actual));
        }
        // A link's target is its content, and repointing it loses the old one.
        // Twenty bytes, and it makes the rule uniform: no exceptions to remember.
        let kept = self.preserve(rel)?;
        let abs = relpath::join(&self.root, rel);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent)?;
        }
        // Create the link under a temporary name in the same directory and
        // rename it into place: `symlink` cannot replace an existing entry, and
        // unlink-then-symlink would leave a window with nothing there at all.
        let staging = abs.with_file_name(format!(".bisync-link-{}", relpath::basename(rel)));
        let _ = fs::remove_file(&staging);
        symlink(target, &staging)?;
        match fs::rename(&staging, &abs) {
            Ok(()) => {}
            Err(e) => {
                let _ = fs::remove_file(&staging);
                self.undo(kept);
                return Err(e);
            }
        }
        Ok(Guarded::Applied { kept })
    }

    /// Delete `rel`, but only if it is still `expected`.
    ///
    /// Directories are removed only when empty. A peer that deleted a whole tree
    /// announces every path in it, and the children are applied before the
    /// parent, so the directory is empty by the time its turn comes — and if it
    /// is not, something arrived that nobody agreed to delete, and it stays.
    pub fn remove(&self, rel: &str, expected: &PathState) -> io::Result<Guarded> {
        let actual = self.current_state(rel)?;
        if actual.is_absent() {
            return Ok(Guarded::Applied { kept: None });
        }
        if actual != *expected {
            return Ok(Guarded::Changed(actual));
        }
        // A deletion destroys local content as surely as an overwrite does, and
        // an agreement that it should be deleted is not a guarantee that whoever
        // agreed meant it. A directory has nothing of its own to preserve, which
        // `preserve` reports as `None`.
        let kept = self.preserve(rel)?;
        let abs = relpath::join(&self.root, rel);
        let result = match actual {
            PathState::Dir => fs::remove_dir(&abs),
            _ => fs::remove_file(&abs),
        };
        match result {
            Ok(()) => Ok(Guarded::Applied { kept }),
            // A non-empty directory, which after the guard above means live
            // content nobody agreed to remove. Report it rather than force it.
            Err(e) if is_not_empty(&e) => {
                self.undo(kept);
                Ok(Guarded::Refused("directory is not empty".into()))
            }
            Err(e) => {
                self.undo(kept);
                Err(e)
            }
        }
    }

    /// Change permissions only. The one case where a file's state differs on the
    /// two sides but its bytes do not, so there is nothing to transfer.
    pub fn set_mode(&self, rel: &str, mode: u32) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if mode != 0 {
                fs::set_permissions(
                    relpath::join(&self.root, rel),
                    fs::Permissions::from_mode(mode),
                )?;
            }
        }
        #[cfg(not(unix))]
        let _ = (rel, mode);
        Ok(())
    }

    /// Copy what is at `rel` into this run's quarantine directory, and return
    /// where it went, relative to the sync root.
    pub fn save_aside(&self, rel: &str) -> io::Result<Option<String>> {
        self.copy_aside(rel, &format!("{}/{}", self.quarantine_rel, rel))
    }

    /// Copy what is at `rel` into `.bisync/diffs`, suffixed with the time, and
    /// return where it went relative to the sync root.
    ///
    /// Called by every operation in this module that is about to destroy local
    /// content — an overwrite, an unlink, a repointed symlink — immediately
    /// before it does. `Ok(None)` when there is nothing there to preserve, which
    /// is the ordinary case for a file arriving for the first time and costs one
    /// `stat`.
    ///
    /// The timestamp is taken now rather than once per run: a long `watch`
    /// session may go through the same path many times over, and each of those
    /// versions is a separate thing someone might want back.
    pub fn preserve(&self, rel: &str) -> io::Result<Option<String>> {
        let stamp = util::format_compact(util::now());
        self.copy_aside(rel, &format!("{}/{rel}.{stamp}", self.diffs_rel))
    }

    /// Undo a [`Self::preserve`] whose change turned out not to happen.
    pub fn discard_preserved(&self, kept: &str) {
        let _ = fs::remove_file(relpath::join(&self.root, kept));
    }

    /// [`Self::discard_preserved`] for the `Option` the guarded operations hold.
    ///
    /// A copy of a file that is, after all, still where it was is not evidence of
    /// anything — it would just accumulate.
    fn undo(&self, kept: Option<String>) {
        if let Some(kept) = kept {
            self.discard_preserved(&kept);
        }
    }

    /// Copy the live `rel` to a free name at or after `base`.
    ///
    /// The source is examined before the destination is reserved, so that a path
    /// with nothing at it — the ordinary case when an incoming file is new —
    /// leaves no empty directories behind under `.bisync`.
    ///
    /// Copies rather than moves: the live file is the one someone is working in,
    /// and taking it away in order to keep it safe would be an odd sort of
    /// safety.
    fn copy_aside(&self, rel: &str, base: &str) -> io::Result<Option<String>> {
        let src = relpath::join(&self.root, rel);
        let md = match fs::symlink_metadata(&src) {
            Ok(md) => md,
            Err(e) if is_missing(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        // A directory has no content of its own to preserve. Anything inside it
        // that gets replaced is kept in its own right.
        if md.is_dir() {
            return Ok(None);
        }
        let (dest_rel, dest) = self.free_path(base)?;
        if md.is_symlink() {
            let target = fs::read_link(&src)?;
            let _ = fs::remove_file(&dest);
            symlink_os(&target, &dest)?;
        } else {
            fs::copy(&src, &dest)?;
        }
        Ok(Some(dest_rel))
    }

    /// How much is in `.bisync/diffs`: how many preserved versions, and their
    /// total size.
    ///
    /// Reported by `bisync status`, because nothing prunes this directory — it is
    /// a safety net, and a safety net that quietly empties itself is not one — so
    /// the only thing keeping it from becoming a surprise is being visible.
    pub fn preserved(&self) -> (usize, u64) {
        let kept = self.list_preserved();
        (kept.len(), kept.iter().map(|k| k.size).sum())
    }

    /// Every preserved version under `.bisync/diffs`, grouped by the path it is a
    /// version of and oldest first within each group.
    ///
    /// Each is reported with the tree path it belongs to and when it was taken,
    /// both read back out of its name. A name that does not parse is reported
    /// with `when: None` rather than skipped: something is in there, and a
    /// listing that silently omitted it would make `prune` look as though it had
    /// tidied up when it had not.
    pub fn list_preserved(&self) -> Vec<Kept> {
        fn walk(root: &Path, prefix: &str, dir: &Path, out: &mut Vec<Kept>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                match entry.file_type() {
                    Ok(t) if t.is_dir() => walk(root, prefix, &path, out),
                    Ok(_) => {
                        let Some(at) = relpath::from_path(root, &path) else {
                            continue;
                        };
                        let size = entry.metadata().map(|md| md.len()).unwrap_or(0);
                        let (of, when) = split_stamp(prefix, &at);
                        out.push(Kept { at, of, when, size });
                    }
                    Err(_) => {}
                }
            }
        }
        let mut out = Vec::new();
        walk(
            &self.root,
            &self.diffs_rel,
            &self.control.join("diffs"),
            &mut out,
        );
        // By path, then oldest first, and by name within one timestamp — so
        // `--keep n` takes a deterministic slice rather than whatever readdir
        // happened to hand back.
        out.sort_by(|a, b| {
            a.of.cmp(&b.of).then_with(|| {
                let key = |k: &Kept| k.when.map(|w| (w.secs, w.nanos));
                key(a).cmp(&key(b)).then_with(|| a.at.cmp(&b.at))
            })
        });
        out
    }

    /// Remove one preserved version, by the `at` of a [`Kept`].
    pub fn remove_preserved(&self, at: &str) -> io::Result<()> {
        fs::remove_file(relpath::join(&self.root, at))
    }

    /// Remove every directory under `.bisync/diffs` with nothing left in it, and
    /// the directory itself if it is empty.
    ///
    /// A chain of emptied directories has to collapse in one pass, so they are
    /// visited deepest first: `remove_dir` refuses a directory with anything in
    /// it, and a parent still holding the child it is about to lose would survive
    /// its own emptying.
    pub fn tidy_preserved(&self) {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    let path = entry.path();
                    walk(&path, out);
                    // After its own children, so the list is already deepest
                    // first and needs no sorting.
                    out.push(path);
                }
            }
        }
        let diffs = self.control.join("diffs");
        let mut dirs = Vec::new();
        walk(&diffs, &mut dirs);
        for dir in &dirs {
            let _ = fs::remove_dir(dir);
        }
        let _ = fs::remove_dir(&diffs);
    }

    /// Move a quarantined copy back into the tree, for `bisync resolve`.
    pub fn restore(&self, quarantined: &str, rel: &str) -> io::Result<()> {
        let src = relpath::join(&self.root, quarantined);
        let dest = relpath::join(&self.root, rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        // Same filesystem — quarantine lives inside the root — so a rename is
        // atomic and the destination is never briefly missing.
        match fs::rename(&src, &dest) {
            Ok(()) => Ok(()),
            // Unless the user moved it out and back across a mount point.
            Err(_) => {
                fs::copy(&src, &dest)?;
                let _ = fs::remove_file(&src);
                Ok(())
            }
        }
    }

    /// Append a line to `.bisync/conflicts.log`, the durable record of every
    /// conflict this root has ever seen.
    pub fn log_conflict(&self, line: &str) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_path())?;
        writeln!(file, "{line}")
    }

    pub fn quarantine_rel(&self) -> &str {
        &self.quarantine_rel
    }

    /// Remove the aside directories if nothing was put in them, so a clean sync
    /// leaves no trail of empty ones. `remove_dir` refuses a directory with
    /// anything in it, which is exactly the test wanted.
    pub fn tidy(&self) {
        let _ = fs::remove_dir(&self.quarantine);
        let _ = fs::remove_dir(self.control.join("quarantine"));
        let _ = fs::remove_dir(self.control.join("diffs"));
    }

    /// Take the control directory itself away, if nothing in it outlived the
    /// run.
    ///
    /// For `unisync`, which keeps no configuration and no state: everything
    /// under its control directory is either a temporary the run has finished
    /// with or a version it preserved, and a tool that leaves an empty directory
    /// in every tree it touches is a tool people learn to resent. `remove_dir`
    /// refuses a directory with anything in it, which is exactly the test
    /// wanted — a run that preserved something leaves the whole trail in place.
    pub fn tidy_control(&self) {
        let _ = fs::remove_dir(&self.tmp);
        let _ = fs::remove_dir(&self.control);
    }
}

/// A transfer being received.
pub struct Incoming {
    pub xfer: u32,
    pub path: String,
    pub dest: Dest,
    pub expect: Digest,
    pub size: u64,
    pub mode: u32,
    pub mtime: Stamp,
    file: Option<File>,
    tmp: PathBuf,
    hasher: Hasher,
    /// Bytes that arrived for this transfer, before decoding. Against the hashed
    /// length — which is content — this is what compression saved on this file.
    wire: u64,
}

impl Incoming {
    /// Take one chunk. Refuses to exceed the announced size, so a peer cannot
    /// make the receiver fill its disk by simply never stopping.
    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        if self.hasher.len() + data.len() as u64 > self.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: sender exceeded the announced {} bytes",
                    self.path, self.size
                ),
            ));
        }
        let file = self.file.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "write after the transfer ended")
        })?;
        file.write_all(data)?;
        self.hasher.update(data);
        Ok(())
    }

    pub fn received(&self) -> u64 {
        self.hasher.len()
    }

    /// Note bytes taken off the wire for this transfer, whatever they decoded to.
    pub fn record_wire(&mut self, bytes: usize) {
        self.wire += bytes as u64;
    }

    pub fn wire(&self) -> u64 {
        self.wire
    }
}

/// A transfer being sent.
pub struct Outgoing {
    pub path: String,
    pub expect: Digest,
    pub size: u64,
    pub mode: u32,
    pub mtime: Stamp,
    pub ino: u64,
    file: File,
    hasher: Hasher,
}

impl Outgoing {
    /// Read the next chunk, or `Ok(0)` at end of file.
    pub fn next(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.file.read(buf) {
                Ok(n) => {
                    self.hasher.update(&buf[..n]);
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    pub fn sent(&self) -> u64 {
        self.hasher.len()
    }

    /// Did we send what we promised?
    ///
    /// The digest over what was actually read is compared with the digest that
    /// was announced. This is the check that catches a file edited during its
    /// own transfer — a case no amount of stat'ing beforehand can rule out — and
    /// it catches it for free, because the bytes had to be hashed anyway.
    pub fn verify(self) -> Result<(), SendMismatch> {
        let sent = self.hasher.len();
        let got = self.hasher.finish();
        if got == self.expect && sent == self.size {
            Ok(())
        } else {
            Err(SendMismatch {
                path: self.path,
                expected: self.expect,
                got,
                sent,
                size: self.size,
            })
        }
    }
}

/// The file changed while it was being sent.
#[derive(Debug)]
pub struct SendMismatch {
    pub path: String,
    pub expected: Digest,
    pub got: Digest,
    pub sent: u64,
    pub size: u64,
}

impl std::fmt::Display for SendMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} changed while being sent ({} bytes as {}, announced {} bytes as {})",
            self.path,
            self.sent,
            self.got.short(),
            self.size,
            self.expected.short()
        )
    }
}

/// One preserved version found under `.bisync/diffs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept {
    /// Where the copy is, relative to the sync root.
    pub at: String,
    /// The path in the tree it is a version of.
    pub of: String,
    /// When it was preserved, or `None` if the name does not say.
    pub when: Option<Stamp>,
    pub size: u64,
}

/// Split `.bisync/diffs/src/main.rs.20260821T140311Z` into the tree path it
/// belongs to and the time it was taken.
///
/// The collision suffix a second copy in the same second gets — `.1`, `.2` — sits
/// after the timestamp, so it comes off first. Anything whose name does not end
/// in a stamp is reported as a version of itself at no particular time, which is
/// the honest answer for a file that something other than bisync put there.
fn split_stamp(diffs: &str, at: &str) -> (String, Option<Stamp>) {
    let bare = at.strip_prefix(&format!("{diffs}/")).unwrap_or(at);
    let mut rest = bare;
    if let Some((head, tail)) = rest.rsplit_once('.') {
        let numeric =
            !tail.is_empty() && tail.len() < 4 && tail.bytes().all(|c| c.is_ascii_digit());
        if numeric
            && head
                .rsplit_once('.')
                .is_some_and(|(_, stamp)| util::parse_compact(stamp).is_some())
        {
            rest = head;
        }
    }
    match rest.rsplit_once('.') {
        Some((of, stamp)) => match util::parse_compact(stamp) {
            Some(when) => (of.to_string(), Some(when)),
            None => (bare.to_string(), None),
        },
        None => (bare.to_string(), None),
    }
}

/// A verified transfer, still in `.bisync/tmp`, waiting to be put somewhere.
#[derive(Debug)]
pub struct Sealed {
    pub path: String,
    tmp: PathBuf,
    pub digest: Digest,
    pub size: u64,
    pub mode: u32,
    pub mtime: Stamp,
}

/// What a file that reached its destination is, for the index and the base.
#[derive(Debug)]
pub struct Landed {
    pub path: String,
    pub digest: Digest,
    pub size: u64,
    pub mode: u32,
    pub mtime: Stamp,
    /// Where the version this one replaced was preserved, if there was one.
    pub kept: Option<String>,
}

#[derive(Debug)]
pub enum Placement {
    Done(Landed),
    /// The destination moved while the transfer was in flight. Nothing was
    /// written; the verified copy is still sealed and can go to quarantine.
    Changed {
        actual: PathState,
        sealed: Sealed,
    },
}

/// How a guarded mutation turned out.
#[derive(Debug)]
pub enum Guarded {
    /// Done, or already so. `kept` is where the local version that the operation
    /// destroyed was preserved, when there was one — so a caller can tell the
    /// user where their file went without having to have arranged it.
    Applied { kept: Option<String> },
    /// The target is not what the decision was made about. Nothing was touched.
    Changed(PathState),
    /// Declined for a reason worth passing on.
    Refused(String),
}

fn invalid(e: crate::wire::DecodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
}

/// `ENOENT` or `ENOTDIR`: either way, nothing is there.
fn is_missing(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    ) || e.raw_os_error() == Some(20)
}

fn is_not_empty(e: &io::Error) -> bool {
    // `DirectoryNotEmpty` is stable, but some platforms report `ENOTEMPTY` as
    // `Other` with the raw code; check both rather than guess.
    e.kind() == io::ErrorKind::DirectoryNotEmpty || e.raw_os_error() == Some(66)
}

#[cfg(unix)]
fn symlink(target: &str, at: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

#[cfg(unix)]
fn symlink_os(target: &Path, at: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

#[cfg(windows)]
fn symlink(target: &str, at: &Path) -> io::Result<()> {
    symlink_os(Path::new(target), at)
}

#[cfg(windows)]
fn symlink_os(target: &Path, at: &Path) -> io::Result<()> {
    // Windows needs to know at creation time whether the link is to a file or a
    // directory, and the target may not exist yet on this side.
    if target.is_dir() {
        std::os::windows::fs::symlink_dir(target, at)
    } else {
        std::os::windows::fs::symlink_file(target, at)
    }
}
