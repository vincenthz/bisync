//! Noticing that something changed.
//!
//! The platform interfaces — FSEvents, inotify, `ReadDirectoryChangesW`, kqueue
//! — come from the [`notify`] crate, which picks the right one and has already
//! been debugged against all of them. Underneath it sits a periodic full rescan,
//! which is both the fallback where no backend works and the safety net under
//! the ones that do: every event-driven interface can drop events under load,
//! and a dropped event must cost a delay rather than a permanently missed file.
//!
//! What this module adds to `notify` is the part specific to synchronising:
//! debouncing, ignore filtering, and the reduction of an event to a bare path.
//! bisync deliberately does not care *what* an event says happened — a create, a
//! write, a rename — because the scan re-reads the path and works that out for
//! itself, from the filesystem rather than from an event's opinion of it.
//!
//! What comes out is a *debounced set of paths*. Debouncing is not a nicety
//! here: saving a file in an editor produces a burst of events — a temporary
//! created, written, `fsync`ed, renamed over the target, the original unlinked —
//! and acting on the first would announce a digest for a file still being
//! written. So a batch is returned only once the tree has been quiet for
//! [`Config::debounce`](crate::config::Config::debounce).
//!
//! Paths come back relative to the root and already filtered: an ignored path
//! never reaches the session, so `target/` churning during a build costs the
//! watcher thread a pattern match and nothing else.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use notify::{RecommendedWatcher, RecursiveMode, Watcher as _, WatcherKind};

use crate::ignore::IgnoreSet;
use crate::relpath;
use crate::wake::Wake;

/// What the backend reports.
pub enum Raw {
    /// This path changed somehow. Backends are not required to say how; the
    /// scan re-reads it and works that out for itself, which is both simpler and
    /// more reliable than trusting an event's opinion.
    Path(PathBuf),
    /// Events were dropped, or the root itself moved. Everything must be
    /// re-examined.
    Rescan,
}

/// A running watch on a directory tree.
///
/// Holding one is what keeps it running; dropping it stops the backend and the
/// debouncer. Nothing is read from it — batches arrive on the [`Wake`] channel
/// given to [`Watcher::start`].
pub struct Watcher {
    kind: &'static str,
    /// Kept alive for its `Drop`, which is what stops the backend.
    backend: Option<Native>,
    debouncer: Option<JoinHandle<()>>,
}

/// Held only for its `Drop`; the payloads are never read.
#[allow(dead_code)]
enum Native {
    /// A running `notify` watcher. Dropping it stops the platform backend and
    /// releases the event handler, and with it the last sender.
    Notify(RecommendedWatcher),
    /// No backend, so the heartbeat is the only source of notifications and the
    /// watcher becomes a periodic full rescan.
    ///
    /// The sender is held for one reason: it is the last one, and dropping it
    /// would close the channel and end the debouncer before it had emitted a
    /// single heartbeat.
    Polling(Sender<Raw>),
}

impl Watcher {
    /// Start watching `root`, delivering debounced batches to `out`.
    ///
    /// `poll_only` forces the rescan-only backend. Worth having as a switch
    /// rather than only a fallback: a directory on NFS or SMB produces no local
    /// events at all when the change was made by another machine, so a native
    /// watcher there is not a fast path but a silent failure.
    pub fn start(
        root: &Path,
        ignore: IgnoreSet,
        debounce: Duration,
        heartbeat: Duration,
        poll_only: bool,
        out: Sender<Wake>,
    ) -> io::Result<Watcher> {
        let (tx, rx) = mpsc::channel();
        // The sender is cloned rather than moved, so a native backend that fails
        // to start still leaves a live channel for the heartbeat to use.
        let (backend, kind) = match if poll_only {
            None
        } else {
            start_native(root, tx.clone())
        } {
            Some(started) => started,
            None => (Native::Polling(tx), "rescan"),
        };
        let root = root.to_path_buf();
        let debouncer = thread::Builder::new()
            .name("bisync-debounce".into())
            .spawn(move || debounce_loop(root, ignore, debounce, heartbeat, rx, out))?;
        Ok(Watcher {
            kind,
            backend: Some(backend),
            debouncer: Some(debouncer),
        })
    }

    /// Which backend is in use, for the startup line.
    pub fn kind(&self) -> &'static str {
        self.kind
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        // The backend goes first: dropping it releases the last sender, and the
        // closed channel is what ends the debouncer.
        self.backend.take();
        if let Some(thread) = self.debouncer.take() {
            let _ = thread.join();
        }
    }
}

/// Collect raw events into quiet-period batches.
///
/// The rule: nothing is emitted until the tree has been silent for `debounce`.
/// Saving a file in an editor produces a burst — a temporary created, written,
/// `fsync`ed, renamed over the target, the original unlinked — and acting on the
/// first event would announce a digest for a file still being written.
///
/// A batch is also emitted when `heartbeat` passes with nothing happening, as a
/// single empty path meaning "look at everything". That is the safety net under
/// both native backends, since each can drop events under load, and the only
/// mechanism at all when there is no native backend.
fn debounce_loop(
    root: PathBuf,
    ignore: IgnoreSet,
    debounce: Duration,
    heartbeat: Duration,
    rx: Receiver<Raw>,
    out: Sender<Wake>,
) {
    let mut batch: BTreeSet<String> = BTreeSet::new();
    let mut full = false;
    let mut last_full = Instant::now();

    loop {
        let quiet = batch.is_empty() && !full;
        let wait = if quiet {
            heartbeat.saturating_sub(last_full.elapsed())
        } else {
            debounce
        };
        match rx.recv_timeout(wait.max(Duration::from_millis(1))) {
            Ok(Raw::Rescan) => full = true,
            Ok(Raw::Path(path)) => {
                if let Some(rel) = relative(&root, &ignore, &path) {
                    batch.insert(rel);
                }
            }
            Err(RecvTimeoutError::Timeout) if quiet => {
                if last_full.elapsed() >= heartbeat {
                    last_full = Instant::now();
                    if out.send(Wake::Local(vec![String::new()])).is_err() {
                        return;
                    }
                }
            }
            // Quiet for a full debounce window with something in hand: emit.
            Err(RecvTimeoutError::Timeout) => {
                // A batch above a few thousand paths costs more to apply one at
                // a time than a single rescan does, and the rescan is the more
                // reliable of the two.
                let paths = if full || batch.len() > 4096 {
                    last_full = Instant::now();
                    batch.clear();
                    vec![String::new()]
                } else {
                    std::mem::take(&mut batch).into_iter().collect()
                };
                full = false;
                if !paths.is_empty() && out.send(Wake::Local(paths)).is_err() {
                    return;
                }
            }
            // The backend has gone. Keep the heartbeat going: a slower watcher
            // is worth having, a silent one is not.
            Err(RecvTimeoutError::Disconnected) => {
                if !batch.is_empty() || full {
                    let paths: Vec<String> = if full {
                        vec![String::new()]
                    } else {
                        std::mem::take(&mut batch).into_iter().collect()
                    };
                    let _ = out.send(Wake::Local(paths));
                }
                return;
            }
        }
    }
}

/// An absolute path from a backend, as a relative path worth acting on.
///
/// Whether a path is ignored can depend on its kind — `target/` excludes a
/// directory called `target` and not a file of that name — so the path is
/// `stat`ed. That costs one syscall per event and saves the whole rescan those
/// events would otherwise trigger: without it, a build churning through
/// `target/` reaches the session, because the directory itself is only ignored
/// when it is known to be one.
///
/// An event for a path that has already gone says nothing about what it was. It
/// is kept if a file of that name would have been syncable, since the point of
/// hearing about a deletion is to remove it from the index — and if it was
/// ignored, it was never in the index and the rescan finds nothing to do.
fn relative(root: &Path, ignore: &IgnoreSet, path: &Path) -> Option<String> {
    let rel = relpath::from_path(root, path)?;
    if rel.is_empty() {
        return None;
    }
    let is_dir = match path.symlink_metadata() {
        Ok(md) => md.is_dir(),
        Err(_) => false,
    };
    if ignore.is_ignored(&rel, is_dir) {
        return None;
    }
    Some(rel)
}

/// Start the platform's watcher, or `None` to fall back to rescanning.
///
/// Failure is not an error. On Linux it usually means `max_user_watches` is
/// exhausted by a large tree; rescanning is slower but correct, and better than
/// refusing to run.
fn start_native(root: &Path, tx: Sender<Raw>) -> Option<(Native, &'static str)> {
    let mut watcher = notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
        match result {
            Ok(event) => {
                // The backend is telling us it lost track — an overflowed queue,
                // a watched directory moved out from under it. Everything has to
                // be looked at again.
                if event.need_rescan() {
                    let _ = tx.send(Raw::Rescan);
                    return;
                }
                // Every path the event mentions, whatever kind of event it is. A
                // rename carries two, and both matter: one path lost a file and
                // the other gained one.
                for path in event.paths {
                    if tx.send(Raw::Path(path)).is_err() {
                        return;
                    }
                }
            }
            // An error from the backend means the same thing as a dropped event:
            // our picture of the tree is no longer trustworthy.
            Err(_) => {
                let _ = tx.send(Raw::Rescan);
            }
        }
    })
    .ok()?;
    watcher.watch(root, RecursiveMode::Recursive).ok()?;
    Some((Native::Notify(watcher), backend_name()))
}

/// Which backend `notify` chose, for the line `bisync watch` prints on startup.
///
/// Worth surfacing rather than hiding: "watching via rescan" when the user
/// expected inotify is the difference between a sync that lags by a minute and
/// one they think is broken.
fn backend_name() -> &'static str {
    match RecommendedWatcher::kind() {
        WatcherKind::Inotify => "inotify",
        WatcherKind::Fsevent => "fsevents",
        WatcherKind::Kqueue => "kqueue",
        WatcherKind::ReadDirectoryChangesWatcher => "readdirectorychanges",
        WatcherKind::PollWatcher => "notify polling",
        // `WatcherKind` is `#[non_exhaustive]`, so a future backend lands here
        // rather than failing to build.
        _ => "notify",
    }
}
