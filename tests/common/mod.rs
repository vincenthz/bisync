//! Test scaffolding: throwaway directories, and two sessions wired to each other.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bisync::merge::Policy;
use bisync::proto::Msg;
use bisync::session::{Event, Role, Session, Settings, Stats};
use bisync::state::State;
use bisync::store::Store;
use bisync::tree::PathState;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A directory that deletes itself. Enough to avoid a `tempfile` dependency in
/// a crate whose whole point is having almost none.
pub struct Temp {
    path: PathBuf,
}

impl Temp {
    pub fn new(tag: &str) -> Temp {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "bisync-test-{tag}-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        Temp { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write a file, creating parents. Paths are `/`-separated and relative.
    pub fn write(&self, rel: &str, content: &str) {
        self.write_bytes(rel, content.as_bytes());
    }

    pub fn write_bytes(&self, rel: &str, content: &[u8]) {
        let at = self.path.join(rel);
        if let Some(parent) = at.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&at, content).unwrap();
    }

    pub fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.path.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    pub fn exists(&self, rel: &str) -> bool {
        self.path.join(rel).symlink_metadata().is_ok()
    }

    pub fn mkdir(&self, rel: &str) {
        fs::create_dir_all(self.path.join(rel)).unwrap();
    }

    pub fn remove(&self, rel: &str) {
        let at = self.path.join(rel);
        if at.symlink_metadata().map(|m| m.is_dir()).unwrap_or(false) {
            fs::remove_dir_all(&at).unwrap();
        } else {
            fs::remove_file(&at).unwrap();
        }
    }

    #[cfg(unix)]
    pub fn symlink(&self, rel: &str, target: &str) {
        let at = self.path.join(rel);
        if let Some(parent) = at.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let _ = fs::remove_file(&at);
        std::os::unix::fs::symlink(target, &at).unwrap();
    }

    #[cfg(unix)]
    pub fn chmod(&self, rel: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(self.path.join(rel), fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    pub fn mode(&self, rel: &str) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::symlink_metadata(self.path.join(rel))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    /// Every path under the root, `/`-separated, directories with a trailing
    /// slash, both tools' control directories excluded.
    pub fn list(&self) -> Vec<String> {
        let mut out = Vec::new();
        walk(&self.path, &self.path, true, &mut out);
        out.sort();
        out
    }

    /// Files under `.bisync/quarantine`, relative to the root.
    pub fn quarantined(&self) -> Vec<String> {
        let mut out = Vec::new();
        let base = self.path.join(".bisync/quarantine");
        if base.is_dir() {
            walk(&self.path, &base, false, &mut out);
        }
        out.retain(|p| !p.ends_with('/'));
        out.sort();
        out
    }

    /// The one quarantined copy of `rel`, whatever timestamped directory it
    /// landed in.
    pub fn quarantined_copy(&self, rel: &str) -> Option<String> {
        self.quarantined().into_iter().find(|p| p.ends_with(rel))
    }

    /// Local versions that were replaced, under `.bisync/diffs`.
    pub fn kept(&self) -> Vec<String> {
        self.preserved_under(".bisync")
    }

    /// The same, under a named control directory — `unisync` keeps its own.
    pub fn preserved_under(&self, control: &str) -> Vec<String> {
        let mut out = Vec::new();
        let base = self.path.join(control).join("diffs");
        if base.is_dir() {
            walk(&self.path, &base, false, &mut out);
        }
        out.retain(|p| !p.ends_with('/'));
        out.sort();
        out
    }

    /// The kept copy of `rel`, whatever timestamp it was suffixed with. Panics
    /// if there is more than one, since a test asking for "the" copy has a
    /// specific one in mind.
    pub fn kept_copy(&self, rel: &str) -> Option<String> {
        let prefix = format!(".bisync/diffs/{rel}.");
        let mut matches: Vec<String> = self
            .kept()
            .into_iter()
            .filter(|p| p.starts_with(&prefix))
            .collect();
        assert!(
            matches.len() <= 1,
            "several kept copies of {rel}: {matches:?}"
        );
        matches.pop()
    }
}

fn walk(root: &Path, dir: &Path, skip_control: bool, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .to_string();
        if skip_control
            && [".bisync", ".unisync"]
                .iter()
                .any(|c| rel == *c || rel.starts_with(&format!("{c}/")))
        {
            continue;
        }
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        out.push(if is_dir { format!("{rel}/") } else { rel });
        if is_dir {
            walk(root, &path, skip_control, out);
        }
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// What one reconciliation did.
pub struct Outcome {
    pub a: Stats,
    pub b: Stats,
    pub events_a: Vec<Event>,
    pub events_b: Vec<Event>,
    pub messages: usize,
    pub state_a: State,
    pub state_b: State,
}

impl Outcome {
    pub fn conflicts_a(&self) -> Vec<String> {
        self.state_a.conflicts.keys().cloned().collect()
    }

    pub fn conflicts_b(&self) -> Vec<String> {
        self.state_b.conflicts.keys().cloned().collect()
    }

    pub fn base_a(&self, path: &str) -> PathState {
        self.state_a.base_of(path)
    }
}

/// Point two roots at each other, the way `bisync init` would.
pub fn link(a: &Temp, b: &Temp) {
    for (one, other) in [(a, b), (b, a)] {
        let control = one.path().join(".bisync");
        fs::create_dir_all(&control).unwrap();
        fs::write(
            control.join("config"),
            format!("peer = {}\n", other.path().display()),
        )
        .unwrap();
    }
}

pub fn settings(max_size: u64, policy: Policy) -> Settings {
    Settings {
        max_size,
        policy,
        ..Settings::default()
    }
}

/// Run one full reconciliation between two roots with no transport at all.
///
/// The two sessions' outboxes are wired to each other's `handle`, which is the
/// entire protocol: if a sync works here it works over ssh, because the only
/// difference is who copies the bytes between the two `Vec<Msg>`.
pub fn reconcile(a: &Temp, b: &Temp, settings: Settings) -> Outcome {
    // Each root gets a config naming the other, so the peer label the state file
    // is stamped with is the one the real commands would compute — otherwise
    // `bisync resolve` would read the state as belonging to someone else and
    // start from scratch.
    link(a, b);
    let mut store_a = Store::open(a.path()).unwrap();
    let mut store_b = Store::open(b.path()).unwrap();
    let label_a = b.path().display().to_string();
    let label_b = a.path().display().to_string();
    let (mut state_a, _) = State::load(&store_a.state_path(), &label_a).unwrap();
    let (mut state_b, _) = State::load(&store_b.state_path(), &label_b).unwrap();

    let mut events_a = Vec::new();
    let mut events_b = Vec::new();
    let mut messages = 0usize;
    let (stats_a, stats_b) = {
        let mut sa = Session::new(
            Role::Initiator,
            settings.clone(),
            &mut store_a,
            &mut state_a,
        );
        let mut sb = Session::new(Role::Responder, settings, &mut store_b, &mut state_b);
        sa.rescan().unwrap();
        sa.open().unwrap();

        for _ in 0..100_000 {
            let out_a: Vec<Msg> = sa.take_out();
            let out_b: Vec<Msg> = sb.take_out();
            let spoke = !out_a.is_empty() || !out_b.is_empty();
            messages += out_a.len() + out_b.len();
            for msg in out_a {
                sb.handle(msg).unwrap();
            }
            for msg in out_b {
                sa.handle(msg).unwrap();
            }
            let pa = sa.pump().unwrap();
            let pb = sb.pump().unwrap();
            sa.settle();
            sb.settle();
            events_a.extend(sa.take_events());
            events_b.extend(sb.take_events());
            if !spoke && !pa && !pb {
                break;
            }
        }
        assert!(
            sa.failure().is_none(),
            "initiator failed: {:?}",
            sa.failure()
        );
        assert!(
            sb.failure().is_none(),
            "responder failed: {:?}",
            sb.failure()
        );
        (sa.stats().clone(), sb.stats().clone())
    };

    // Fold the session's figures into the running totals before saving, exactly
    // as `bisync sync` does — the accumulated saving is a property of the root,
    // not of one session.
    state_a.sent.add(stats_a.out);
    state_a.received.add(stats_a.inbound);
    state_b.sent.add(stats_b.out);
    state_b.received.add(stats_b.inbound);
    state_a.save(&store_a.state_path()).unwrap();
    state_b.save(&store_b.state_path()).unwrap();
    Outcome {
        a: stats_a,
        b: stats_b,
        events_a,
        events_b,
        messages,
        state_a,
        state_b,
    }
}

/// Reconcile with the default settings: 1 MiB, quarantine on conflict.
pub fn sync(a: &Temp, b: &Temp) -> Outcome {
    reconcile(a, b, Settings::default())
}

/// Assert both roots hold the same tree, by their own Merkle digests.
///
/// `max_size` must match what the sync ran under: a file the sync declined to
/// transfer is legitimately present on one side only, and counting it would make
/// a correct outcome look like a failure.
pub fn assert_converged_at(a: &Temp, b: &Temp, max_size: u64) {
    let ignore = bisync::ignore::IgnoreSet::defaults();
    let ra = bisync::scan::scan(a.path(), &ignore, max_size, None).unwrap();
    let rb = bisync::scan::scan(b.path(), &ignore, max_size, None).unwrap();
    assert_eq!(
        ra.index.root_digest(),
        rb.index.root_digest(),
        "trees differ:\n  a: {:?}\n  b: {:?}",
        a.list(),
        b.list()
    );
}

pub fn assert_converged(a: &Temp, b: &Temp) {
    assert_converged_at(a, b, bisync::config::DEFAULT_MAX_SIZE);
}
