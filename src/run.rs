//! The commands, and the loop that drives a session.
//!
//! Everything below `drive` is bookkeeping: open a root, load its config and
//! state, wire up a link and possibly a watcher, run, save. `drive` itself is the
//! only interesting part, and what makes it interesting is that it never blocks
//! on one thing while another has work: transfers go out a chunk at a time
//! between polls of the wake channel, so a large file does not stop the session
//! hearing about a small one.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::config::{Config, Peer};
use crate::merge::{Direction, Policy};
use crate::session::{Event, Role, Session, Settings, Stats};
use crate::state::{LoadOutcome, State};
use crate::store::Store;
use crate::transport::Link;
use crate::tree::Kind;
use crate::util;
use crate::wake::Wake;
use crate::watch::Watcher;

/// Command-line settings that override the config file.
#[derive(Clone, Debug, Default)]
pub struct Overrides {
    pub peer: Option<String>,
    pub max_size: Option<u64>,
    pub conflict: Option<Policy>,
    /// DEFLATE level, or 0 for none. `None` leaves the config alone.
    pub compress: Option<u8>,
    /// Which way changes may flow.
    ///
    /// Per invocation rather than from the config, deliberately: a config that
    /// permanently made a root pull-only would silently never push, which is the
    /// kind of setting people discover months later.
    pub direction: Direction,
    /// Show a diff of what a sync would change. Implies `dry_run`.
    pub diff: bool,
    pub poll_only: bool,
    pub dry_run: bool,
    pub verbose: bool,
    pub quiet: bool,
}

/// How long a one-shot sync will sit with nothing happening before deciding the
/// peer has stopped answering. Generous: the far side may be hashing a large
/// tree before it says anything at all.
const STALL: Duration = Duration::from_secs(300);

/// A sync root, opened.
struct Root {
    store: Store,
    state: State,
    cfg: Config,
    peer: Peer,
    settings: Settings,
}

/// Let the command line have the last word over the config file.
///
/// Shared by every command that reads a config, so that `bisync status -z9`
/// describes the sync `bisync sync -z9` would perform rather than the one the
/// config file alone would.
fn apply_overrides(cfg: &mut Config, overrides: &Overrides) {
    if let Some(peer) = &overrides.peer {
        cfg.peer = Some(Peer::parse(peer));
    }
    if let Some(max_size) = overrides.max_size {
        cfg.max_size = max_size;
    }
    if let Some(policy) = overrides.conflict {
        cfg.conflict = policy;
    }
    if let Some(level) = overrides.compress {
        cfg.compress = level;
    }
    cfg.poll_only |= overrides.poll_only;
}

impl Overrides {
    /// Settle the flags that imply one another.
    ///
    /// `--diff` only makes sense as a dry run: it exists to say what *would*
    /// happen, and diffing content that is about to be written anyway would be
    /// describing the past.
    pub fn resolved(mut self) -> Overrides {
        self.dry_run |= self.diff;
        self
    }
}

fn open(root: &Path, overrides: &Overrides, watch: bool) -> io::Result<Root> {
    let store = Store::open(root)?;
    let mut cfg = Config::load(&store.config_path())?;
    apply_overrides(&mut cfg, overrides);

    let Some(peer) = cfg.peer.clone() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "no peer configured for {}: run `bisync init <dir> --peer user@host:/path`",
                root.display()
            ),
        ));
    };
    let (state, outcome) = State::load(&store.state_path(), &peer.to_string())?;
    if let LoadOutcome::Reset(why) = &outcome {
        eprintln!("bisync: starting from scratch: {why}");
        eprintln!("bisync: differences will be reported as conflicts rather than guessed at");
    }
    let settings = Settings {
        max_size: cfg.max_size,
        ignore: cfg.ignore_set(),
        policy: cfg.conflict,
        direction: overrides.direction,
        compress: cfg.compress,
        watch,
        dry_run: overrides.dry_run,
        diff: overrides.diff,
    };
    Ok(Root {
        store,
        state,
        cfg,
        peer,
        settings,
    })
}

// ------------------------------------------------------------------- commands

/// `bisync init` — write a config for a root, and scan it once.
pub fn init(root: &Path, peer: Option<&str>, overrides: &Overrides) -> io::Result<i32> {
    std::fs::create_dir_all(root)?;
    let store = Store::open(root)?;
    let path = store.config_path();
    if path.exists() {
        eprintln!("bisync: {} already exists", path.display());
        return Ok(1);
    }
    let mut cfg = Config {
        peer: peer.map(Peer::parse),
        ..Config::default()
    };
    if let Some(max_size) = overrides.max_size {
        cfg.max_size = max_size;
    }
    if let Some(policy) = overrides.conflict {
        cfg.conflict = policy;
    }
    std::fs::write(&path, cfg.render())?;
    println!("wrote {}", path.display());

    let report = crate::scan::scan(store.root(), &cfg.ignore_set(), cfg.max_size, None)?;
    println!("{}", report.summary());
    println!("tree digest {}", report.index.root_digest());
    match &cfg.peer {
        Some(peer) => {
            println!();
            println!(
                "Run `bisync init` on {} too, then `bisync sync` here.",
                peer
            );
        }
        None => {
            println!();
            println!("Set `peer` in {} before syncing.", path.display());
        }
    }
    Ok(0)
}

/// `bisync sync` — reconcile once and exit.
pub fn sync(root: &Path, overrides: &Overrides) -> io::Result<i32> {
    let mut root = open(root, overrides, false)?;
    let reporter = Reporter::new(overrides);

    let (tx, rx) = mpsc::channel();
    let mut link = Link::connect(&root.peer, &root.cfg, false, tx)?;
    reporter.info(&format!(
        "{} <-> {}",
        root.store.root().display(),
        root.peer
    ));

    let mut session = Session::new(
        Role::Initiator,
        root.settings.clone(),
        &mut root.store,
        &mut root.state,
    );
    let report = session.rescan()?;
    reporter.scan(&report);
    session.open()?;

    let outcome = drive(&mut session, &mut link, &rx, &reporter, None);
    let stats = session.stats().clone();
    let failure = session.failure().map(str::to_string);
    drop(session);

    if !overrides.dry_run {
        root.state.sent.add(stats.out);
        root.state.received.add(stats.inbound);
        root.state.save(&root.store.state_path())?;
    }
    root.store.tidy();
    let _ = link.close();
    outcome?;
    reporter.summary(&stats, &root.state);
    if let Some(failure) = failure {
        eprintln!("bisync: {failure}");
        return Ok(1);
    }
    // Every conflict still on record, not only the ones noticed just now: a
    // frozen path is an outstanding decision whether or not this run found it.
    Ok(if root.state.conflicts.is_empty() {
        0
    } else {
        2
    })
}

/// `bisync watch` — reconcile, then stay and propagate changes as they happen.
pub fn watch(root: &Path, overrides: &Overrides) -> io::Result<i32> {
    let mut root = open(root, overrides, true)?;
    let reporter = Reporter::new(overrides);

    let (tx, rx) = mpsc::channel();
    let mut link = Link::connect(&root.peer, &root.cfg, true, tx.clone())?;
    let watcher = Watcher::start(
        root.store.root(),
        root.settings.ignore.clone(),
        root.cfg.debounce,
        root.cfg.poll_interval,
        root.cfg.poll_only,
        tx,
    )?;
    reporter.info(&format!(
        "{} <-> {} (watching via {})",
        root.store.root().display(),
        root.peer,
        watcher.kind()
    ));

    let state_path = root.store.state_path();
    let mut session = Session::new(
        Role::Initiator,
        root.settings.clone(),
        &mut root.store,
        &mut root.state,
    );
    let report = session.rescan()?;
    reporter.scan(&report);
    session.open()?;

    let outcome = drive(&mut session, &mut link, &rx, &reporter, Some(&state_path));
    let stats = session.stats().clone();
    drop(session);
    drop(watcher);

    root.state.sent.add(stats.out);
    root.state.received.add(stats.inbound);
    root.state.save(&state_path)?;
    let _ = link.close();
    outcome?;
    reporter.summary(&stats, &root.state);
    Ok(0)
}

/// `bisync server` — the far end of a link. Speaks the protocol on stdin and
/// stdout and says nothing else there; anything for a human goes to stderr,
/// because stdout is the wire.
pub fn server(root: &Path, watch_mode: bool, overrides: &Overrides) -> io::Result<i32> {
    let store = Store::open(root)?;
    let cfg = Config::load(&store.config_path())?;
    // The peer is whoever connected, and it is the one that names the terms. Our
    // own config still supplies the transport-independent defaults, and its
    // ignore list is compared against theirs so a mismatch gets reported.
    let mut settings = Settings {
        max_size: cfg.max_size,
        ignore: cfg.ignore_set(),
        policy: cfg.conflict,
        // Both until the initiator's `Hello` says otherwise, which it will
        // before anything is decided.
        direction: Direction::Both,
        compress: cfg.compress,
        watch: watch_mode,
        dry_run: false,
        diff: false,
    };
    if let Some(policy) = overrides.conflict {
        settings.policy = policy;
    }
    let mut store = store;
    // The base belongs to the initiator, whoever that turns out to be. A server
    // root reached from two different peers keeps one base at a time, and says
    // so when it changes hands.
    let peer_label = cfg
        .peer
        .as_ref()
        .map(|p| p.to_string())
        .unwrap_or_else(|| "peer".to_string());
    let (mut state, outcome) = State::load(&store.state_path(), &peer_label)?;
    if let LoadOutcome::Reset(why) = &outcome {
        eprintln!("bisync server: starting from scratch: {why}");
    }

    let (tx, rx) = mpsc::channel();
    let mut link = Link::stdio(tx.clone());
    let reporter = Reporter::server();

    // Started before the handshake so no change is missed between the initial
    // scan and the session being ready; the batches simply queue up.
    let watcher = if watch_mode {
        Some(Watcher::start(
            store.root(),
            settings.ignore.clone(),
            cfg.debounce,
            cfg.poll_interval,
            cfg.poll_only,
            tx,
        )?)
    } else {
        None
    };

    let state_path = store.state_path();
    let mut session = Session::new(Role::Responder, settings, &mut store, &mut state);
    let outcome = drive(&mut session, &mut link, &rx, &reporter, Some(&state_path));
    let stats = session.stats().clone();
    drop(session);
    drop(watcher);
    state.sent.add(stats.out);
    state.received.add(stats.inbound);
    state.save(&state_path)?;
    store.tidy();
    outcome?;
    Ok(0)
}

/// `bisync status` — what this root looks like, without talking to anyone.
pub fn status(root: &Path, overrides: &Overrides) -> io::Result<i32> {
    let store = Store::open(root)?;
    let mut cfg = Config::load(&store.config_path())?;
    apply_overrides(&mut cfg, overrides);
    let peer_label = cfg.peer.as_ref().map(|p| p.to_string()).unwrap_or_default();
    let (state, outcome) = State::load(&store.state_path(), &peer_label)?;
    let ignore = cfg.ignore_set();
    let report = crate::scan::scan(store.root(), &ignore, cfg.max_size, Some(&state.index))?;
    let index = &report.index;

    println!("root      {}", store.root().display());
    match &cfg.peer {
        Some(peer) => println!("peer      {peer}"),
        None => println!("peer      (none configured)"),
    }
    println!("digest    {}", index.root_digest());
    println!(
        "contents  {}, {}, {} ({})",
        util::plural(index.count_of(Kind::File), "file"),
        util::count(index.count_of(Kind::Dir), "directory", "directories"),
        util::plural(index.count_of(Kind::Symlink), "symlink"),
        util::format_size(index.total_bytes())
    );
    println!("limit     {} per file", util::format_size(cfg.max_size));
    println!("conflicts {} policy", cfg.conflict.name());
    match cfg.compress {
        0 => println!("compress  off"),
        level => println!("compress  deflate level {level}"),
    }
    println!("ignoring  {} rules", ignore.len());
    match outcome {
        LoadOutcome::Fresh => println!("state     none yet; the next sync starts from scratch"),
        LoadOutcome::Reset(why) => println!("state     unusable ({why})"),
        LoadOutcome::Loaded => println!(
            "state     {} paths agreed with the peer, base {}",
            state.base.len(),
            state.base_digest().short()
        ),
    }
    // What compression has actually bought on this tree, which is the only way
    // to tell a link it helps from one where it is just burning CPU.
    if let Some(described) = state.sent.describe() {
        println!("sent      {described}");
    }
    if let Some(described) = state.received.describe() {
        println!("received  {described}");
    }

    // Nothing prunes `diffs`, so the only thing keeping it from being a surprise
    // is saying how big it has got.
    let (kept, kept_bytes) = store.preserved();
    if kept > 0 {
        println!(
            "kept      {} in {} ({})",
            util::count(kept, "old version", "old versions"),
            crate::store::DIFFS,
            util::format_size(kept_bytes)
        );
    }

    if !index.oversize().is_empty() {
        println!();
        println!(
            "over the {} limit, not synced:",
            util::format_size(cfg.max_size)
        );
        for (path, size) in index.oversize() {
            println!("  {:>9}  {path}", util::format_size(*size));
        }
    }

    // Local changes since the last agreement. Cheap to work out and the most
    // useful thing on the page: it is what the next sync will offer the peer.
    let mut pending = 0;
    let mut lines = Vec::new();
    for (path, entry) in index.iter() {
        let base = state.base_of(path);
        if base != entry.state() {
            pending += 1;
            if lines.len() < 20 {
                lines.push(format!(
                    "  {} {path}",
                    if base.is_absent() { "new " } else { "chg " }
                ));
            }
        }
    }
    for path in state.base.keys() {
        if !index.contains(path) {
            pending += 1;
            if lines.len() < 20 {
                lines.push(format!("  del  {path}"));
            }
        }
    }
    if pending > 0 {
        println!();
        println!("{} to offer the peer:", util::plural(pending, "change"));
        for line in &lines {
            println!("{line}");
        }
        if pending > lines.len() {
            println!("  ... and {} more", pending - lines.len());
        }
    }

    if !state.conflicts.is_empty() {
        println!();
        println!(
            "{}: see `bisync conflicts`",
            util::plural(state.conflicts.len(), "conflict")
        );
    }
    for warning in report.warnings() {
        eprintln!("bisync: {warning}");
    }
    Ok(if state.conflicts.is_empty() { 0 } else { 2 })
}

/// `bisync conflicts` — the frozen paths and where each side's version is.
pub fn conflicts(root: &Path) -> io::Result<i32> {
    let store = Store::open(root)?;
    let cfg = Config::load(&store.config_path())?;
    let peer_label = cfg.peer.as_ref().map(|p| p.to_string()).unwrap_or_default();
    let (state, _) = State::load(&store.state_path(), &peer_label)?;
    if state.conflicts.is_empty() {
        println!("no conflicts");
        return Ok(0);
    }
    let mut records: Vec<_> = state.conflicts.iter().collect();
    records.sort_by_key(|(_, record)| (record.detected.secs, record.detected.nanos));
    for (path, record) in records {
        println!("{path}");
        println!(
            "  {} at {}",
            record.kind.describe(),
            util::format_utc(record.detected)
        );
        println!("  here  {}", record.local.describe());
        println!("  peer  {}", record.remote.describe());
        if record.quarantine.is_empty() {
            println!("  the peer's copy has not been fetched; run `bisync sync`");
        } else {
            println!("  peer's copy at {}", record.quarantine);
        }
        println!("  resolve with `bisync resolve {path} --local` or `--remote`");
    }
    println!();
    println!(
        "{} frozen until resolved",
        util::plural(state.conflicts.len(), "path")
    );
    Ok(2)
}

/// `bisync resolve` — settle a conflict in favour of one side.
pub fn resolve(root: &Path, paths: &[String], keep_remote: bool, all: bool) -> io::Result<i32> {
    let store = Store::open(root)?;
    let cfg = Config::load(&store.config_path())?;
    let peer_label = cfg.peer.as_ref().map(|p| p.to_string()).unwrap_or_default();
    let (mut state, _) = State::load(&store.state_path(), &peer_label)?;

    let targets: Vec<String> = if all {
        state.conflicts.keys().cloned().collect()
    } else {
        paths.to_vec()
    };
    if targets.is_empty() {
        eprintln!("bisync: name a path, or pass --all");
        return Ok(1);
    }

    let mut settled = 0;
    for path in &targets {
        let Some(record) = state.conflicts.get(path).cloned() else {
            eprintln!("bisync: {path}: not in conflict");
            continue;
        };
        if keep_remote {
            // The peer's version wins. It is already on disk, in quarantine, so
            // this is a rename rather than another transfer.
            if record.remote.is_absent() {
                match store.remove(path, &record.local)? {
                    crate::store::Guarded::Applied { .. } => {}
                    other => {
                        eprintln!("bisync: {path}: not deleted ({other:?})");
                        continue;
                    }
                }
            } else if record.quarantine.is_empty() {
                eprintln!(
                    "bisync: {path}: the peer's copy is not here yet; run `bisync sync` first"
                );
                continue;
            } else {
                // Replacing the local version with the peer's, which is a
                // replacement like any other and belongs in `diffs` rather than
                // in quarantine — quarantine is for what was *not* applied.
                if let Some(at) = store.preserve(path)? {
                    println!("{path}: local version kept at {at}");
                }
                store.restore(&record.quarantine, path)?;
            }
            // Base and local now agree on the peer's version, so the next sync
            // sees a converged path rather than a change to push back.
            state.set_base(path, record.remote.clone());
        } else {
            // Ours wins. Rewinding the base to the peer's version is what makes
            // the next announcement a fast-forward from the peer's point of
            // view, so it takes our copy without calling it a conflict again.
            state.set_base(path, record.remote.clone());
            if !record.quarantine.is_empty() {
                let at = crate::relpath::join(store.root(), &record.quarantine);
                let _ = std::fs::remove_file(&at);
            }
        }
        state.conflicts.remove(path);
        state.index.remove(path);
        settled += 1;
        println!(
            "{path}: resolved in favour of {}",
            if keep_remote { "the peer" } else { "this side" }
        );
    }

    // The index entries for resolved paths were dropped so the next scan reads
    // them fresh rather than trusting a stamp from before the resolution.
    let report = crate::scan::scan(
        store.root(),
        &cfg.ignore_set(),
        cfg.max_size,
        Some(&state.index),
    )?;
    state.index = report.index;
    state.save(&store.state_path())?;
    println!();
    println!(
        "{} resolved; run `bisync sync` to propagate",
        util::plural(settled, "conflict")
    );
    Ok(0)
}

/// What `bisync prune` is asked to remove.
///
/// There is no default. Everything under `.bisync/diffs` is there because
/// something was about to be destroyed and bisync declined to let that be the
/// end of it, so which of those copies is now expendable is a judgement bisync is
/// in no position to make on the operator's behalf.
#[derive(Clone, Copy, Debug)]
pub enum Prune {
    /// Versions preserved longer ago than this.
    OlderThan(Duration),
    /// All but the newest `n` versions of each path.
    KeepNewest(usize),
    /// Everything.
    All,
}

/// `bisync prune` — remove preserved versions from `.bisync/diffs`.
pub fn prune(root: &Path, what: Prune, overrides: &Overrides) -> io::Result<i32> {
    let store = Store::open(root)?;
    let kept = store.list_preserved();
    if kept.is_empty() {
        println!("nothing kept in {}", crate::store::DIFFS);
        return Ok(0);
    }

    let now = util::now().secs;
    let mut doomed: Vec<&crate::store::Kept> = Vec::new();
    let mut undated = 0usize;
    match what {
        Prune::All => doomed.extend(kept.iter()),
        Prune::OlderThan(age) => {
            let cutoff = now - age.as_secs() as i64;
            for version in &kept {
                match version.when {
                    Some(when) if when.secs < cutoff => doomed.push(version),
                    // A version whose name does not carry a time cannot be shown
                    // to be old, so it stays. `--all` is how to be rid of it.
                    None => undated += 1,
                    Some(_) => {}
                }
            }
        }
        Prune::KeepNewest(n) => {
            // `list_preserved` groups by path and puts the oldest first, so each
            // run of equal paths is already in the order to drop from.
            for group in kept.chunk_by(|a, b| a.of == b.of) {
                let drop = group.len().saturating_sub(n);
                doomed.extend(&group[..drop]);
            }
        }
    }

    let bytes: u64 = doomed.iter().map(|k| k.size).sum();
    if overrides.verbose || overrides.dry_run {
        for version in &doomed {
            println!(
                "{} {}",
                if overrides.dry_run {
                    "would remove"
                } else {
                    "remove"
                },
                version.at
            );
        }
    }
    if overrides.dry_run {
        println!(
            "would remove {} ({}), leaving {}",
            util::count(doomed.len(), "version", "versions"),
            util::format_size(bytes),
            util::count(kept.len() - doomed.len(), "version", "versions")
        );
        return Ok(0);
    }

    let mut removed = 0usize;
    let mut freed = 0u64;
    for version in &doomed {
        match store.remove_preserved(&version.at) {
            Ok(()) => {
                removed += 1;
                freed += version.size;
            }
            Err(e) => eprintln!("bisync: {}: {e}", version.at),
        }
    }
    store.tidy_preserved();

    println!(
        "removed {} ({}), leaving {}",
        util::count(removed, "version", "versions"),
        util::format_size(freed),
        util::count(kept.len() - removed, "version", "versions")
    );
    if undated > 0 {
        println!(
            "{} left alone: no timestamp in the name, so not shown to be old",
            util::count(undated, "version", "versions")
        );
    }
    Ok(0)
}

/// `bisync tree` — the Merkle tree, for seeing why two roots disagree.
pub fn tree(root: &Path, overrides: &Overrides) -> io::Result<i32> {
    let store = Store::open(root)?;
    let mut cfg = Config::load(&store.config_path())?;
    apply_overrides(&mut cfg, overrides);
    let report = crate::scan::scan(store.root(), &cfg.ignore_set(), cfg.max_size, None)?;
    println!("{}  .", report.index.root_digest());
    for (path, entry) in report.index.iter() {
        let mark = match entry.kind {
            Kind::Dir => "/",
            Kind::Symlink => "@",
            Kind::File => "",
        };
        println!("{}  {path}{mark}", entry.digest);
    }
    for (path, size) in report.index.oversize() {
        println!(
            "{:<64}  {path}  ({} skipped)",
            "-",
            util::format_size(*size)
        );
    }
    Ok(0)
}

// --------------------------------------------------------------------- driver

/// Run a session to completion, or forever in watch mode.
fn drive(
    session: &mut Session<'_>,
    link: &mut Link,
    rx: &Receiver<Wake>,
    reporter: &Reporter,
    save_to: Option<&Path>,
) -> io::Result<()> {
    let watching = session.settings.watch;
    let mut last_progress = Instant::now();
    let mut dirty = false;

    loop {
        // 1. Everything the session has to say.
        let mut spoke = flush(session, link, reporter)?;

        // 2. Transfers, a bounded number of chunks at a time. Bounded so a large
        //    file cannot monopolise the loop and leave the peer unheard.
        let mut pending = false;
        for _ in 0..16 {
            if !session.pump()? {
                break;
            }
            pending = true;
            spoke |= flush(session, link, reporter)?;
        }
        // Settling can send `Bye`, which must not happen while chunks are still
        // queued behind it.
        if !pending {
            session.settle();
            spoke |= flush(session, link, reporter)?;
        }
        if spoke {
            last_progress = Instant::now();
        }

        if let Some(failure) = session.failure() {
            return Err(io::Error::other(failure.to_string()));
        }
        if !watching && session.finished() {
            return Ok(());
        }

        // 3. Wait. Only when nothing is queued to send, or the peer waits on us.
        link.flush()?;
        let wake = if pending {
            match rx.try_recv() {
                Ok(wake) => Some(wake),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => Some(Wake::Closed),
            }
        } else {
            match rx.recv_timeout(Duration::from_secs(5)) {
                Ok(wake) => Some(wake),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => Some(Wake::Closed),
            }
        };

        match wake {
            Some(Wake::Msg(msg)) => {
                last_progress = Instant::now();
                let name = msg.name();
                session
                    .handle(msg)
                    .map_err(|e| io::Error::other(format!("{name}: {e}")))?;
                dirty = true;
            }
            Some(Wake::Local(paths)) => {
                last_progress = Instant::now();
                reporter.local(&paths);
                session.local_changed(&paths)?;
                dirty = true;
            }
            Some(Wake::Closed) => {
                if watching {
                    return Err(io::Error::other("the peer closed the connection"));
                }
                // Only a clean end if we had finished anyway.
                return if session.busy() {
                    Err(io::Error::other("the peer closed the connection mid-sync"))
                } else {
                    Ok(())
                };
            }
            Some(Wake::Failed(why)) => return Err(io::Error::other(why)),
            None => {
                // Persist progress periodically in watch mode, so a session
                // killed after hours of quiet does not start over.
                if dirty && !pending {
                    if let Some(path) = save_to {
                        session.state().save(path)?;
                        dirty = false;
                    }
                }
                if !watching && last_progress.elapsed() > STALL {
                    return Err(io::Error::other("the peer stopped responding"));
                }
            }
        }
    }
}

/// Send everything the session has queued and print what it wants to say.
/// Returns whether anything happened.
fn flush(session: &mut Session<'_>, link: &mut Link, reporter: &Reporter) -> io::Result<bool> {
    let mut spoke = false;
    for msg in session.take_out() {
        link.send(&msg)?;
        spoke = true;
    }
    for event in session.take_events() {
        reporter.event(&event);
        spoke = true;
    }
    Ok(spoke)
}

// -------------------------------------------------------------------- reporting

/// Where session events go.
struct Reporter {
    verbose: bool,
    quiet: bool,
    dry_run: bool,
    /// stderr for the server: stdout is the wire.
    to_stderr: bool,
    colour: bool,
}

impl Reporter {
    fn new(overrides: &Overrides) -> Reporter {
        Reporter {
            verbose: overrides.verbose,
            quiet: overrides.quiet,
            dry_run: overrides.dry_run,
            to_stderr: false,
            colour: std::io::stdout().is_terminal(),
        }
    }

    fn server() -> Reporter {
        Reporter {
            verbose: false,
            quiet: true,
            dry_run: false,
            to_stderr: true,
            colour: false,
        }
    }

    /// The prefix the far end's own output carries, so a line that appears in the
    /// initiator's terminal because ssh forwarded its stderr is not mistaken for
    /// something that happened locally.
    fn tag(&self) -> &'static str {
        if self.to_stderr { "remote: " } else { "" }
    }

    fn line(&self, text: &str) {
        if self.to_stderr {
            eprintln!("{text}");
        } else {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{text}");
        }
    }

    fn info(&self, text: &str) {
        if !self.quiet {
            self.line(text);
        }
    }

    fn scan(&self, report: &crate::scan::ScanReport) {
        self.info(&report.summary());
        // Said plainly rather than only in the verbose summary: a file silently
        // not syncing is the kind of surprise this tool should never spring.
        let oversize = report.index.oversize();
        if !oversize.is_empty() && !self.quiet {
            let total: u64 = oversize.values().sum();
            self.line(&format!(
                "{} over the size limit, not synced ({}); `bisync status` lists them",
                util::plural(oversize.len(), "file"),
                util::format_size(total)
            ));
        }
        for warning in report.warnings() {
            self.warn(&warning);
        }
    }

    fn warn(&self, text: &str) {
        if self.to_stderr {
            eprintln!("bisync remote: {text}");
        } else if self.colour {
            eprintln!("\x1b[33m!\x1b[0m {text}");
        } else {
            eprintln!("! {text}");
        }
    }

    fn local(&self, paths: &[String]) {
        if !self.verbose {
            return;
        }
        if paths.len() == 1 && paths[0].is_empty() {
            self.info("local: full rescan");
        } else {
            self.info(&format!(
                "local: {} changed",
                util::plural(paths.len(), "path")
            ));
        }
    }

    fn event(&self, event: &Event) {
        match event {
            Event::Info(text) => {
                if self.verbose {
                    self.info(text);
                }
            }
            Event::Warn(text) => self.warn(text),
            Event::Change { verb, path, detail } => {
                if self.quiet {
                    return;
                }
                if detail.is_empty() {
                    self.line(&format!("{verb:<5} {path}"));
                } else {
                    self.line(&format!("{verb:<5} {path}  ({detail})"));
                }
            }
            Event::Diff {
                path,
                was,
                becomes,
                change,
            } => {
                use crate::diff::Kind;
                let summary = match change.kind {
                    Kind::Same => "identical".to_string(),
                    Kind::Binary => format!(
                        "binary, {} -> {}",
                        util::format_size(*was),
                        util::format_size(*becomes)
                    ),
                    Kind::TooLarge => format!(
                        "{} lines replaced by {}, too much to show",
                        change.removed, change.added
                    ),
                    Kind::Text => format!("+{} -{}", change.added, change.removed),
                };
                self.line(&format!("diff  {path}  ({summary})"));
                for line in change.text.lines() {
                    self.line(&format!("      {}", crate::diff::paint(line, self.colour)));
                }
            }
            Event::Conflict {
                path,
                kind,
                quarantine,
            } => {
                let marker = if self.colour && !self.to_stderr {
                    "\x1b[31m!!\x1b[0m"
                } else {
                    "!!"
                };
                let tag = self.tag();
                self.line(&format!("{tag}{marker}    {path}  ({})", kind.describe()));
                match quarantine {
                    Some(at) => {
                        self.line(&format!("{tag}      not overwritten; peer's copy at {at}"))
                    }
                    None => self.line(&format!(
                        "{tag}      not overwritten; frozen until `bisync resolve`"
                    )),
                }
            }
        }
    }

    fn summary(&self, stats: &Stats, state: &State) {
        if self.quiet {
            return;
        }
        let mut parts = Vec::new();
        if stats.received > 0 {
            parts.push(format!(
                "received {} ({})",
                util::plural(stats.received, "file"),
                volume(stats.received_bytes, stats.inbound)
            ));
        }
        if stats.sent > 0 {
            parts.push(format!(
                "sent {} ({})",
                util::plural(stats.sent, "file"),
                volume(stats.sent_bytes, stats.out)
            ));
        }
        if stats.kept > 0 {
            parts.push(format!(
                "{} kept in {}",
                util::count(stats.kept, "local version", "local versions"),
                crate::store::DIFFS
            ));
        }
        if stats.quarantined > 0 {
            parts.push(format!(
                "{} kept aside",
                util::plural(stats.quarantined, "conflicting version")
            ));
        }
        if stats.pushed > 0 {
            parts.push(format!(
                "{} accepted by the peer",
                util::plural(stats.pushed, "change")
            ));
        }
        if stats.created > 0 {
            parts.push(format!(
                "{} created",
                util::count(stats.created, "directory", "directories")
            ));
        }
        if stats.deleted > 0 {
            parts.push(format!("deleted {}", util::plural(stats.deleted, "path")));
        }
        if parts.is_empty() {
            parts.push("nothing to do".to_string());
        }

        if self.dry_run {
            self.line("dry run: nothing was changed on either side");
        } else {
            self.line(&parts.join(", "));
        }
        if !state.conflicts.is_empty() {
            self.line(&format!(
                "{} unresolved: run `bisync conflicts`",
                util::plural(state.conflicts.len(), "conflict")
            ));
        }
    }
}

/// How much content moved, and what it cost on the wire when the two differ.
///
/// One figure when compression did nothing — a run that sent a single
/// incompressible file should not be lectured about ratios — and both when it
/// did, in one clause rather than repeating the size in a second one.
fn volume(bytes: u64, tally: crate::compress::Tally) -> String {
    if tally.saved() == 0 {
        return util::format_size(bytes);
    }
    format!(
        "{}, {} on the wire, {}% saved",
        util::format_size(tally.plain),
        util::format_size(tally.wire),
        tally.percent()
    )
}

/// Where a root is, from an argument or the working directory.
pub fn root_of(arg: Option<&str>) -> io::Result<PathBuf> {
    match arg {
        Some(arg) => {
            let path = PathBuf::from(arg);
            path.canonicalize()
                .map_err(|e| io::Error::new(e.kind(), format!("{arg}: {e}")))
        }
        None => std::env::current_dir(),
    }
}
