//! The commands, the loop that drives a session, and the interactive part.
//!
//! A `unisync` run has a shape `bisync` does not: it stops in the middle and
//! waits for a person. That is why the driver here is written as a sequence of
//! phases — handshake, compare, decide, carry out — rather than as one event
//! loop. Between the phases the link sits idle, which is why the far end of a
//! `unisync` link has no stall timeout: someone reading a diff is not a peer
//! that has stopped answering.
//!
//! Within a phase the loop is `bisync`'s: everything queued goes out, transfers
//! advance a chunk at a time between polls of the channel the reader thread
//! delivers on, and nothing blocks while there is something to send.

use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::config::{Config, Peer};
use crate::diff;
use crate::ignore::{DEFAULT_PATTERNS, IgnoreSet};
use crate::relpath;
use crate::store::{self, Store};
use crate::transport::Link;
use crate::tree::PathState;
use crate::util;
use crate::wake::Wake;

use super::ask::{self, Prompt};
use super::plan::{Plan, Step, Way};
use super::session::{Event, Phase, Role, Session, Settings, Stats};

/// How long a run will sit with nothing happening before deciding the peer has
/// stopped answering. Only ever in force while waiting on the peer — never
/// across a question, which has no time limit at all.
const STALL: Duration = Duration::from_secs(300);

/// Lines of a diff shown at a prompt before it is cut short. A diff nobody can
/// scroll back through is not an aid to deciding.
const DIFF_LINES: usize = 200;

/// Everything the command line settled.
#[derive(Clone, Debug)]
pub struct Options {
    pub max_size: u64,
    pub compress: u8,
    /// Propose removing whatever the sending side does not have.
    pub delete: bool,
    /// Accept every proposed change without asking.
    pub yes: bool,
    /// Report the plan and stop. Nothing is changed at either end.
    pub dry_run: bool,
    /// Extra ignore rules, and whether the built-in list is in force under them.
    pub ignore: Vec<String>,
    pub default_ignores: bool,
    pub ssh: String,
    pub ssh_options: Vec<String>,
    pub remote_command: String,
    pub verbose: bool,
    pub quiet: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            max_size: crate::config::DEFAULT_MAX_SIZE,
            compress: crate::compress::DEFAULT_LEVEL,
            delete: false,
            yes: false,
            dry_run: false,
            ignore: Vec::new(),
            default_ignores: true,
            ssh: "ssh".to_string(),
            ssh_options: Vec::new(),
            remote_command: "unisync".to_string(),
            verbose: false,
            quiet: false,
        }
    }
}

impl Options {
    /// The rules in force, which the far end adopts for the run.
    ///
    /// `--ignore` adds to the built-in list rather than replacing it, which is
    /// the opposite of what a `bisync` config does — a config is written once
    /// and read at leisure, and a flag typed at a prompt is not.
    /// `--no-default-ignores` is the way to start from nothing.
    pub fn ignore_set(&self) -> IgnoreSet {
        let mut lines: Vec<String> = Vec::new();
        if self.default_ignores {
            lines.extend(DEFAULT_PATTERNS.iter().map(|p| p.to_string()));
        }
        lines.extend(self.ignore.iter().cloned());
        IgnoreSet::new(lines)
    }

    fn config(&self) -> Config {
        Config {
            ssh: self.ssh.clone(),
            ssh_options: self.ssh_options.clone(),
            remote_command: self.remote_command.clone(),
            ..Config::default()
        }
    }
}

/// `unisync pull` and `unisync push`: the whole of one run.
pub fn transfer(root: &Path, peer: &Peer, way: Way, opts: &Options) -> io::Result<i32> {
    let reporter = Reporter::new(opts);
    let mut store = Store::open_at(root, store::UNI_CONTROL)?;
    let settings = Settings {
        max_size: opts.max_size,
        ignore: opts.ignore_set(),
        way,
        delete: opts.delete,
        compress: opts.compress,
        dry_run: opts.dry_run,
    };

    let (tx, rx) = mpsc::channel();
    let mut link = Link::connect(peer, &opts.config(), false, tx)?;
    reporter.info(&format!(
        "{} {} {}",
        root.display(),
        match way {
            Way::Pull => "<-",
            Way::Push => "->",
        },
        peer
    ));

    let mut session = Session::new(Role::Initiator, settings, &mut store);
    let report = session.scan()?;
    reporter.scan(&report);
    session.open();

    // Handshake and comparison. Both ends are working the whole time, so a peer
    // that goes quiet for the stall period has stopped.
    let outcome = spin(&mut session, &mut link, &rx, &reporter, Some(STALL), |s| {
        matches!(s.phase(), Phase::Deciding | Phase::Done)
    })
    .and_then(|()| carry_out(&mut session, &mut link, &rx, &reporter, opts, way));

    let abandoned = matches!(outcome, Ok(Ran::Abandoned));
    let outcome = outcome.map(|_| ());
    let stats = session.stats().clone();
    let failure = session.failure().map(str::to_string);
    drop(session);
    store.tidy();
    store.tidy_control();
    let _ = link.close();
    outcome?;
    if let Some(failure) = failure {
        eprintln!("unisync: {failure}");
        return Ok(1);
    }
    if !abandoned {
        reporter.summary(&stats, opts, &store);
    }
    Ok(if stats.refused > 0 { 1 } else { 0 })
}

/// Whether a run got as far as doing anything.
enum Ran {
    Through,
    /// The user answered `q`. Nothing accepted before that point happens either.
    Abandoned,
}

/// From a finished comparison to a finished run: report the plan, ask about it,
/// and see the accepted changes through.
fn carry_out(
    session: &mut Session<'_>,
    link: &mut Link,
    rx: &Receiver<Wake>,
    reporter: &Reporter,
    opts: &Options,
    way: Way,
) -> io::Result<Ran> {
    if session.phase() == Phase::Deciding {
        let plan = session.take_plan();
        reporter.plan(&plan, way);
        if !plan.is_empty() && !opts.dry_run {
            let accepted = match decide(session, link, rx, reporter, opts, way, plan.steps)? {
                Some(accepted) => accepted,
                None => {
                    reporter.info("abandoned; nothing was changed");
                    session.say_bye();
                    spin(session, link, rx, reporter, Some(STALL), |s| s.finished())?;
                    return Ok(Ran::Abandoned);
                }
            };
            reporter.info(&format!(
                "{} accepted",
                util::plural(accepted.len(), "change")
            ));
            session.commit(accepted)?;
            spin(session, link, rx, reporter, Some(STALL), |s| !s.busy())?;
        }
    }
    session.say_bye();
    spin(session, link, rx, reporter, Some(STALL), |s| s.finished())?;
    Ok(Ran::Through)
}

/// Put every step to the user, and return the ones they accepted — or `None` if
/// they abandoned the run, in which case nothing at all is carried out.
fn decide(
    session: &mut Session<'_>,
    link: &mut Link,
    rx: &Receiver<Wake>,
    reporter: &Reporter,
    opts: &Options,
    way: Way,
    steps: Vec<Step>,
) -> io::Result<Option<Vec<Step>>> {
    if opts.yes {
        return Ok(Some(steps));
    }
    // Deliberately not conditional on stdin being a terminal. Answers piped in
    // work, which is how this is tested and how someone scripts it; a stdin with
    // nothing on it reaches the end of input at the first question and abandons
    // the run, which is the safe reading of silence.
    let mut ask = Prompt::terminal();
    ask::choose(
        steps,
        &mut ask,
        |step| difference(session, link, rx, reporter, way, step),
        |step, why| reporter.left_alone(&step.path, why),
    )
}

/// What the two versions of one path actually differ by.
///
/// The peer's copy is fetched for this and thrown away — it lands in the control
/// directory's `tmp`, is read back, and is deleted. Which of the two versions is
/// the "new" one depends on which way the run goes: the peer holds the incoming
/// version of a pull, and the version about to be replaced of a push.
fn difference(
    session: &mut Session<'_>,
    link: &mut Link,
    rx: &Receiver<Wake>,
    reporter: &Reporter,
    way: Way,
    step: &Step,
) -> io::Result<String> {
    if !step.is_diffable() {
        return Ok(describe_undiffable(step));
    }
    let peers = match way {
        Way::Pull => &step.to,
        Way::Push => &step.from,
    };
    let PathState::File { digest, .. } = peers else {
        return Ok(describe_undiffable(step));
    };

    session.inspect(&step.path, *digest);
    spin(session, link, rx, reporter, Some(STALL), |s| {
        s.has_inspected()
    })?;
    let Some(fetched) = session.take_inspected().and_then(|i| i.content) else {
        return Ok("the peer would not send its copy, so there is nothing to compare".to_string());
    };

    let here = std::fs::read(relpath::join(session.root(), &step.path)).unwrap_or_default();
    // Old first, new second, whichever end each of them came from.
    let (old, new) = match way {
        Way::Pull => (here, fetched),
        Way::Push => (fetched, here),
    };
    let change = diff::compare(&old, &new, 3);
    let colour = reporter.colour;
    let mut out = String::new();
    for header in [
        format!(
            "--- {} now ({})",
            way.receiver(),
            util::format_size(old.len() as u64)
        ),
        format!(
            "+++ {} ({})",
            way.sender(),
            util::format_size(new.len() as u64)
        ),
    ] {
        out.push_str(&diff::paint(&header, colour));
        out.push('\n');
    }
    match change.kind {
        diff::Kind::Same => out.push_str("the two copies are identical\n"),
        diff::Kind::Binary => out.push_str("not text; nothing useful to show line by line\n"),
        diff::Kind::TooLarge => out.push_str(&format!(
            "{} lines replaced by {}: too much to show\n",
            change.removed, change.added
        )),
        diff::Kind::Text => {
            for (n, line) in change.text.lines().enumerate() {
                if n == DIFF_LINES {
                    out.push_str(&format!(
                        "... and {} more lines\n",
                        change.text.lines().count() - DIFF_LINES
                    ));
                    break;
                }
                out.push_str(&diff::paint(line, colour));
                out.push('\n');
            }
        }
    }
    Ok(out)
}

fn describe_undiffable(step: &Step) -> String {
    match (&step.from, &step.to) {
        (PathState::Absent, PathState::File { size, .. }) => format!(
            "a new file of {}; there is nothing here to compare it with",
            util::format_size(*size)
        ),
        (from, PathState::Absent) => {
            format!("{} would be removed", from.describe())
        }
        (from, to) => format!("{} would become {}", from.describe(), to.describe()),
    }
}

/// `unisync server` — the far end of a link. Speaks the protocol on stdin and
/// stdout and says nothing else there; anything for a human goes to stderr,
/// because stdout is the wire.
pub fn server(root: &Path) -> io::Result<i32> {
    let mut store = Store::open_at(root, store::UNI_CONTROL)?;
    let (tx, rx) = mpsc::channel();
    let mut link = Link::stdio(tx);
    let reporter = Reporter::server();
    // Every term arrives in `Hello`; these last only until it does.
    let mut session = Session::new(Role::Responder, Settings::default(), &mut store);
    // No stall timeout: the initiator is entitled to sit at a prompt for as long
    // as it takes someone to decide.
    let outcome = spin(&mut session, &mut link, &rx, &reporter, None, |s| {
        s.finished()
    });
    let stats = session.stats().clone();
    drop(session);
    store.tidy();
    store.tidy_control();
    let _ = link.close();
    outcome?;
    Ok(if stats.refused > 0 { 1 } else { 0 })
}

// --------------------------------------------------------------------- driver

/// Run the session until `until` is satisfied, the peer goes away, or it fails.
fn spin(
    session: &mut Session<'_>,
    link: &mut Link,
    rx: &Receiver<Wake>,
    reporter: &Reporter,
    stall: Option<Duration>,
    until: impl Fn(&Session<'_>) -> bool,
) -> io::Result<()> {
    let mut last_progress = Instant::now();
    loop {
        let mut spoke = flush(session, link, reporter)?;

        // Transfers, a bounded number of chunks at a time. Bounded so that a
        // large file cannot monopolise the loop and leave the peer unheard.
        let mut pending = false;
        for _ in 0..16 {
            if !session.pump()? {
                break;
            }
            pending = true;
            spoke |= flush(session, link, reporter)?;
        }
        // Settling can send `Bye`, which must not go out ahead of chunks that
        // are still queued behind it.
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
        if until(session) {
            return Ok(());
        }

        link.flush().map_err(peer_gone)?;
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
            }
            // No watcher runs here; a one-shot run takes the tree as it finds it.
            Some(Wake::Local(_)) => {}
            Some(Wake::Closed) => {
                return if session.busy() {
                    Err(io::Error::other("the peer closed the connection mid-run"))
                } else {
                    Ok(())
                };
            }
            Some(Wake::Failed(why)) => return Err(io::Error::other(why)),
            None => {
                if let Some(stall) = stall {
                    if last_progress.elapsed() > stall {
                        return Err(io::Error::other("the peer stopped responding"));
                    }
                }
            }
        }
    }
}

/// Send everything the session has queued and print what it wants to say.
fn flush(session: &mut Session<'_>, link: &mut Link, reporter: &Reporter) -> io::Result<bool> {
    let mut spoke = false;
    for msg in session.take_out() {
        link.send(&msg).map_err(peer_gone)?;
        spoke = true;
    }
    for event in session.take_events() {
        reporter.event(&event);
        spoke = true;
    }
    Ok(spoke)
}

/// Writing to a peer that has already exited.
///
/// Its own account of why — a directory that is not there, a program that is not
/// installed — has gone to stderr, which ssh forwards, so it is on the screen
/// already. Repeating that as a plumbing error would bury it.
fn peer_gone(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::BrokenPipe {
        io::Error::other("the peer went away before the run got going")
    } else {
        e
    }
}

// ------------------------------------------------------------------ reporting

struct Reporter {
    verbose: bool,
    quiet: bool,
    /// Whether what this writes to is a terminal, and so whether a diff is worth
    /// colouring. Answered once, at the top, rather than per line.
    colour: bool,
    /// A dry run's only output is the plan, so it is listed in full whether or
    /// not anyone asked to be verbose.
    dry_run: bool,
    /// stderr for the server: stdout is the wire.
    to_stderr: bool,
}

impl Reporter {
    fn new(opts: &Options) -> Reporter {
        Reporter {
            verbose: opts.verbose,
            quiet: opts.quiet,
            colour: io::stdout().is_terminal(),
            dry_run: opts.dry_run,
            to_stderr: false,
        }
    }

    fn server() -> Reporter {
        Reporter {
            verbose: false,
            quiet: true,
            // Nothing on the far side of a link is a terminal, and the initiator
            // would forward the escape codes into its own output.
            colour: false,
            dry_run: false,
            to_stderr: true,
        }
    }

    fn line(&self, text: &str) {
        if self.to_stderr {
            eprintln!("{text}");
        } else {
            let mut out = io::stdout().lock();
            let _ = writeln!(out, "{text}");
        }
    }

    fn info(&self, text: &str) {
        if !self.quiet {
            self.line(text);
        }
    }

    /// A step nobody was asked about, because an answer to another one settled
    /// it. Said out loud: it was in the plan, it is not going to happen, and the
    /// user did not answer for it directly.
    fn left_alone(&self, path: &str, why: &str) {
        if !self.quiet {
            self.line(&format!("skip    {path}  ({why})"));
        }
    }

    fn warn(&self, text: &str) {
        if self.to_stderr {
            eprintln!("unisync remote: {text}");
        } else {
            eprintln!("! {text}");
        }
    }

    fn scan(&self, report: &crate::scan::ScanReport) {
        if self.verbose {
            self.info(&report.summary());
        }
        let oversize = report.index.oversize();
        if !oversize.is_empty() && !self.quiet {
            let total: u64 = oversize.values().sum();
            self.line(&format!(
                "{} over the size limit, left out ({})",
                util::plural(oversize.len(), "file"),
                util::format_size(total)
            ));
        }
        for warning in report.warnings() {
            self.warn(&warning);
        }
    }

    /// What the comparison found, before anything is asked about it.
    fn plan(&self, plan: &Plan, way: Way) {
        if !plan.skipped.is_empty() && !self.quiet {
            self.line(&format!(
                "{} left out of the plan{}",
                util::plural(plan.skipped.len(), "difference"),
                if self.verbose { ":" } else { "; -v lists them" }
            ));
            if self.verbose {
                for skip in &plan.skipped {
                    self.line(&format!("      {}  ({})", skip.path, skip.why));
                }
            }
        }
        if plan.is_empty() {
            self.info(&format!(
                "nothing to {}: the two trees already agree about everything in the plan",
                way.name()
            ));
            return;
        }
        let tally: Vec<String> = plan
            .tally()
            .into_iter()
            .map(|(verb, n)| format!("{n} {verb}"))
            .collect();
        self.info(&format!(
            "{} for {} ({})",
            util::plural(plan.steps.len(), "change"),
            way.receiver(),
            tally.join(", ")
        ));
        // In a dry run this listing is the whole output, so it is not optional.
        if (self.verbose || self.dry_run) && !self.quiet {
            for step in &plan.steps {
                let detail = step.detail();
                if detail.is_empty() {
                    self.line(&format!("{:<7} {}", step.verb(), step.path));
                } else {
                    self.line(&format!("{:<7} {}  ({detail})", step.verb(), step.path));
                }
            }
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
                    self.line(&format!("{verb:<7} {path}"));
                } else {
                    self.line(&format!("{verb:<7} {path}  ({detail})"));
                }
            }
        }
    }

    fn summary(&self, stats: &Stats, opts: &Options, store: &Store) {
        if self.quiet {
            return;
        }
        if opts.dry_run {
            self.line("dry run: nothing was changed at either end");
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
        if stats.pushed > 0 {
            parts.push(format!(
                "{} carried out by the peer",
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
        if stats.kept > 0 {
            parts.push(format!(
                "{} kept in {}",
                util::count(stats.kept, "old version", "old versions"),
                store.diffs_rel()
            ));
        }
        if stats.refused > 0 {
            parts.push(format!(
                "{} could not be carried out",
                util::plural(stats.refused, "change")
            ));
        }
        if parts.is_empty() {
            parts.push("nothing changed".to_string());
        }
        self.line(&parts.join(", "));
    }
}

/// How much content moved, and what it cost on the wire when the two differ.
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
