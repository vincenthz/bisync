//! The protocol state machine, with no memory of anything before this run.
//!
//! One `Session` per end of a link, driven entirely by messages in and messages
//! out, exactly as [`crate::session`] is — and for the same reason: a whole
//! transfer can then be tested by wiring two of them together with no transport
//! at all. What is missing compared to its sibling is everything to do with
//! remembering. There is no base, no conflict record and no state file, so:
//!
//! * The comparison is a plain difference between two trees rather than a
//!   three-way merge. Where they disagree, the sending side's version is what
//!   the tree becomes.
//! * Nothing is ever decided about a path twice, so nothing needs to be frozen
//!   and there is nothing to resolve later. A change either happens in this run
//!   or is not mentioned again.
//! * The dangerous cases — a path the receiving side has and the sender does
//!   not, a directory facing a file — are not guessed at. They are either put to
//!   the user, or left out of the plan and reported.
//!
//! Everything the two ends say to each other is [`crate::proto`]'s message set,
//! unchanged: the framing, the descent and the transfer are the same protocol,
//! and only what a receiver does with `Announce` differs. The handshake carries
//! the program name, so a `unisync` pointed at a `bisync server` — which would
//! understand the frames and mean something else by them — stops before it has
//! done anything.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;

use crate::compress::{self, Encoding, Tally};
use crate::hash::Digest;
use crate::ignore::IgnoreSet;
use crate::merge::{Direction, Policy};
use crate::proto::{self, ANNOUNCE_BATCH, CHUNK, Change, Dest, Level, Msg, Reject, Root, WantItem};
use crate::scan;
use crate::store::{Guarded, Incoming, Outgoing, Placement, Store};
use crate::tree::{Entry, Index, Kind, PathState, Stamp};
use crate::util;

use super::plan::{self, Plan, Step, Survey, Way};

pub use crate::session::Role;

/// What goes in the handshake, and what the far end is checked against.
const PROGRAM: &str = "unisync";

/// How far the initiator has got.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    /// Before the peer has answered the handshake.
    Opening,
    /// Walking the two trees to find what differs.
    Surveying,
    /// The plan is ready and the driver has yet to say what to do with it. The
    /// only phase in which this session is waiting on a person rather than on a
    /// peer, and the reason the far end has no stall timeout.
    Deciding,
    /// Carrying out what was accepted.
    Working,
    /// Nothing left to do.
    Done,
}

/// The terms a run happens under. The initiator's are the session's; the
/// responder replaces its own with what arrives in `Hello`.
#[derive(Clone)]
pub struct Settings {
    pub max_size: u64,
    pub ignore: IgnoreSet,
    /// Which way content travels, from this end's point of view.
    pub way: Way,
    /// Propose removing what the sending side does not have.
    pub delete: bool,
    pub compress: u8,
    /// Decide and report; change nothing at either end.
    pub dry_run: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            max_size: crate::config::DEFAULT_MAX_SIZE,
            ignore: IgnoreSet::defaults(),
            way: Way::Pull,
            delete: false,
            compress: compress::DEFAULT_LEVEL,
            dry_run: false,
        }
    }
}

/// Something worth telling the user about.
#[derive(Clone, Debug)]
pub enum Event {
    Info(String),
    Warn(String),
    /// A change that happened, with a fixed short verb so the output lines up.
    Change {
        verb: &'static str,
        path: String,
        detail: String,
    },
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub sent: usize,
    pub sent_bytes: u64,
    pub received: usize,
    pub received_bytes: u64,
    pub deleted: usize,
    pub created: usize,
    /// Local versions copied aside before being replaced or removed.
    pub kept: usize,
    /// Changes the peer says it carried out.
    pub pushed: usize,
    /// Steps that could not be carried out, for whatever reason.
    pub refused: usize,
    pub dirs_listed: usize,
    pub out: Tally,
    pub inbound: Tally,
}

/// The peer's copy of a file, fetched only to be looked at.
pub struct Inspected {
    pub path: String,
    /// `None` when the peer would not or could not send it.
    pub content: Option<Vec<u8>>,
}

/// Content asked for, and what is to become of it.
struct Wanted {
    /// What the destination was when the step was proposed. The commit is
    /// refused if it is no longer that.
    expected: PathState,
    digest: Digest,
    dest: Dest,
    /// The step came from the peer's `Announce`, so the peer is waiting to hear
    /// how it went.
    answer: bool,
}

/// The transfer in progress on the sending side.
struct Sending {
    xfer: u32,
    compress: bool,
    tally: Tally,
}

/// What carrying out one step came to.
enum Outcome {
    Applied,
    /// Content was asked for; the answer comes when it lands.
    Pending,
    Refused(Reject, String),
}

pub struct Session<'a> {
    role: Role,
    pub settings: Settings,
    store: &'a mut Store,
    index: Index,
    /// Whether this is the end that does the writing. Decided here for the
    /// initiator and by the handshake for the responder, and consulted rather
    /// than re-derived, so there is one answer to the question.
    applies: bool,

    phase: Phase,
    survey: Survey,
    plan: Plan,
    peer_root: Option<Root>,

    out: Vec<Msg>,
    events: Vec<Event>,
    stats: Stats,

    wanted: BTreeMap<String, Wanted>,
    want_queue: Vec<WantItem>,
    /// Paths announced to the peer and not yet answered for.
    announced: BTreeSet<String>,
    announce_queue: Vec<Change>,

    send_queue: VecDeque<(String, Digest, Dest)>,
    active_send: Option<Outgoing>,
    sending: Option<Sending>,
    incoming: BTreeMap<u32, Incoming>,
    /// Transfers refused at `FileStart`, whose chunks are to be dropped rather
    /// than treated as an unknown transfer once each.
    refused: BTreeSet<u32>,
    inspected: Option<Inspected>,
    /// Paths this run has already dealt with. Only one thing puts a path here
    /// twice: emptying a directory that is being replaced deals with entries
    /// that are steps in their own right, and carrying those out again would
    /// count and report each of them twice.
    settled: BTreeSet<String>,

    ready: bool,
    bye_sent: bool,
    peer_bye: bool,
    failed: Option<String>,
}

impl<'a> Session<'a> {
    pub fn new(role: Role, settings: Settings, store: &'a mut Store) -> Session<'a> {
        // A responder learns its way from the handshake; until then this is only
        // a placeholder, and `applies` is set again when `Hello` arrives.
        let applies = role == Role::Initiator && settings.way == Way::Pull;
        // Following directories only the peer has costs a round trip each, and
        // is only worth it when what is inside them can affect the plan.
        let explore = settings.way == Way::Pull || settings.delete;
        Session {
            role,
            settings,
            store,
            index: Index::new(),
            applies,
            phase: Phase::Opening,
            survey: Survey::new(explore),
            plan: Plan::default(),
            peer_root: None,
            out: Vec::new(),
            events: Vec::new(),
            stats: Stats::default(),
            wanted: BTreeMap::new(),
            want_queue: Vec::new(),
            announced: BTreeSet::new(),
            announce_queue: Vec::new(),
            send_queue: VecDeque::new(),
            active_send: None,
            sending: None,
            incoming: BTreeMap::new(),
            refused: BTreeSet::new(),
            inspected: None,
            settled: BTreeSet::new(),
            ready: false,
            bye_sent: false,
            peer_bye: false,
            failed: None,
        }
    }

    // ------------------------------------------------------------- accessors

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    pub fn index(&self) -> &Index {
        &self.index
    }

    pub fn peer_root(&self) -> Option<&Root> {
        self.peer_root.as_ref()
    }

    pub fn failure(&self) -> Option<&str> {
        self.failed.as_deref()
    }

    pub fn take_out(&mut self) -> Vec<Msg> {
        self.flush_queues();
        std::mem::take(&mut self.out)
    }

    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// The peer's copy of a file asked for with [`Session::inspect`], once it
    /// has arrived or been refused.
    pub fn take_inspected(&mut self) -> Option<Inspected> {
        self.inspected.take()
    }

    /// Whether that answer has arrived. A separate question because the driver
    /// waits on it from a closure that only has the session by reference.
    pub fn has_inspected(&self) -> bool {
        self.inspected.is_some()
    }

    /// The sync root.
    pub fn root(&self) -> &std::path::Path {
        self.store.root()
    }

    /// Anything left to do on this side.
    pub fn busy(&self) -> bool {
        self.phase == Phase::Surveying
            || !self.wanted.is_empty()
            || !self.want_queue.is_empty()
            || !self.announced.is_empty()
            || !self.announce_queue.is_empty()
            || !self.send_queue.is_empty()
            || self.active_send.is_some()
            || !self.incoming.is_empty()
            || !self.out.is_empty()
    }

    pub fn finished(&self) -> bool {
        self.failed.is_some() || (self.peer_bye && !self.busy())
    }

    /// Rescan the tree.
    pub fn scan(&mut self) -> io::Result<scan::ScanReport> {
        let report = scan::scan(
            self.store.root(),
            &self.settings.ignore,
            self.settings.max_size,
            Some(&self.index),
        )?;
        self.index = report.index.clone();
        Ok(report)
    }

    /// Open the session. The initiator states the terms; the responder waits.
    pub fn open(&mut self) {
        if self.role != Role::Initiator {
            return;
        }
        self.out.push(Msg::Hello {
            version: proto::VERSION,
            program: program_id(),
            max_size: self.settings.max_size,
            ignore: self.settings.ignore.to_lines(),
            // Nothing here has conflicts to have a policy about, and the far end
            // ignores it. Sent because the message has the field.
            policy: Policy::default(),
            direction: self.settings.way.direction(),
            dry_run: self.settings.dry_run,
            compress: self.settings.compress,
            watch: false,
        });
    }

    // ---------------------------------------------------------------- driving

    /// The plan, taken. Only meaningful in [`Phase::Deciding`].
    pub fn take_plan(&mut self) -> Plan {
        std::mem::take(&mut self.plan)
    }

    /// Ask the peer for its copy of a file, to show a diff of it. The content
    /// goes nowhere near the tree: it is read back out of `tmp` and thrown away.
    pub fn inspect(&mut self, path: &str, digest: Digest) {
        self.inspected = None;
        self.request(path, PathState::Absent, digest, Dest::Inspect, false);
    }

    /// Carry out the accepted steps — here if this is the receiving end, or by
    /// telling the peer to if it is not.
    pub fn commit(&mut self, steps: Vec<Step>) -> io::Result<()> {
        self.phase = Phase::Working;
        if self.settings.dry_run {
            return Ok(());
        }
        if self.applies {
            for step in steps {
                self.carry_out(&step, false)?;
            }
            return Ok(());
        }
        for step in steps {
            self.announced.insert(step.path.clone());
            self.announce_queue.push(Change {
                path: step.path,
                from: step.from,
                to: step.to,
                mtime: step.mtime,
            });
        }
        Ok(())
    }

    /// Nothing more will be asked of the peer.
    pub fn say_bye(&mut self) {
        if !self.bye_sent {
            self.out.push(Msg::Bye);
            self.bye_sent = true;
        }
        if self.phase != Phase::Done {
            self.phase = Phase::Done;
        }
    }

    /// Called by the driver after every batch of work: the responder says
    /// goodbye once the initiator has and it has nothing left in flight.
    pub fn settle(&mut self) {
        if self.role == Role::Responder && self.peer_bye && !self.busy() {
            self.say_bye();
        }
    }

    // --------------------------------------------------------------- messages

    pub fn handle(&mut self, msg: Msg) -> io::Result<()> {
        match msg {
            Msg::Hello {
                version,
                program,
                max_size,
                ignore,
                direction,
                dry_run,
                compress,
                ..
            } => self.on_hello(
                version, &program, max_size, ignore, direction, dry_run, compress,
            )?,
            Msg::Welcome {
                version,
                program,
                root,
                ..
            } => self.on_welcome(version, &program, root),
            Msg::Rescan => {
                self.scan()?;
                let root = self.local_root();
                self.out.push(Msg::Root(root));
            }
            // Only the initiator compares roots, and it does so from `Welcome`.
            // A later one is news about the peer, not an instruction.
            Msg::Root(root) => self.peer_root = Some(root),
            Msg::ListDir { path } => self.on_list_dir(&path),
            Msg::DirList {
                path,
                exists,
                children,
                ..
            } => self.on_dir_list(&path, exists, &children),
            Msg::Announce { changes } => self.on_announce(changes)?,
            Msg::Want { items } => self.on_want(items),
            Msg::Applied { paths } => self.on_applied(&paths),
            Msg::Rejected { items } => self.on_rejected(items),
            Msg::FileStart {
                xfer,
                path,
                dest,
                digest,
                size,
                mode,
                mtime,
            } => self.on_file_start(xfer, path, dest, digest, size, mode, mtime),
            Msg::FileData {
                xfer,
                encoding,
                plain_len,
                data,
            } => self.on_file_data(xfer, encoding, plain_len, &data),
            Msg::FileEnd { xfer } => self.on_file_end(xfer)?,
            Msg::FileAbort { xfer, reason } => self.on_file_abort(xfer, &reason),
            Msg::Note { level, text } => {
                let line = format!("peer: {text}");
                self.events.push(match level {
                    Level::Info => Event::Info(line),
                    _ => Event::Warn(line),
                });
            }
            Msg::Error { text } => self.failed = Some(format!("peer reported: {text}")),
            Msg::Bye => self.peer_bye = true,
            Msg::Ping { token } => self.out.push(Msg::Pong { token }),
            Msg::Pong { .. } => {}
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn on_hello(
        &mut self,
        version: u32,
        program: &str,
        max_size: u64,
        ignore: Vec<String>,
        direction: Direction,
        dry_run: bool,
        compress: u8,
    ) -> io::Result<()> {
        if self.role != Role::Responder {
            return self.refuse("the peer opened a session at an end that had already opened one");
        }
        if version != proto::VERSION {
            return self.refuse(&format!(
                "protocol {version} from {program}, but this is {}: install the same version at both ends",
                proto::VERSION
            ));
        }
        if !is_unisync(program) {
            return self.refuse(&format!(
                "{program} speaks this protocol but means other things by it; \
                 the far end of a unisync run must be `unisync server`"
            ));
        }
        // A direction names a way along the link, so the responder's is the
        // mirror of what it was sent.
        self.settings.way = match direction {
            Direction::Pull => Way::Push,
            Direction::Push => Way::Pull,
            Direction::Both => {
                return self.refuse("a unisync run goes one way; this one claims to go both");
            }
        };
        self.applies = self.settings.way == Way::Pull;
        // The initiator's terms, wholesale: two ends filtering or size-limiting
        // differently would disagree about what is in the tree at all.
        self.settings.ignore = IgnoreSet::new(&ignore);
        self.settings.max_size = max_size;
        self.settings.compress = compress;
        self.settings.dry_run = dry_run;
        self.ready = true;
        self.phase = Phase::Working;

        let report = self.scan()?;
        self.events.push(Event::Info(report.summary()));
        for warning in report.warnings() {
            self.events.push(Event::Warn(warning));
        }
        let root = self.local_root();
        self.out.push(Msg::Welcome {
            version: proto::VERSION,
            program: program_id(),
            // Nothing compares this: the far end of a `unisync` run has no
            // configuration of its own to disagree with.
            own_ignore: self.settings.ignore.digest(),
            root,
        });
        Ok(())
    }

    fn on_welcome(&mut self, version: u32, program: &str, root: Root) {
        if version != proto::VERSION {
            self.failed = Some(format!(
                "the far end speaks protocol {version} ({program}), this one {}: \
                 install the same version at both ends",
                proto::VERSION
            ));
            return;
        }
        if !is_unisync(program) {
            self.failed = Some(format!(
                "the far end answered as {program}, not unisync: \
                 point --remote-command at a unisync on that machine"
            ));
            return;
        }
        self.ready = true;
        if root.oversize > 0 {
            self.events.push(Event::Info(format!(
                "the peer is skipping {} over the {} limit ({} in all)",
                util::plural(root.oversize as usize, "file"),
                util::format_size(self.settings.max_size),
                util::format_size(root.oversize_bytes)
            )));
        }
        let same = root.digest == self.index.root_digest();
        self.peer_root = Some(root);
        if same {
            self.events.push(Event::Info(format!(
                "the two trees are identical at {}",
                self.index.root_digest().short()
            )));
            self.phase = Phase::Done;
            return;
        }
        self.phase = Phase::Surveying;
        self.survey.start();
        self.emit_requests();
    }

    fn on_list_dir(&mut self, path: &str) {
        let children = self.index.children(path);
        let exists = path.is_empty() || self.index.dir_digest(path).is_some();
        let digest = self.index.dir_digest(path).unwrap_or_default();
        self.stats.dirs_listed += 1;
        self.out.push(Msg::DirList {
            path: path.to_string(),
            exists,
            digest,
            children,
        });
    }

    fn on_dir_list(&mut self, dir: &str, exists: bool, children: &[crate::tree::Child]) {
        if !exists && !children.is_empty() {
            self.events.push(Event::Warn(format!(
                "the peer listed children for {dir:?}, which it says is absent"
            )));
        }
        self.survey.absorb(&self.index, dir, children);
        self.emit_requests();
        if self.survey.done() && self.phase == Phase::Surveying {
            let found = std::mem::replace(&mut self.survey, Survey::new(false)).into_found();
            self.plan = plan::plan(found, &self.index, self.settings.way, self.settings.delete);
            self.phase = Phase::Deciding;
        }
    }

    fn emit_requests(&mut self) {
        for path in self.survey.take_requests() {
            self.out.push(Msg::ListDir { path });
        }
    }

    /// The peer wants these changes made here. Nothing is weighed up: the peer
    /// is the end a person sat at, and it has already asked them.
    fn on_announce(&mut self, changes: Vec<Change>) -> io::Result<()> {
        let mut steps: Vec<Step> = changes
            .into_iter()
            .map(|change| Step {
                path: change.path,
                from: change.from,
                to: change.to,
                mtime: change.mtime,
            })
            .collect();
        plan::order(&mut steps);

        let mut applied = Vec::new();
        let mut rejected = Vec::new();
        for step in steps {
            match self.carry_out(&step, true)? {
                Outcome::Applied => applied.push(step.path),
                Outcome::Pending => {}
                Outcome::Refused(reason, detail) => rejected.push((step.path, reason, detail)),
            }
        }
        if !applied.is_empty() {
            self.out.push(Msg::Applied { paths: applied });
        }
        if !rejected.is_empty() {
            self.out.push(Msg::Rejected { items: rejected });
        }
        Ok(())
    }

    fn on_applied(&mut self, paths: &[String]) {
        for path in paths {
            if self.announced.remove(path) {
                self.stats.pushed += 1;
            }
        }
    }

    fn on_rejected(&mut self, items: Vec<(String, Reject, String)>) {
        for (path, reason, detail) in items {
            // A fetch made only to show a diff: the driver is waiting on an
            // answer either way, and "no" is an answer.
            if self
                .wanted
                .get(&path)
                .is_some_and(|w| w.dest == Dest::Inspect)
            {
                self.wanted.remove(&path);
                self.inspected = Some(Inspected {
                    path,
                    content: None,
                });
                continue;
            }
            self.wanted.remove(&path);
            self.announced.remove(&path);
            self.stats.refused += 1;
            self.events.push(Event::Change {
                verb: "skip",
                path,
                detail: format!("{}: {detail}", reason.describe()),
            });
        }
    }

    // --------------------------------------------------------------- applying

    /// Carry out one step, guarded.
    ///
    /// `answer` says whether the peer is waiting to be told how it went, which
    /// is true of everything that arrived in an `Announce` and of nothing this
    /// side decided for itself.
    fn carry_out(&mut self, step: &Step, answer: bool) -> io::Result<Outcome> {
        let rel = step.path.as_str();
        if self.settled.contains(rel) {
            return Ok(Outcome::Applied);
        }
        if let Some(rule) = self
            .settings
            .ignore
            .explain(rel, step.to.kind() == Some(Kind::Dir))
        {
            let rule = rule.to_string();
            self.note_skip(rel, &format!("ignored by {rule:?}"));
            return Ok(Outcome::Refused(Reject::Ignored, rule));
        }
        if let PathState::File { size, .. } = &step.to {
            if *size > self.settings.max_size {
                let detail = format!(
                    "{} > {}",
                    util::format_size(*size),
                    util::format_size(self.settings.max_size)
                );
                self.note_skip(
                    rel,
                    &format!("{} is over the limit", util::format_size(*size)),
                );
                return Ok(Outcome::Refused(Reject::TooLarge, detail));
            }
        }
        if self.settings.dry_run {
            return Ok(Outcome::Refused(Reject::Failed, "dry run".to_string()));
        }
        if !self.applies {
            return Ok(Outcome::Refused(
                Reject::Direction,
                "content is not flowing this way in this run".to_string(),
            ));
        }

        // A directory being replaced takes everything inside it with it, and
        // each of those has to be dealt with, and guarded, before the directory
        // itself can be.
        if matches!(step.from, PathState::Dir) && !matches!(step.to, PathState::Dir) {
            self.drop_subtree(rel)?;
        }

        match &step.to {
            PathState::Absent => match self.store.remove(rel, &step.from)? {
                Guarded::Applied { kept } => {
                    self.index.remove(rel);
                    self.index.remove_subtree(rel);
                    self.settled.insert(rel.to_string());
                    self.stats.deleted += 1;
                    self.stats.kept += kept.is_some() as usize;
                    let detail = describe_kept(&kept);
                    self.change("del", rel, detail);
                    Ok(Outcome::Applied)
                }
                Guarded::Changed(actual) => Ok(self.moved(rel, actual)),
                Guarded::Refused(why) => {
                    self.warn(&format!("{rel}: not deleted: {why}"));
                    self.stats.refused += 1;
                    Ok(Outcome::Refused(Reject::Failed, why))
                }
            },
            PathState::Dir => {
                // A file where the sending side has a directory has to go first,
                // guarded by what was proposed, or `mkdir` would just report that
                // something is in the way.
                if matches!(
                    step.from,
                    PathState::File { .. } | PathState::Symlink { .. }
                ) {
                    match self.store.remove(rel, &step.from)? {
                        Guarded::Applied { kept } => {
                            self.index.remove(rel);
                            self.note_kept(&kept);
                        }
                        Guarded::Changed(actual) => return Ok(self.moved(rel, actual)),
                        Guarded::Refused(why) => {
                            self.stats.refused += 1;
                            return Ok(Outcome::Refused(Reject::Failed, why));
                        }
                    }
                }
                match self.store.make_dir(rel, 0o755)? {
                    Guarded::Applied { .. } => {
                        self.index.insert(rel.to_string(), Entry::dir(0o755));
                        self.stats.created += 1;
                        self.change("mkdir", rel, String::new());
                        Ok(Outcome::Applied)
                    }
                    Guarded::Changed(actual) => Ok(self.moved(rel, actual)),
                    Guarded::Refused(why) => {
                        self.stats.refused += 1;
                        Ok(Outcome::Refused(Reject::Failed, why))
                    }
                }
            }
            PathState::Symlink { target } => {
                match self.store.set_symlink(rel, target, &step.from)? {
                    Guarded::Applied { kept } => {
                        let digest = crate::hash::symlink_digest(target.as_bytes());
                        self.index
                            .insert(rel.to_string(), Entry::symlink(digest, target.clone()));
                        self.note_kept(&kept);
                        self.change("link", rel, format!("-> {target}"));
                        Ok(Outcome::Applied)
                    }
                    Guarded::Changed(actual) => Ok(self.moved(rel, actual)),
                    Guarded::Refused(why) => {
                        self.stats.refused += 1;
                        Ok(Outcome::Refused(Reject::Failed, why))
                    }
                }
            }
            PathState::File { digest, mode, .. } => {
                // The same bytes with different permissions: nothing to
                // transfer, and asking for a megabyte to change one octal digit
                // would be absurd.
                if let PathState::File { digest: here, .. } = &step.from {
                    if here == digest {
                        self.store.set_mode(rel, *mode)?;
                        if let Some(entry) = self.index.get_mut(rel) {
                            entry.mode = *mode;
                        }
                        self.change("chmod", rel, format!("{mode:04o}"));
                        return Ok(Outcome::Applied);
                    }
                }
                self.request(rel, step.from.clone(), *digest, Dest::Live, answer);
                Ok(Outcome::Pending)
            }
        }
    }

    /// Empty a directory that is about to be replaced, deepest first and each
    /// entry guarded by what the scan saw. Anything that has changed since is
    /// left where it is, which then leaves the directory non-empty — and that is
    /// the right outcome, reported rather than forced.
    fn drop_subtree(&mut self, dir: &str) -> io::Result<()> {
        let mut victims: Vec<(String, PathState)> = self
            .index
            .range_under(dir)
            .map(|(path, entry)| (path.clone(), entry.state()))
            .collect();
        victims.sort_by(|a, b| b.0.cmp(&a.0));
        for (path, expected) in victims {
            match self.store.remove(&path, &expected)? {
                Guarded::Applied { kept } => {
                    self.index.remove(&path);
                    self.settled.insert(path.clone());
                    self.stats.deleted += 1;
                    self.stats.kept += kept.is_some() as usize;
                    let detail = describe_kept(&kept);
                    self.change("del", &path, detail);
                }
                Guarded::Changed(actual) => {
                    self.moved(&path, actual);
                }
                Guarded::Refused(why) => self.warn(&format!("{path}: not deleted: {why}")),
            }
        }
        Ok(())
    }

    /// The path is no longer what the user was asked about, so the answer they
    /// gave is not about this. Nothing is touched.
    fn moved(&mut self, rel: &str, actual: PathState) -> Outcome {
        self.warn(&format!(
            "{rel}: changed since it was proposed (now {}); left alone",
            actual.describe()
        ));
        self.stats.refused += 1;
        Outcome::Refused(
            Reject::Failed,
            format!(
                "changed to {} before it could be applied",
                actual.describe()
            ),
        )
    }

    fn request(
        &mut self,
        rel: &str,
        expected: PathState,
        digest: Digest,
        dest: Dest,
        answer: bool,
    ) {
        // One request per path at a time; a second would race the first into the
        // same destination.
        if self.wanted.contains_key(rel) {
            return;
        }
        self.wanted.insert(
            rel.to_string(),
            Wanted {
                expected,
                digest,
                dest,
                answer,
            },
        );
        self.want_queue.push(WantItem {
            path: rel.to_string(),
            digest,
            dest,
        });
    }

    // -------------------------------------------------------------- transfers

    fn on_want(&mut self, items: Vec<WantItem>) {
        let mut rejected = Vec::new();
        for item in items {
            if let Some(rule) = self.settings.ignore.explain(&item.path, false) {
                rejected.push((item.path, Reject::Ignored, rule.to_string()));
                continue;
            }
            match self.index.get(&item.path) {
                Some(entry) if entry.kind == Kind::File && entry.digest == item.digest => {
                    if entry.size > self.settings.max_size {
                        rejected.push((item.path, Reject::TooLarge, util::format_size(entry.size)));
                        continue;
                    }
                    self.send_queue
                        .push_back((item.path, item.digest, item.dest));
                }
                // It moved on since the comparison. Saying so is better than
                // sending different bytes under the old digest.
                Some(entry) => rejected.push((
                    item.path,
                    Reject::HaveNewer,
                    format!("now {}", entry.digest.short()),
                )),
                None => rejected.push((item.path, Reject::Failed, "gone".to_string())),
            }
        }
        if !rejected.is_empty() {
            self.out.push(Msg::Rejected { items: rejected });
        }
    }

    /// Push transfers along by one chunk, and say whether there is more to do.
    ///
    /// One chunk per call, so the caller keeps control and can interleave reads
    /// from the peer rather than going deaf for the length of a file.
    pub fn pump(&mut self) -> io::Result<bool> {
        if self.active_send.is_none() {
            let Some((path, digest, dest)) = self.send_queue.pop_front() else {
                return Ok(false);
            };
            match self.store.send(&path, digest) {
                Ok(outgoing) => {
                    let xfer = self.store.next_xfer();
                    let compress =
                        self.settings.compress > 0 && !compress::already_compressed(&path);
                    self.out.push(Msg::FileStart {
                        xfer,
                        path,
                        dest,
                        digest,
                        size: outgoing.size,
                        mode: outgoing.mode,
                        mtime: outgoing.mtime,
                    });
                    self.sending = Some(Sending {
                        xfer,
                        compress,
                        tally: Tally::default(),
                    });
                    self.active_send = Some(outgoing);
                }
                Err(e) => {
                    self.out.push(Msg::Rejected {
                        items: vec![(path, Reject::Failed, e.to_string())],
                    });
                    return Ok(true);
                }
            }
        }

        let mut sending = self.sending.take().expect("a transfer in progress");
        let xfer = sending.xfer;
        let mut outgoing = self.active_send.take().expect("active send");
        let mut buf = vec![0u8; CHUNK];
        match outgoing.next(&mut buf) {
            Ok(0) => {
                let path = outgoing.path.clone();
                let size = outgoing.sent();
                match outgoing.verify() {
                    Ok(()) => {
                        self.out.push(Msg::FileEnd { xfer });
                        self.stats.sent += 1;
                        self.stats.sent_bytes += size;
                        let detail = describe_transfer(sending.tally);
                        self.change("send", &path, detail);
                    }
                    // The file changed under us mid-read. Withdraw it rather
                    // than deliver bytes the announced digest does not cover.
                    Err(mismatch) => {
                        let reason = mismatch.to_string();
                        self.out.push(Msg::FileAbort {
                            xfer,
                            reason: reason.clone(),
                        });
                        self.warn(&reason);
                    }
                }
            }
            Ok(n) => {
                // Deflate the chunk and keep the result only if it came out
                // smaller. The frame says which it is, so the two ends never
                // have to agree about it beforehand.
                let squeezed = if sending.compress {
                    compress::shrink(&buf[..n], self.settings.compress)
                } else {
                    None
                };
                let (encoding, data) = match squeezed {
                    Some(squeezed) => (Encoding::Deflate, squeezed),
                    None => {
                        buf.truncate(n);
                        (Encoding::Raw, buf)
                    }
                };
                let (plain, wire) = (n as u64, data.len() as u64);
                sending.tally.record(plain, wire);
                self.stats.out.record(plain, wire);
                self.out.push(Msg::FileData {
                    xfer,
                    encoding,
                    plain_len: n as u32,
                    data,
                });
                self.active_send = Some(outgoing);
                self.sending = Some(sending);
            }
            Err(e) => {
                let reason = e.to_string();
                let path = outgoing.path.clone();
                self.out.push(Msg::FileAbort {
                    xfer,
                    reason: reason.clone(),
                });
                self.warn(&format!("{path}: {reason}"));
            }
        }
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    fn on_file_start(
        &mut self,
        xfer: u32,
        path: String,
        dest: Dest,
        digest: Digest,
        size: u64,
        mode: u32,
        mtime: Stamp,
    ) {
        // Only content that was asked for, at the digest it was asked for.
        // Without this a peer could write anywhere in the tree by simply
        // starting to send.
        let ok = self
            .wanted
            .get(&path)
            .is_some_and(|w| w.digest == digest && w.dest == dest);
        if !ok {
            self.refused.insert(xfer);
            self.out.push(Msg::Rejected {
                items: vec![(path, Reject::Failed, "not requested".to_string())],
            });
            return;
        }
        if size > self.settings.max_size {
            self.refused.insert(xfer);
            self.wanted.remove(&path);
            self.out.push(Msg::Rejected {
                items: vec![(path, Reject::TooLarge, util::format_size(size))],
            });
            return;
        }
        match self
            .store
            .receive(xfer, &path, dest, digest, size, mode, mtime)
        {
            Ok(incoming) => {
                self.incoming.insert(xfer, incoming);
            }
            Err(e) => {
                self.refused.insert(xfer);
                self.wanted.remove(&path);
                self.out.push(Msg::Rejected {
                    items: vec![(path, Reject::Failed, e.to_string())],
                });
            }
        }
    }

    fn on_file_data(&mut self, xfer: u32, encoding: Encoding, plain_len: u32, data: &[u8]) {
        if self.refused.contains(&xfer) {
            return;
        }
        if !self.incoming.contains_key(&xfer) {
            self.refused.insert(xfer);
            return;
        }
        // Decoded before anything else touches it, so the digest, the size guard
        // and the temporary file never have to know compression exists.
        let plain = match encoding {
            Encoding::Raw => Ok(data.to_vec()),
            Encoding::Deflate => compress::expand(data, plain_len as usize),
        };
        let outcome = plain.and_then(|plain| {
            let incoming = self.incoming.get_mut(&xfer).expect("checked above");
            incoming.write(&plain)?;
            incoming.record_wire(data.len());
            Ok(plain.len() as u64)
        });
        match outcome {
            Ok(plain) => self.stats.inbound.record(plain, data.len() as u64),
            Err(e) => {
                let incoming = self.incoming.remove(&xfer).expect("checked above");
                let path = incoming.path.clone();
                self.store.discard(incoming);
                self.wanted.remove(&path);
                self.refused.insert(xfer);
                self.warn(&format!("{path}: {e}"));
                self.out.push(Msg::Rejected {
                    items: vec![(path, Reject::Failed, e.to_string())],
                });
            }
        }
    }

    fn on_file_end(&mut self, xfer: u32) -> io::Result<()> {
        self.refused.remove(&xfer);
        let Some(incoming) = self.incoming.remove(&xfer) else {
            return Ok(());
        };
        let path = incoming.path.clone();
        let arrived = Tally {
            plain: incoming.received(),
            wire: incoming.wire(),
        };
        let Some(want) = self.wanted.remove(&path) else {
            self.store.discard(incoming);
            return Ok(());
        };
        let sealed = match self.store.seal(incoming) {
            Ok(sealed) => sealed,
            // The bytes do not hash to what was promised. Nothing was written
            // outside `tmp`, and that has been removed.
            Err(Guarded::Refused(why)) => {
                self.warn(&why);
                self.stats.refused += 1;
                if want.dest == Dest::Inspect {
                    self.inspected = Some(Inspected {
                        path,
                        content: None,
                    });
                } else if want.answer {
                    self.out.push(Msg::Rejected {
                        items: vec![(path, Reject::Failed, why)],
                    });
                }
                return Ok(());
            }
            Err(_) => unreachable!("seal returns only Refused"),
        };

        if want.dest == Dest::Inspect {
            let content = self.store.read_sealed(&sealed)?;
            self.store.discard_sealed(sealed);
            self.inspected = Some(Inspected {
                path,
                content: Some(content),
            });
            return Ok(());
        }

        match self.store.place(sealed, &want.expected)? {
            Placement::Done(landed) => {
                self.index.insert(
                    path.clone(),
                    Entry {
                        kind: Kind::File,
                        digest: landed.digest,
                        size: landed.size,
                        mode: landed.mode,
                        mtime: landed.mtime,
                        ino: 0,
                        target: String::new(),
                    },
                );
                self.stats.received += 1;
                self.stats.received_bytes += landed.size;
                if let Some(at) = &landed.kept {
                    self.stats.kept += 1;
                    self.events.push(Event::Info(format!(
                        "{path}: previous version kept at {at}"
                    )));
                }
                let detail = describe_transfer(arrived);
                self.change("recv", &path, detail);
                if want.answer {
                    self.out.push(Msg::Applied { paths: vec![path] });
                }
            }
            // Someone edited the destination while the transfer was running. The
            // fetched copy is intact and verified, so it is kept aside rather
            // than either written over live work or thrown away.
            Placement::Changed { actual, sealed } => {
                let at = self.store.place_aside(sealed)?;
                self.warn(&format!(
                    "{path}: changed here during the transfer ({}); the peer's copy is at {at}",
                    actual.describe()
                ));
                self.stats.refused += 1;
                if want.answer {
                    self.out.push(Msg::Rejected {
                        items: vec![(
                            path,
                            Reject::Failed,
                            "changed during the transfer".to_string(),
                        )],
                    });
                }
            }
        }
        Ok(())
    }

    fn on_file_abort(&mut self, xfer: u32, reason: &str) {
        self.refused.remove(&xfer);
        let Some(incoming) = self.incoming.remove(&xfer) else {
            return;
        };
        let path = incoming.path.clone();
        self.store.discard(incoming);
        let want = self.wanted.remove(&path);
        self.stats.refused += 1;
        self.warn(&format!("{path}: the peer withdrew it: {reason}"));
        if want.is_some_and(|w| w.dest == Dest::Inspect) {
            self.inspected = Some(Inspected {
                path,
                content: None,
            });
        }
    }

    // ------------------------------------------------------------------ small

    pub fn local_root(&self) -> Root {
        let index = &self.index;
        Root {
            digest: index.root_digest(),
            files: index.count_of(Kind::File) as u32,
            dirs: index.count_of(Kind::Dir) as u32,
            symlinks: index.count_of(Kind::Symlink) as u32,
            bytes: index.total_bytes(),
            oversize: index.oversize().len() as u32,
            oversize_bytes: index.oversize().values().sum(),
        }
    }

    /// Turn queued wants and announcements into messages, batched.
    fn flush_queues(&mut self) {
        if !self.want_queue.is_empty() {
            let items = std::mem::take(&mut self.want_queue);
            self.out.push(Msg::Want { items });
        }
        while !self.announce_queue.is_empty() {
            let take = self.announce_queue.len().min(ANNOUNCE_BATCH);
            let changes: Vec<Change> = self.announce_queue.drain(..take).collect();
            self.out.push(Msg::Announce { changes });
        }
    }

    /// Say so, tell the peer, and stop.
    fn refuse(&mut self, text: &str) -> io::Result<()> {
        self.out.push(Msg::Error {
            text: text.to_string(),
        });
        self.failed = Some(text.to_string());
        Ok(())
    }

    fn change(&mut self, verb: &'static str, path: &str, detail: String) {
        self.events.push(Event::Change {
            verb,
            path: path.to_string(),
            detail,
        });
    }

    fn warn(&mut self, text: &str) {
        self.events.push(Event::Warn(text.to_string()));
    }

    /// A step that is not going to happen, and why. Counted, because a run that
    /// could not do what it was told to is not a run that did nothing.
    fn note_skip(&mut self, path: &str, detail: &str) {
        self.stats.refused += 1;
        self.events.push(Event::Change {
            verb: "skip",
            path: path.to_string(),
            detail: detail.to_string(),
        });
    }

    fn note_kept(&mut self, kept: &Option<String>) {
        if let Some(at) = kept {
            self.stats.kept += 1;
            self.events
                .push(Event::Info(format!("previous version kept at {at}")));
        }
    }
}

fn program_id() -> String {
    format!("{PROGRAM} {}", env!("CARGO_PKG_VERSION"))
}

/// Is the far end this program? The version string is `unisync <version>`, and
/// what matters is the name: the message set is `bisync`'s, so a `bisync server`
/// would understand every frame and act on `Announce` by merging it against a
/// base this tool has never heard of.
fn is_unisync(program: &str) -> bool {
    program == PROGRAM || program.starts_with(&format!("{PROGRAM} "))
}

/// A `send` or `recv` line's detail: the size, and what it cost on the wire when
/// the two differ.
fn describe_transfer(tally: Tally) -> String {
    if tally.wire >= tally.plain {
        return util::format_size(tally.plain);
    }
    format!(
        "{} -> {}, {}% saved",
        util::format_size(tally.plain),
        util::format_size(tally.wire),
        tally.percent()
    )
}

fn describe_kept(kept: &Option<String>) -> String {
    match kept {
        Some(at) => format!("kept at {at}"),
        None => String::new(),
    }
}
