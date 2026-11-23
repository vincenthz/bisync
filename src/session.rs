//! The protocol state machine: messages in, messages and filesystem effects out.
//!
//! One `Session` per end of a link. It is symmetric except for two things the
//! initiator does alone — send `Hello`, and drive the Merkle descent — because
//! both ends descending at once would do the same work twice and race each other
//! into the same decisions.
//!
//! The session touches the filesystem through [`Store`], which guards every
//! destructive operation, and it holds no sockets: messages arrive by
//! [`Session::handle`] and leave through [`Session::take_out`]. That is what
//! makes a full two-way sync testable by wiring two sessions' outboxes to each
//! other's inboxes in a loop with no transport at all.
//!
//! # Where the work comes from
//!
//! Two paths lead to the same place, and both are needed.
//!
//! **Descent** answers "we have just connected, what differs?" without either
//! side enumerating its tree at the other. Compare root digests; if they differ,
//! ask for the root's children; recurse only into children whose digests differ.
//! A tree with one changed file costs one `DirList` per level of its depth.
//!
//! **Announcement** answers "something just changed here" while connected. The
//! side that noticed sends `from -> to`; the other decides what it wants. No
//! descent, no rescan on the far side, and the `from` field lets the receiver
//! tell a fast-forward from a genuine divergence.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;

use crate::compress::{self, Encoding, Tally};
use crate::diff;
use crate::hash::Digest;
use crate::ignore::IgnoreSet;
use crate::merge::{self, Conflict, Decision, Direction, Policy};
use crate::proto::{self, ANNOUNCE_BATCH, CHUNK, Change, Dest, Level, Msg, Reject, Root, WantItem};
use crate::relpath;
use crate::scan;
use crate::state::{ConflictRecord, State};
use crate::store::{Guarded, Incoming, Placement, Store};
use crate::tree::{Entry, Kind, PathState, Stamp};
use crate::util;

/// How deep the descent will follow a peer. Far beyond any real tree; a bound
/// exists so a peer that answers every `ListDir` with another directory cannot
/// keep us walking forever.
const MAX_DEPTH: usize = 256;

/// Which end of the link this is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Spawned the other end. Sends `Hello`, drives the descent, decides when
    /// the session is over.
    Initiator,
    /// Was spawned. Answers, and announces its own changes.
    Responder,
}

/// The terms a session runs under. The initiator's copy is authoritative and is
/// sent in `Hello`; the responder replaces its own with what it receives.
#[derive(Clone)]
pub struct Settings {
    pub max_size: u64,
    pub ignore: IgnoreSet,
    pub policy: Policy,
    /// Which way changes may flow.
    pub direction: Direction,
    /// DEFLATE level for content, or 0 to send it uncompressed.
    pub compress: u8,
    /// Stay connected after reconciling.
    pub watch: bool,
    /// Decide and report, change nothing.
    pub dry_run: bool,
    /// On a dry run, fetch what would arrive and show a diff against what is
    /// here. Costs the transfer it is describing; nothing is written to the tree.
    pub diff: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            max_size: crate::config::DEFAULT_MAX_SIZE,
            ignore: IgnoreSet::defaults(),
            policy: Policy::default(),
            direction: Direction::default(),
            compress: compress::DEFAULT_LEVEL,
            watch: false,
            dry_run: false,
            diff: false,
        }
    }
}

/// The session terms as they arrive in `Hello`, so adopting them is one
/// destructuring rather than eight positional arguments.
struct Terms {
    version: u32,
    program: String,
    max_size: u64,
    ignore: Vec<String>,
    policy: Policy,
    direction: Direction,
    dry_run: bool,
    compress: u8,
    watch: bool,
}

/// Something worth telling the user about.
#[derive(Clone, Debug)]
pub enum Event {
    Info(String),
    Warn(String),
    /// A change applied to this side's tree. `verb` is a fixed short word so the
    /// output lines up: `recv`, `send`, `del`, `link`, `mkdir`, `chmod`, `skip`.
    Change {
        verb: &'static str,
        path: String,
        detail: String,
    },
    /// What a dry run found between the local version and the incoming one.
    Diff {
        path: String,
        was: u64,
        becomes: u64,
        change: diff::Change,
    },
    Conflict {
        path: String,
        kind: Conflict,
        /// Where the peer's version was put, if it was fetched.
        quarantine: Option<String>,
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
    /// Peer versions of conflicted paths saved aside. Counted apart from
    /// `received`, because nothing in the tree changed.
    pub quarantined: usize,
    /// Local versions copied to `.bisync/diffs` before being replaced.
    pub kept: usize,
    /// Paths left alone because changes are not flowing that way this session.
    pub declined: usize,
    /// Changes the peer accepted from us that needed no transfer, plus files it
    /// took: what this side pushed, as acknowledged rather than as offered.
    pub pushed: usize,
    pub conflicts: usize,
    pub dirs_listed: usize,
    /// Content sent: plain bytes against bytes on the wire.
    pub out: Tally,
    /// Content received, likewise.
    pub inbound: Tally,
}

/// A path whose content we asked for, and why.
struct Wanted {
    /// What the local path was when the decision was made. The commit is refused
    /// if it is no longer that.
    expected: PathState,
    /// What the base becomes if it lands live.
    target: PathState,
    digest: Digest,
    dest: Dest,
    /// Copy the existing local version to quarantine before overwriting it.
    save_local: bool,
    /// Set when the fetch exists only to preserve the peer's side of a conflict.
    conflict: Option<Conflict>,
}

pub struct Session<'a> {
    role: Role,
    pub settings: Settings,
    store: &'a mut Store,
    state: &'a mut State,

    out: Vec<Msg>,
    events: Vec<Event>,
    stats: Stats,

    /// Set once `Hello`/`Welcome` have been exchanged.
    ready: bool,
    peer_root: Option<Root>,
    /// Directories asked for and not yet answered.
    outstanding: usize,
    /// Directories already asked for, so a peer cannot send us round in circles.
    dived: BTreeSet<String>,

    /// Paths announced and awaiting `Applied`/`Rejected`, with what the base
    /// becomes when they are accepted.
    announced: BTreeMap<String, PathState>,
    announce_queue: Vec<Change>,

    /// Content asked for and not yet landed.
    wanted: BTreeMap<String, Wanted>,
    want_queue: Vec<WantItem>,

    /// Content the peer asked for.
    send_queue: VecDeque<(String, Digest, Dest)>,
    active_send: Option<crate::store::Outgoing>,
    /// What `active_send` is, beyond the file itself.
    sending: Option<Sending>,
    incoming: BTreeMap<u32, Incoming>,
    /// Transfers refused at `FileStart`, whose data must be dropped rather than
    /// treated as an unknown transfer once per chunk.
    refused: BTreeSet<u32>,

    /// Paths already reported to the user this session. A path can pass through
    /// the merge several times — once in the descent, again when the peer
    /// announces its side of the same thing — and reporting it each time would
    /// bury one conflict, or one dry-run line, in six identical copies.
    reported: BTreeSet<String>,

    bye_sent: bool,
    peer_bye: bool,
    failed: Option<String>,
}

impl<'a> Session<'a> {
    pub fn new(role: Role, settings: Settings, store: &'a mut Store, state: &'a mut State) -> Self {
        Session {
            role,
            settings,
            store,
            state,
            out: Vec::new(),
            events: Vec::new(),
            stats: Stats::default(),
            ready: false,
            peer_root: None,
            outstanding: 0,
            dived: BTreeSet::new(),
            announced: BTreeMap::new(),
            announce_queue: Vec::new(),
            wanted: BTreeMap::new(),
            want_queue: Vec::new(),
            send_queue: VecDeque::new(),
            active_send: None,
            sending: None,
            incoming: BTreeMap::new(),
            refused: BTreeSet::new(),
            reported: BTreeSet::new(),
            bye_sent: false,
            peer_bye: false,
            failed: None,
        }
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn state(&self) -> &State {
        self.state
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

    /// Anything left to do on this side.
    pub fn busy(&self) -> bool {
        self.outstanding > 0
            // A dry run never sends its announcements, so they are never
            // acknowledged; counting them as work would keep the session open
            // for the stall timeout and then fail.
            || (!self.settings.dry_run && !self.announced.is_empty())
            || !self.announce_queue.is_empty()
            || !self.wanted.is_empty()
            || !self.want_queue.is_empty()
            || !self.send_queue.is_empty()
            || self.active_send.is_some()
            || !self.incoming.is_empty()
            || !self.out.is_empty()
    }

    /// The initiator's exit condition: our work is done and the peer says its
    /// work is done too.
    pub fn finished(&self) -> bool {
        self.failed.is_some() || (self.peer_bye && !self.busy())
    }

    /// Open the session. The initiator states the terms; the responder waits.
    pub fn open(&mut self) -> io::Result<()> {
        if self.role != Role::Initiator {
            return Ok(());
        }
        self.out.push(Msg::Hello {
            version: proto::VERSION,
            program: program_id(),
            max_size: self.settings.max_size,
            ignore: self.settings.ignore.to_lines(),
            policy: self.settings.policy,
            direction: self.settings.direction,
            dry_run: self.settings.dry_run,
            compress: self.settings.compress,
            watch: self.settings.watch,
        });
        Ok(())
    }

    // ---------------------------------------------------------------- messages

    pub fn handle(&mut self, msg: Msg) -> io::Result<()> {
        match msg {
            Msg::Hello {
                version,
                program,
                max_size,
                ignore,
                policy,
                direction,
                dry_run,
                compress,
                watch,
            } => self.on_hello(Terms {
                version,
                program,
                max_size,
                ignore,
                policy,
                direction,
                dry_run,
                compress,
                watch,
            })?,
            Msg::Welcome {
                version,
                program,
                own_ignore,
                root,
            } => self.on_welcome(version, program, own_ignore, root)?,
            Msg::Rescan => {
                let report = self.rescan()?;
                let root = self.local_root();
                self.note_scan(&report);
                self.out.push(Msg::Root(root));
            }
            Msg::Root(root) => self.on_peer_root(root)?,
            Msg::ListDir { path } => self.on_list_dir(&path),
            Msg::DirList {
                path,
                exists,
                digest,
                children,
            } => {
                self.outstanding = self.outstanding.saturating_sub(1);
                self.on_dir_list(&path, exists, digest, &children)?;
            }
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
            } => self.on_file_start(xfer, path, dest, digest, size, mode, mtime)?,
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
        self.maybe_bye();
        Ok(())
    }

    fn on_hello(&mut self, terms: Terms) -> io::Result<()> {
        let Terms {
            version,
            program,
            max_size,
            ignore,
            policy,
            direction,
            dry_run,
            compress,
            watch,
        } = terms;
        if version != proto::VERSION {
            let text = format!(
                "protocol {version} from {program}, but this is {}: install the same bisync on both ends",
                proto::VERSION
            );
            self.out.push(Msg::Error { text: text.clone() });
            self.failed = Some(text);
            return Ok(());
        }
        // The initiator's terms replace ours for the duration. Two ends
        // filtering or size-limiting differently would never agree on a tree
        // digest, and would trade metadata for as long as they stayed connected.
        let mine = self.settings.ignore.digest();
        let theirs = IgnoreSet::new(&ignore);
        if mine != theirs.digest() {
            self.events.push(Event::Warn(format!(
                "ignore rules differ from the peer's; using the peer's {} rules for this session",
                theirs.len()
            )));
            self.out.push(Msg::Note {
                level: Level::Warn,
                text: format!(
                    "the far end's own ignore rules differ from yours; yours ({} rules) are in force",
                    theirs.len()
                ),
            });
        }
        if max_size != self.settings.max_size {
            self.events.push(Event::Info(format!(
                "size limit for this session is {} (the peer's), not {}",
                util::format_size(max_size),
                util::format_size(self.settings.max_size)
            )));
        }
        if policy != self.settings.policy {
            self.events.push(Event::Info(format!(
                "conflict policy for this session is {} (the peer's), not {}",
                policy.name(),
                self.settings.policy.name()
            )));
        }
        if direction != Direction::Both {
            self.events.push(Event::Info(format!(
                "changes flow one way this session: {} from the peer's point of view",
                direction.inverted().name()
            )));
        }
        self.settings.ignore = theirs;
        self.settings.max_size = max_size;
        self.settings.policy = policy;
        // Mirrored: the initiator's `pull` is this end's `push`.
        self.settings.direction = direction.inverted();
        self.settings.dry_run = dry_run;
        self.settings.compress = compress;
        self.settings.watch = watch;
        self.ready = true;

        let report = self.rescan()?;
        self.note_scan(&report);
        let root = self.local_root();
        self.out.push(Msg::Welcome {
            version: proto::VERSION,
            program: program_id(),
            own_ignore: mine,
            root,
        });
        // Whatever changed here while we were not connected.
        self.queue_local_changes();
        Ok(())
    }

    fn on_welcome(
        &mut self,
        version: u32,
        program: String,
        own_ignore: Digest,
        root: Root,
    ) -> io::Result<()> {
        if version != proto::VERSION {
            let text = format!("peer speaks protocol {version}, this is {}", proto::VERSION);
            self.failed = Some(format!("{text} ({program})"));
            return Ok(());
        }
        if own_ignore != self.settings.ignore.digest() {
            self.events.push(Event::Warn(
                "the peer's configured ignore rules differ from yours; yours are in force"
                    .to_string(),
            ));
        }
        self.ready = true;
        // Announce before descending: for the common case of a few edits since
        // the last sync this gets transfers moving a round trip earlier, and the
        // descent then skips those paths because they are already announced.
        self.queue_local_changes();
        self.on_peer_root(root)
    }

    fn on_peer_root(&mut self, root: Root) -> io::Result<()> {
        let local = self.state.index.root_digest();
        self.peer_root = Some(root.clone());
        if root.oversize > 0 {
            self.events.push(Event::Info(format!(
                "peer is skipping {} over the {} limit ({} in total)",
                util::plural(root.oversize as usize, "file"),
                util::format_size(self.settings.max_size),
                util::format_size(root.oversize_bytes)
            )));
        }
        if root.digest == local {
            self.converged();
            // Say so, so the far side can settle its own base and release its
            // own frozen paths. Only the initiator compares roots, so without
            // this a conflict resolved here would clear here and stay frozen
            // there — each end waiting for the other to mention it.
            if self.role == Role::Initiator {
                let mine = self.local_root();
                self.out.push(Msg::Root(mine));
            }
            return Ok(());
        }
        self.events.push(Event::Info(format!(
            "trees differ (here {}, peer {}); descending",
            local.short(),
            root.digest.short()
        )));
        if self.role == Role::Initiator {
            self.dive("");
        }
        Ok(())
    }

    /// The two trees are identical.
    ///
    /// Worth its own function because of what it settles: every path is in the
    /// state both sides agree on, so the base can be set from the index wholesale
    /// — and any conflict on record is, by definition, no longer one.
    fn converged(&mut self) {
        let mut base = BTreeMap::new();
        for (path, entry) in self.state.index.iter() {
            base.insert(path.clone(), entry.state());
        }
        let resolved: Vec<String> = self.state.conflicts.keys().cloned().collect();
        if !self.settings.dry_run {
            self.state.base = base;
            self.state.conflicts.clear();
        }
        for path in resolved {
            self.events.push(Event::Info(format!(
                "{path}: conflict resolved, both sides now agree"
            )));
        }
        self.events.push(Event::Info(format!(
            "in sync at {} ({})",
            self.state.index.root_digest().short(),
            util::count(self.state.index.len(), "entry", "entries")
        )));
    }

    fn on_list_dir(&mut self, path: &str) {
        let children = self.state.index.children(path);
        let exists = path.is_empty() || self.state.index.dir_digest(path).is_some();
        let digest = self.state.index.dir_digest(path).unwrap_or_default();
        self.stats.dirs_listed += 1;
        self.out.push(Msg::DirList {
            path: path.to_string(),
            exists,
            digest,
            children,
        });
    }

    /// Ask the peer for a directory's children.
    fn dive(&mut self, path: &str) {
        if relpath::depth(path) > MAX_DEPTH || !self.dived.insert(path.to_string()) {
            return;
        }
        self.outstanding += 1;
        self.out.push(Msg::ListDir {
            path: path.to_string(),
        });
    }

    /// Compare one directory level and act on every child that differs.
    fn on_dir_list(
        &mut self,
        dir: &str,
        exists: bool,
        _digest: Digest,
        children: &[crate::tree::Child],
    ) -> io::Result<()> {
        if !exists && !children.is_empty() {
            self.events.push(Event::Warn(format!(
                "peer listed children for {dir:?}, which it says is absent"
            )));
        }
        let remote: BTreeMap<&str, &crate::tree::Child> =
            children.iter().map(|c| (c.name.as_str(), c)).collect();
        let local = self.state.index.children(dir);
        let mut names: BTreeSet<&str> = remote.keys().copied().collect();
        for child in &local {
            names.insert(child.name.as_str());
        }
        let local_by_name: BTreeMap<&str, &crate::tree::Child> =
            local.iter().map(|c| (c.name.as_str(), c)).collect();
        let mut settled: Vec<String> = Vec::new();

        for name in names {
            let rel = if dir.is_empty() {
                name.to_string()
            } else {
                format!("{dir}/{name}")
            };
            let here = local_by_name.get(name);
            let there = remote.get(name);

            // Both directories: one digest comparison settles the entire
            // subtree. This is the line that makes the descent worth having.
            if let (Some(h), Some(t)) = (here, there) {
                if h.kind == Kind::Dir && t.kind == Kind::Dir {
                    if h.digest == t.digest {
                        self.adopt_subtree(&rel);
                    } else {
                        if !self.settings.dry_run {
                            self.state.set_base(&rel, PathState::Dir);
                        }
                        self.dive(&rel);
                    }
                    continue;
                }
            }

            let local_state = here.map(|c| child_state(c)).unwrap_or_default();
            let remote_state = there.map(|c| child_state(c)).unwrap_or_default();
            let remote_mtime = there.map(|c| c.mtime).unwrap_or_default();
            // Only acknowledgements are reported back from a descent. A
            // rejection here would be an answer to a question the peer never
            // asked, and `Reject::Conflict` in particular would have it freeze a
            // path on the strength of it; a genuine conflict is communicated by
            // announcing our version, which `hold` does.
            if let Outcome::Applied =
                self.decide(&rel, local_state, remote_state, None, remote_mtime)?
            {
                settled.push(rel.clone());
            }

            // A directory the peer has and we do not: its contents are still
            // unknown, so keep walking once it exists here.
            if there.is_some_and(|c| c.kind == Kind::Dir) && here.is_none() {
                self.dive(&rel);
            }
        }
        if !settled.is_empty() {
            self.out.push(Msg::Applied { paths: settled });
        }
        Ok(())
    }

    /// Record that a whole subtree already matches: base from index, conflicts
    /// on it settled, and the peer told so its own base can move with ours.
    fn adopt_subtree(&mut self, dir: &str) {
        if self.settings.dry_run {
            return;
        }
        let mut updates: Vec<(String, PathState)> = Vec::new();
        for (path, entry) in self.state.index.range_under(dir) {
            updates.push((path.clone(), entry.state()));
        }
        updates.push((dir.to_string(), PathState::Dir));
        let mut settled = Vec::with_capacity(updates.len());
        for (path, state) in updates {
            self.state.conflicts.remove(&path);
            self.state.set_base(&path, state);
            settled.push(path);
        }
        self.out.push(Msg::Applied { paths: settled });
    }

    // -------------------------------------------------------------- decisions

    /// Decide one path and act on it.
    ///
    /// `from` is the peer's own base when it announced the change, and `None`
    /// during a descent — a descent produces no such claim, so the merge falls
    /// back to our base for both roles, which is the plain three-way case.
    fn decide(
        &mut self,
        rel: &str,
        local: PathState,
        remote: PathState,
        from: Option<PathState>,
        remote_mtime: Stamp,
    ) -> io::Result<Outcome> {
        if let Some(rule) = self
            .settings
            .ignore
            .explain(rel, remote.kind() == Some(Kind::Dir))
        {
            // Both ends run the initiator's rules, so this means the peer's
            // scan predates a rule change. Nothing to do but say so.
            if !remote.is_absent() {
                self.events.push(Event::Change {
                    verb: "skip",
                    path: rel.to_string(),
                    detail: format!("ignored by {rule:?}"),
                });
            }
            return Ok(Outcome::Rejected(Reject::Ignored, rule.to_string()));
        }
        if let PathState::File { size, .. } = &remote {
            if *size > self.settings.max_size {
                self.events.push(Event::Change {
                    verb: "skip",
                    path: rel.to_string(),
                    detail: format!("{} is over the limit", util::format_size(*size)),
                });
                return Ok(Outcome::Rejected(
                    Reject::TooLarge,
                    format!(
                        "{} > {}",
                        util::format_size(*size),
                        util::format_size(self.settings.max_size)
                    ),
                ));
            }
        }

        let base = self.state.base_of(rel);
        let from = from.unwrap_or_else(|| base.clone());

        // A contested directory freezes its contents. Without this, a path whose
        // parent is a file here and a directory on the peer would be applied
        // into something that is not a directory — and more importantly, the
        // decision about the parent has not been made yet, so no decision about
        // what is inside it can be right.
        if let Some(held) = relpath::ancestors(rel)
            .iter()
            .find(|a| self.state.is_held(a))
        {
            return Ok(Outcome::Rejected(
                Reject::Held,
                format!("{held} is in conflict"),
            ));
        }

        // A path already in conflict stays frozen — but only against the same
        // two versions, and only against a peer that has not resolved it.
        //
        // The exception is what makes `bisync resolve` work at all. Resolving in
        // favour of the local copy rewinds the base to the peer's version, so
        // the next announcement arrives here with `from` equal to what we are
        // holding: the peer has seen our version and deliberately moved past it.
        // Refusing that would freeze both ends permanently, each waiting for the
        // other to give way.
        let resolved_by_peer = from == local && !from.is_absent();
        if !resolved_by_peer {
            if let Some(record) = self.state.conflicts.get(rel) {
                if record.remote == remote && record.local == local && local != remote {
                    return Ok(Outcome::Rejected(
                        Reject::Held,
                        record.kind.describe().to_string(),
                    ));
                }
            }
        }
        let decision = merge::resolve(&base, &local, &remote, &from);
        let local_mtime = self
            .state
            .index
            .get(rel)
            .map(|e| e.mtime)
            .unwrap_or_default();
        // `local` and `remote` name the two ends of the link, so the responder
        // applies the mirror image of what the initiator asked for. See
        // [`Policy::inverted`].
        let policy = match self.role {
            Role::Initiator => self.settings.policy,
            Role::Responder => self.settings.policy.inverted(),
        };
        let decision = merge::under_policy(decision, policy, local_mtime, remote_mtime);

        // A one-way session still works out what every path's situation is — the
        // base must not advance for something it declined to act on, or a later
        // full sync would think the two ends had agreed about it — and then
        // declines to act on half of them.
        match decision {
            Decision::Take { .. } if !self.settings.direction.may_take() => {
                if self.reported.insert(rel.to_string()) {
                    self.stats.declined += 1;
                    self.events.push(Event::Change {
                        verb: "skip",
                        path: rel.to_string(),
                        detail: format!(
                            "would take {}, but this session only pushes",
                            remote.describe()
                        ),
                    });
                }
                return Ok(Outcome::Rejected(Reject::Direction, "not taking".into()));
            }
            Decision::Keep if !self.settings.direction.may_offer() => {
                if self.reported.insert(rel.to_string()) {
                    self.stats.declined += 1;
                    self.events.push(Event::Change {
                        verb: "skip",
                        path: rel.to_string(),
                        detail: format!(
                            "could offer {}, but this session only pulls",
                            local.describe()
                        ),
                    });
                }
                return Ok(Outcome::Rejected(Reject::Direction, "not offering".into()));
            }
            _ => {}
        }
        self.act(rel, local, remote, decision, remote_mtime)
    }

    fn act(
        &mut self,
        rel: &str,
        local: PathState,
        remote: PathState,
        decision: Decision,
        remote_mtime: Stamp,
    ) -> io::Result<Outcome> {
        match decision {
            Decision::Converged => {
                if !self.settings.dry_run {
                    self.state.set_base(rel, remote);
                    if self.state.conflicts.remove(rel).is_some() {
                        self.events.push(Event::Info(format!(
                            "{rel}: conflict resolved, both sides now agree"
                        )));
                    }
                }
                Ok(Outcome::Applied)
            }
            Decision::Keep => {
                self.queue_announce(rel, &local);
                Ok(Outcome::Rejected(Reject::HaveNewer, local.describe()))
            }
            Decision::Take { save_local } => {
                self.take(rel, local, remote, remote_mtime, save_local)
            }
            Decision::Hold(kind) => self.hold(rel, local, remote, kind),
        }
    }

    /// Adopt the peer's version of a path.
    fn take(
        &mut self,
        rel: &str,
        local: PathState,
        remote: PathState,
        remote_mtime: Stamp,
        save_local: bool,
    ) -> io::Result<Outcome> {
        if self.settings.dry_run {
            // With `--diff`, a file that would be overwritten is fetched and
            // compared rather than merely announced. Only when there is something
            // here to compare against: a file arriving for the first time has no
            // diff, just a size.
            let both_files = matches!(
                (&local, &remote),
                (PathState::File { .. }, PathState::File { .. })
            );
            if self.settings.diff && both_files {
                if let PathState::File { digest, .. } = &remote {
                    self.request(
                        rel,
                        local.clone(),
                        remote.clone(),
                        *digest,
                        Dest::Inspect,
                        false,
                        None,
                    );
                    return Ok(Outcome::Pending);
                }
            }
            if self.reported.insert(rel.to_string()) {
                self.events.push(Event::Change {
                    verb: "would",
                    path: rel.to_string(),
                    detail: format!("take peer's {}", remote.describe()),
                });
            }
            // Held rather than Applied: an acknowledgement would have the peer
            // advance its base for a change that did not happen, and a later real
            // sync would then never offer it again.
            return Ok(Outcome::Rejected(Reject::Held, "dry run".into()));
        }
        // A directory going away, or being replaced by a file, means everything
        // inside it goes too — and each of those has to be dealt with, and
        // guarded, before the directory itself can be.
        if local == PathState::Dir && remote != PathState::Dir {
            self.drop_subtree(rel)?;
        }

        match &remote {
            PathState::Absent => match self.store.remove(rel, &local)? {
                Guarded::Applied { kept } => {
                    self.state.index.remove(rel);
                    self.state.index.remove_subtree(rel);
                    self.state.set_base(rel, PathState::Absent);
                    self.state.index.recompute();
                    self.stats.deleted += 1;
                    self.stats.kept += kept.is_some() as usize;
                    self.events.push(Event::Change {
                        verb: "del",
                        path: rel.to_string(),
                        detail: describe_kept(&kept),
                    });
                    Ok(Outcome::Applied)
                }
                Guarded::Changed(actual) => self.changed_under_us(rel, local, remote, actual),
                Guarded::Refused(why) => {
                    self.events
                        .push(Event::Warn(format!("{rel}: not deleted: {why}")));
                    Ok(Outcome::Rejected(Reject::Failed, why))
                }
            },
            PathState::Dir => {
                // A file where the peer has a directory: the file goes first,
                // guarded by what we decided about, or `mkdir` would simply
                // report that something is in the way.
                if matches!(local, PathState::File { .. } | PathState::Symlink { .. }) {
                    match self.store.remove(rel, &local)? {
                        Guarded::Applied { kept } => {
                            self.note_kept(&kept);
                            self.state.index.remove(rel);
                        }
                        Guarded::Changed(actual) => {
                            return self.changed_under_us(rel, local, remote, actual);
                        }
                        Guarded::Refused(why) => {
                            return Ok(Outcome::Rejected(Reject::Failed, why));
                        }
                    }
                }
                match self.store.make_dir(rel, 0o755)? {
                    Guarded::Applied { .. } => {
                        self.state.index.insert(rel.to_string(), Entry::dir(0o755));
                        self.state.set_base(rel, PathState::Dir);
                        self.state.index.recompute();
                        self.stats.created += 1;
                        self.events.push(Event::Change {
                            verb: "mkdir",
                            path: rel.to_string(),
                            detail: String::new(),
                        });
                        Ok(Outcome::Applied)
                    }
                    Guarded::Changed(actual) => self.changed_under_us(rel, local, remote, actual),
                    Guarded::Refused(why) => Ok(Outcome::Rejected(Reject::Failed, why)),
                }
            }
            PathState::Symlink { target } => match self.store.set_symlink(rel, target, &local)? {
                Guarded::Applied { kept } => {
                    self.note_kept(&kept);
                    let digest = crate::hash::symlink_digest(target.as_bytes());
                    self.state
                        .index
                        .insert(rel.to_string(), Entry::symlink(digest, target.clone()));
                    self.state.set_base(rel, remote.clone());
                    self.state.index.recompute();
                    self.events.push(Event::Change {
                        verb: "link",
                        path: rel.to_string(),
                        detail: format!("-> {target}"),
                    });
                    Ok(Outcome::Applied)
                }
                Guarded::Changed(actual) => self.changed_under_us(rel, local, remote, actual),
                Guarded::Refused(why) => Ok(Outcome::Rejected(Reject::Failed, why)),
            },
            PathState::File { digest, size, mode } => {
                // Same bytes, different permissions: there is nothing to
                // transfer, and asking for a megabyte to change one octal digit
                // would be absurd.
                if let PathState::File {
                    digest: local_digest,
                    ..
                } = &local
                {
                    if local_digest == digest {
                        self.store.set_mode(rel, *mode)?;
                        if let Some(entry) = self.state.index.get_mut(rel) {
                            entry.mode = *mode;
                        }
                        self.state.set_base(rel, remote.clone());
                        self.events.push(Event::Change {
                            verb: "chmod",
                            path: rel.to_string(),
                            detail: format!("{mode:04o}"),
                        });
                        return Ok(Outcome::Applied);
                    }
                }
                let _ = size;
                self.request(
                    rel,
                    local,
                    remote.clone(),
                    *digest,
                    Dest::Live,
                    save_local,
                    None,
                );
                let _ = remote_mtime;
                Ok(Outcome::Pending)
            }
        }
    }

    /// Freeze a path both sides changed, and fetch the peer's version to sit
    /// beside ours rather than on top of it.
    fn hold(
        &mut self,
        rel: &str,
        local: PathState,
        remote: PathState,
        kind: Conflict,
    ) -> io::Result<Outcome> {
        if self.settings.dry_run {
            if self.reported.insert(rel.to_string()) {
                self.events.push(Event::Conflict {
                    path: rel.to_string(),
                    kind,
                    quarantine: None,
                });
            }
            return Ok(Outcome::Rejected(
                Reject::Conflict,
                kind.describe().to_string(),
            ));
        }
        let fresh = !self.state.conflicts.contains_key(rel);
        self.state.conflicts.insert(
            rel.to_string(),
            ConflictRecord {
                kind,
                detected: util::now(),
                local: local.clone(),
                remote: remote.clone(),
                quarantine: String::new(),
            },
        );
        if fresh {
            self.stats.conflicts += 1;
            let _ = self.store.log_conflict(&format!(
                "{} {rel}: {} (here {}, peer {})",
                util::format_utc(util::now()),
                kind.describe(),
                local.describe(),
                remote.describe()
            ));
        }
        if self.reported.insert(rel.to_string()) {
            self.events.push(Event::Conflict {
                path: rel.to_string(),
                kind,
                quarantine: None,
            });
        }
        // Ask for their copy, to land in quarantine. Nothing in the tree moves;
        // where the copy ended up is reported when it arrives.
        if let PathState::File { digest, .. } = &remote {
            self.request(
                rel,
                local.clone(),
                remote.clone(),
                *digest,
                Dest::Quarantine,
                false,
                Some(kind),
            );
        }
        // Tell them our version too, so the conflict is visible from both ends
        // rather than only from whichever side happened to notice it.
        self.queue_announce(rel, &local);
        Ok(Outcome::Rejected(
            Reject::Conflict,
            kind.describe().to_string(),
        ))
    }

    /// The path is not what we decided about. Not an error — someone is working
    /// in the directory — but the decision is void, so re-derive it from what is
    /// actually there.
    fn changed_under_us(
        &mut self,
        rel: &str,
        _local: PathState,
        remote: PathState,
        actual: PathState,
    ) -> io::Result<Outcome> {
        self.events.push(Event::Warn(format!(
            "{rel}: changed here while syncing ({}), leaving it alone",
            actual.describe()
        )));
        self.refresh_index_entry(rel)?;
        self.hold(rel, actual, remote, Conflict::BothEdited)
    }

    /// Queue a request for content.
    #[allow(clippy::too_many_arguments)]
    fn request(
        &mut self,
        rel: &str,
        expected: PathState,
        target: PathState,
        digest: Digest,
        dest: Dest,
        save_local: bool,
        conflict: Option<Conflict>,
    ) {
        // A dry run transfers nothing — except an `Inspect` fetch, which exists
        // precisely to have the real content to compare against and puts it
        // nowhere.
        if self.settings.dry_run && dest != Dest::Inspect {
            return;
        }
        // One request per path at a time. A second would race the first into the
        // same destination.
        if self.wanted.contains_key(rel) {
            return;
        }
        self.wanted.insert(
            rel.to_string(),
            Wanted {
                expected,
                target,
                digest,
                dest,
                save_local,
                conflict,
            },
        );
        self.want_queue.push(WantItem {
            path: rel.to_string(),
            digest,
            dest,
        });
    }

    /// Delete everything under a directory, deepest first, each with its own
    /// guard. A child that has been changed here is held rather than removed,
    /// and the directory then stays because it is not empty — which is the right
    /// outcome, and reported as such.
    fn drop_subtree(&mut self, dir: &str) -> io::Result<()> {
        let mut victims: Vec<(String, PathState)> = self
            .state
            .index
            .range_under(dir)
            .map(|(path, entry)| (path.clone(), entry.state()))
            .collect();
        victims.sort_by(|a, b| b.0.cmp(&a.0));
        for (path, expected) in victims {
            let base = self.state.base_of(&path);
            if base != expected {
                // Not agreed with the peer: an edit here that the deletion would
                // destroy. Hold it and leave it in place.
                self.hold(
                    &path,
                    expected,
                    PathState::Absent,
                    Conflict::EditedHereDeletedThere,
                )?;
                continue;
            }
            match self.store.remove(&path, &expected)? {
                Guarded::Applied { kept } => {
                    self.state.index.remove(&path);
                    self.state.set_base(&path, PathState::Absent);
                    self.stats.deleted += 1;
                    self.stats.kept += kept.is_some() as usize;
                    self.events.push(Event::Change {
                        verb: "del",
                        path: path.clone(),
                        detail: describe_kept(&kept),
                    });
                }
                Guarded::Changed(actual) => {
                    self.changed_under_us(&path, expected, PathState::Absent, actual)?;
                }
                Guarded::Refused(why) => {
                    self.events
                        .push(Event::Warn(format!("{path}: not deleted: {why}")));
                }
            }
        }
        self.state.index.recompute();
        Ok(())
    }

    // ------------------------------------------------------------- announcing

    /// Announce everything that has changed here since the last agreement.
    ///
    /// Does nothing when there is no agreement to have changed from. On a first
    /// sync every path would qualify, and announcing an entire tree is precisely
    /// what the descent exists to avoid; the descent finds the same differences
    /// at a cost proportional to what actually differs.
    pub fn queue_local_changes(&mut self) {
        if self.state.base.is_empty() {
            return;
        }
        let changes = self.state.changes_vs_base();
        for change in changes {
            if self.wanted.contains_key(&change.path) {
                continue;
            }
            // Through `offer`, which is where the dry-run and direction checks
            // live. Pushing to the queue directly — as this once did — announced
            // changes that a dry run had promised not to make.
            self.offer(&change.path, change.to, change.mtime);
        }
    }

    fn queue_announce(&mut self, rel: &str, local: &PathState) {
        let mtime = self
            .state
            .index
            .get(rel)
            .map(|e| e.mtime)
            .unwrap_or_default();
        if !self.offer(rel, local.clone(), mtime) {
            return;
        }
        // A new directory is worthless to the peer on its own; everything in it
        // has to be offered too, or the peer creates an empty directory and
        // waits for a descent to find the contents.
        if *local == PathState::Dir {
            let subtree: Vec<(String, PathState, Stamp)> = self
                .state
                .index
                .range_under(rel)
                .map(|(path, entry)| (path.clone(), entry.state(), entry.mtime))
                .collect();
            for (path, state, mtime) in subtree {
                if self.state.is_held(&path) {
                    continue;
                }
                self.offer(&path, state, mtime);
            }
        }
    }

    /// Offer one path to the peer, or report that we would. Returns false if it
    /// was already offered this session — one announcement per path is enough,
    /// and a second would race the first.
    fn offer(&mut self, rel: &str, to: PathState, mtime: Stamp) -> bool {
        if self.announced.contains_key(rel) {
            return false;
        }
        if !self.settings.direction.may_offer() {
            // Deliberately *not* recorded in `announced`: that map is what the
            // session is still waiting to hear about, and a path nobody will ever
            // acknowledge would leave it busy forever. `reported` keeps the line
            // from being printed twice instead.
            if self.reported.insert(rel.to_string()) {
                self.stats.declined += 1;
                self.events.push(Event::Change {
                    verb: "skip",
                    path: rel.to_string(),
                    detail: format!("could offer {}, but this session only pulls", to.describe()),
                });
            }
            return false;
        }
        if self.settings.dry_run {
            self.events.push(Event::Change {
                verb: "would",
                path: rel.to_string(),
                detail: if to.is_absent() {
                    "delete on the peer".to_string()
                } else {
                    format!("send {}", to.describe())
                },
            });
            // Recorded even in a dry run, so the same path is not reported twice
            // by two different code paths reaching the same conclusion.
            self.announced.insert(rel.to_string(), to);
            return true;
        }
        self.announce_queue.push(Change {
            path: rel.to_string(),
            from: self.state.base_of(rel),
            to: to.clone(),
            mtime,
        });
        self.announced.insert(rel.to_string(), to);
        true
    }

    fn on_announce(&mut self, changes: Vec<Change>) -> io::Result<()> {
        // Creations parents-first, deletions children-first. Anything else and a
        // directory arrives before it exists, or refuses to go because something
        // inside it is still there.
        let (mut adds, mut dels): (Vec<Change>, Vec<Change>) =
            changes.into_iter().partition(|c| !c.to.is_absent());
        adds.sort_by(|a, b| a.path.cmp(&b.path));
        dels.sort_by(|a, b| b.path.cmp(&a.path));

        let mut applied = Vec::new();
        let mut rejected = Vec::new();
        for change in adds.into_iter().chain(dels) {
            let local = self.state.index.state(&change.path);
            match self.decide(
                &change.path,
                local,
                change.to,
                Some(change.from),
                change.mtime,
            )? {
                Outcome::Applied => applied.push(change.path),
                Outcome::Pending => {}
                Outcome::Rejected(reason, detail) => rejected.push((change.path, reason, detail)),
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

    /// The peer's state for these paths now matches ours, so the base moves up.
    ///
    /// Not only for paths we announced. A peer that pulled a file by `Want`, or
    /// that a descent found already in agreement with us, says so this way too —
    /// and without acting on that, the side that was pulled *from* would keep a
    /// base of "we have never agreed about this" and offer the path again on
    /// every future connection.
    fn on_applied(&mut self, paths: &[String]) {
        if self.settings.dry_run {
            return;
        }
        for path in paths {
            let state = match self.announced.remove(path) {
                Some(state) => {
                    self.stats.pushed += 1;
                    state
                }
                // What the peer is agreeing to is what we have.
                None => self.state.index.state(path),
            };
            self.state.set_base(path, state);
            self.state.conflicts.remove(path);
        }
    }

    fn on_rejected(&mut self, items: Vec<(String, Reject, String)>) {
        for (path, reason, detail) in items {
            self.announced.remove(&path);
            match reason {
                // The peer will announce its own version; nothing to do but wait.
                Reject::HaveNewer | Reject::Held => {}
                Reject::Conflict => {
                    // The peer has frozen the path. Freeze it here too, so we
                    // stop offering it; its version reaches our quarantine when
                    // it announces, or on the next descent.
                    if !self.state.conflicts.contains_key(&path) && !self.settings.dry_run {
                        let local = self.state.index.state(&path);
                        self.state.conflicts.insert(
                            path.clone(),
                            ConflictRecord {
                                kind: Conflict::BothEdited,
                                detected: util::now(),
                                local,
                                remote: PathState::Absent,
                                quarantine: String::new(),
                            },
                        );
                        self.stats.conflicts += 1;
                    }
                    if self.reported.insert(path.clone()) {
                        self.events.push(Event::Conflict {
                            path,
                            kind: Conflict::BothEdited,
                            quarantine: None,
                        });
                    }
                }
                // The peer is not taking anything this session. Not a problem
                // and not a conflict; the base stays where it was.
                Reject::Direction => {
                    self.stats.declined += 1;
                }
                Reject::Ignored | Reject::TooLarge | Reject::Failed => {
                    self.events.push(Event::Change {
                        verb: "skip",
                        path,
                        detail: format!("{}: {detail}", reason.describe()),
                    });
                }
            }
        }
    }

    // -------------------------------------------------------------- transfers

    fn on_want(&mut self, items: Vec<WantItem>) {
        let mut rejected = Vec::new();
        for item in items {
            if let Some(rule) = self.settings.ignore.explain(&item.path, false) {
                rejected.push((item.path, Reject::Ignored, rule.to_string()));
                continue;
            }
            match self.state.index.get(&item.path) {
                Some(entry) if entry.kind == Kind::File && entry.digest == item.digest => {
                    if entry.size > self.settings.max_size {
                        rejected.push((item.path, Reject::TooLarge, util::format_size(entry.size)));
                        continue;
                    }
                    self.send_queue
                        .push_back((item.path, item.digest, item.dest));
                }
                // The file moved on since we announced it. Saying so is better
                // than sending different bytes under the old digest.
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

    /// Push transfers along by one chunk.
    ///
    /// Returns whether there is more to do. One chunk per call, so the caller
    /// keeps control and can interleave reads from the peer instead of going
    /// deaf for the length of a file.
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
                        self.events.push(Event::Change {
                            verb: "send",
                            path,
                            detail: describe_transfer(sending.tally),
                        });
                    }
                    // The file changed under us mid-read. Withdraw it rather
                    // than deliver bytes the announced digest does not cover;
                    // the next scan sees the new content and announces that.
                    Err(mismatch) => {
                        let reason = mismatch.to_string();
                        self.out.push(Msg::FileAbort {
                            xfer,
                            reason: reason.clone(),
                        });
                        self.events.push(Event::Warn(reason));
                    }
                }
            }
            Ok(n) => {
                // Deflate the chunk, and keep the result only if it is smaller.
                // Whichever wins, the frame says which it is, so the two ends
                // never have to agree about it beforehand.
                let squeezed = if sending.compress && self.settings.compress > 0 {
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
                self.out.push(Msg::FileAbort {
                    xfer,
                    reason: e.to_string(),
                });
                self.events
                    .push(Event::Warn(format!("{}: {e}", outgoing.path)));
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
    ) -> io::Result<()> {
        // Only content we asked for, at the digest we asked for, is accepted.
        // Without this a peer could write anywhere in the tree by announcing
        // nothing and simply starting to send.
        let ok = self
            .wanted
            .get(&path)
            .is_some_and(|w| w.digest == digest && w.dest == dest);
        if !ok {
            self.refused.insert(xfer);
            self.out.push(Msg::Rejected {
                items: vec![(path, Reject::Failed, "not requested".to_string())],
            });
            return Ok(());
        }
        if size > self.settings.max_size {
            self.refused.insert(xfer);
            self.wanted.remove(&path);
            self.out.push(Msg::Rejected {
                items: vec![(path, Reject::TooLarge, util::format_size(size))],
            });
            return Ok(());
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
        Ok(())
    }

    fn on_file_data(&mut self, xfer: u32, encoding: Encoding, plain_len: u32, data: &[u8]) {
        if self.refused.contains(&xfer) {
            return;
        }
        if !self.incoming.contains_key(&xfer) {
            self.refused.insert(xfer);
            return;
        }
        // Decoded before anything else touches it, so everything downstream —
        // the digest, the size guard, the temporary file — sees content and does
        // not have to know compression exists.
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
                self.events.push(Event::Warn(format!("{path}: {e}")));
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
        // Captured before `seal` consumes the transfer, for the `recv` line.
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
            Err(Guarded::Refused(why)) => {
                // The bytes do not hash to what was promised. Nothing was
                // written outside `.bisync/tmp`, and that has been removed.
                self.events.push(Event::Warn(why.clone()));
                self.out.push(Msg::Rejected {
                    items: vec![(path, Reject::Failed, why)],
                });
                return Ok(());
            }
            Err(_) => unreachable!("seal returns only Refused"),
        };

        if want.dest == Dest::Inspect {
            let incoming = self.store.read_sealed(&sealed)?;
            self.store.discard_sealed(sealed);
            let current =
                std::fs::read(crate::relpath::join(self.store.root(), &path)).unwrap_or_default();
            let change = diff::compare(&current, &incoming, 3);
            self.events.push(Event::Diff {
                path: path.clone(),
                was: current.len() as u64,
                becomes: incoming.len() as u64,
                change,
            });
            // Nothing was applied and nothing is expected of the peer, but it is
            // waiting to hear; a dry run must not leave it holding the path open.
            self.out.push(Msg::Rejected {
                items: vec![(path, Reject::Failed, "dry run".to_string())],
            });
            return Ok(());
        }

        if want.dest == Dest::Quarantine {
            let kind = want.conflict.unwrap_or(Conflict::BothEdited);
            let size = sealed.size;
            let at = self.store.place_aside(sealed)?;
            if let Some(record) = self.state.conflicts.get_mut(&path) {
                record.quarantine = at.clone();
            }
            self.stats.quarantined += 1;
            self.events.push(Event::Change {
                verb: "kept",
                path: path.clone(),
                detail: format!("peer's version at {at}, {}", util::format_size(size)),
            });
            self.out.push(Msg::Rejected {
                items: vec![(path, Reject::Conflict, kind.describe().to_string())],
            });
            return Ok(());
        }

        match self.store.place(sealed, &want.expected)? {
            Placement::Done(landed) => {
                let entry = Entry {
                    kind: Kind::File,
                    digest: landed.digest,
                    size: landed.size,
                    mode: landed.mode,
                    mtime: landed.mtime,
                    ino: 0,
                    target: String::new(),
                };
                self.state.index.insert(path.clone(), entry);
                self.state.index.recompute();
                self.state.set_base(&path, want.target);
                self.state.conflicts.remove(&path);
                self.stats.received += 1;
                self.stats.received_bytes += landed.size;
                // `place` preserved whatever it overwrote; all that is left is to
                // say so.
                if let Some(at) = &landed.kept {
                    self.stats.kept += 1;
                    if want.save_local {
                        // Not merely an overwrite: a local change the peer never
                        // saw is being discarded. Worth saying out loud.
                        self.events.push(Event::Warn(format!(
                            "{path}: local version replaced by the peer's, kept at {at}"
                        )));
                    } else {
                        self.events.push(Event::Info(format!(
                            "{path}: previous version kept at {at}"
                        )));
                    }
                }
                self.events.push(Event::Change {
                    verb: "recv",
                    path: path.clone(),
                    detail: describe_transfer(arrived),
                });
                self.out.push(Msg::Applied { paths: vec![path] });
            }
            // Someone edited the destination while the transfer was running. The
            // peer's copy is intact and verified, so it goes to quarantine and
            // the path becomes a conflict — which is exactly what it is.
            Placement::Changed { actual, sealed } => {
                let at = self.store.place_aside(sealed)?;
                self.events.push(Event::Warn(format!(
                    "{path}: changed here during the transfer ({}); peer's copy kept at {at}",
                    actual.describe()
                )));
                self.refresh_index_entry(&path)?;
                let kind = Conflict::BothEdited;
                self.state.conflicts.insert(
                    path.clone(),
                    ConflictRecord {
                        kind,
                        detected: util::now(),
                        local: actual,
                        remote: want.target,
                        quarantine: at.clone(),
                    },
                );
                self.stats.conflicts += 1;
                if self.reported.insert(path.clone()) {
                    self.events.push(Event::Conflict {
                        path: path.clone(),
                        kind,
                        quarantine: Some(at),
                    });
                }
                self.out.push(Msg::Rejected {
                    items: vec![(path, Reject::Conflict, kind.describe().to_string())],
                });
            }
        }
        Ok(())
    }

    fn on_file_abort(&mut self, xfer: u32, reason: &str) {
        self.refused.remove(&xfer);
        if let Some(incoming) = self.incoming.remove(&xfer) {
            let path = incoming.path.clone();
            self.store.discard(incoming);
            self.wanted.remove(&path);
            self.events
                .push(Event::Warn(format!("{path}: peer withdrew it: {reason}")));
        }
    }

    // ------------------------------------------------------------------ local

    /// Rescan the whole tree.
    pub fn rescan(&mut self) -> io::Result<scan::ScanReport> {
        let report = scan::scan(
            self.store.root(),
            &self.settings.ignore,
            self.settings.max_size,
            Some(&self.state.index),
        )?;
        self.state.index = report.index.clone();
        Ok(report)
    }

    /// Rescan just the paths a watcher reported, then announce what moved.
    pub fn local_changed(&mut self, paths: &[String]) -> io::Result<()> {
        if paths.is_empty() {
            return Ok(());
        }
        let report = scan::refresh(
            self.store.root(),
            &self.settings.ignore,
            self.settings.max_size,
            &mut self.state.index,
            paths,
        )?;
        for warning in report.warnings() {
            self.events.push(Event::Warn(warning));
        }
        self.queue_local_changes();
        Ok(())
    }

    /// Re-read one path into the index, after finding the filesystem had moved.
    fn refresh_index_entry(&mut self, rel: &str) -> io::Result<()> {
        let paths = [rel.to_string()];
        scan::refresh(
            self.store.root(),
            &self.settings.ignore,
            self.settings.max_size,
            &mut self.state.index,
            &paths,
        )?;
        Ok(())
    }

    /// Count a version the store preserved, and mention where it went.
    ///
    /// For the operations whose report line has no room for it. The `del` and
    /// `recv` lines carry it themselves.
    fn note_kept(&mut self, kept: &Option<String>) {
        if let Some(at) = kept {
            self.stats.kept += 1;
            self.events
                .push(Event::Info(format!("previous version kept at {at}")));
        }
    }

    fn note_scan(&mut self, report: &scan::ScanReport) {
        self.events.push(Event::Info(report.summary()));
        for warning in report.warnings() {
            self.events.push(Event::Warn(warning));
        }
    }

    pub fn local_root(&self) -> Root {
        let index = &self.state.index;
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

    /// Say goodbye once there is nothing left to do — unless we are staying.
    fn maybe_bye(&mut self) {
        if self.settings.watch || self.bye_sent || !self.ready {
            return;
        }
        // The responder waits to be told; it has no way of knowing whether the
        // initiator is still descending.
        if self.role == Role::Responder && !self.peer_bye {
            return;
        }
        if self.busy() || !self.want_queue.is_empty() || !self.announce_queue.is_empty() {
            return;
        }
        self.out.push(Msg::Bye);
        self.bye_sent = true;
    }

    /// Called by the driver after every batch of work, to catch the case where
    /// the last thing that happened made the session idle.
    pub fn settle(&mut self) {
        self.maybe_bye();
    }
}

/// The transfer in progress on the sending side.
#[derive(Clone, Copy, Debug)]
struct Sending {
    /// Transfer id, so every chunk of one file is labelled consistently.
    xfer: u32,
    /// Whether to try compressing this file's chunks at all. Decided once, from
    /// the name, rather than per chunk: a video is a video all the way down, and
    /// the wasted pass over it is the expensive kind.
    compress: bool,
    /// This file's own plain-against-wire figures, for its `send` line.
    tally: Tally,
}

/// What handling one change came to, from the announcer's point of view.
enum Outcome {
    /// Settled; the peer may advance its base.
    Applied,
    /// A transfer was requested; the answer comes later.
    Pending,
    Rejected(Reject, String),
}

fn child_state(child: &crate::tree::Child) -> PathState {
    match child.kind {
        Kind::File => PathState::File {
            digest: child.digest,
            size: child.size,
            mode: child.mode,
        },
        Kind::Symlink => PathState::Symlink {
            target: child.target.clone(),
        },
        Kind::Dir => PathState::Dir,
    }
}

/// A `send` line's detail: the size, and what it cost on the wire when that
/// differs. `4.1K -> 1.2K` says more than `4.1K` and takes four more characters.
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

/// `kept at <path>`, for a report line with room for it, or nothing.
fn describe_kept(kept: &Option<String>) -> String {
    match kept {
        Some(at) => format!("kept at {at}"),
        None => String::new(),
    }
}

fn program_id() -> String {
    format!("bisync {}", env!("CARGO_PKG_VERSION"))
}
