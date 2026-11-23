//! What one side would have to do to look like the other.
//!
//! Two pieces, both pure: [`Survey`], which walks the two trees a directory at a
//! time and records where they disagree, and [`plan`], which turns those
//! disagreements into the ordered list of [`Step`]s one side would carry out.
//! Neither touches a filesystem or a socket — a `Survey` is fed directory
//! listings and hands back the names of more directories it wants — which is
//! what makes the whole comparison testable without a link.
//!
//! The walk is `bisync`'s Merkle descent with the bookkeeping removed. Two
//! directories whose digests agree are the same directory all the way down and
//! are never opened; everything else is followed one level at a time. What is
//! different here is what comes out of it: `bisync` compares each difference
//! against a remembered base to work out which side moved, and this has no base
//! to compare against. The sending side simply wins, and every case where that
//! would destroy something is put to the user instead.

use std::collections::BTreeSet;

use crate::merge::Direction;
use crate::relpath;
use crate::tree::{Child, Index, Kind, PathState, Stamp};
use crate::util::format_size;

/// How deep the descent will follow a peer, as in [`crate::session`]: far past
/// any real tree, so that a peer answering every listing with another directory
/// cannot keep us walking for ever.
const MAX_DEPTH: usize = 256;

/// Which way a run copies.
///
/// There is no `both`. Reconciling two directories in both directions at once
/// needs to know which side moved since they last agreed, which needs a
/// remembered base — and not keeping one is the whole point of this tool.
/// `bisync` is the one that keeps it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Way {
    /// The peer's tree is the one being copied; this side changes.
    Pull,
    /// This tree is the one being copied; the peer changes.
    Push,
}

impl Way {
    pub fn name(self) -> &'static str {
        match self {
            Way::Pull => "pull",
            Way::Push => "push",
        }
    }

    /// The same thing said as a session term, for the handshake. It names a way
    /// along the link rather than "away from me", so the far end mirrors it.
    pub fn direction(self) -> Direction {
        match self {
            Way::Pull => Direction::Pull,
            Way::Push => Direction::Push,
        }
    }

    /// The side that ends up doing the writing.
    pub fn receiver(self) -> &'static str {
        match self {
            Way::Pull => "here",
            Way::Push => "the peer",
        }
    }

    pub fn sender(self) -> &'static str {
        match self {
            Way::Pull => "the peer",
            Way::Push => "here",
        }
    }
}

/// One change to make on the receiving side.
///
/// `from` is what the receiving side had when the two trees were compared, and
/// it travels with the change as the guard: the side about to carry it out
/// re-reads the path first and refuses if it is no longer that. Nothing here is
/// a promise that the change is right — that is the user's to give — only that
/// it is being made about the thing it was proposed about.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Step {
    pub path: String,
    /// The receiving side's state, as seen during the comparison.
    pub from: PathState,
    /// The sending side's state, and what the path becomes.
    pub to: PathState,
    /// The sending side's modification time, restored along with the content.
    pub mtime: Stamp,
}

impl Step {
    /// A fixed short word, so a list of steps lines up in a column.
    pub fn verb(&self) -> &'static str {
        match (&self.from, &self.to) {
            (_, PathState::Absent) => "del",
            (PathState::Absent, PathState::Dir) => "mkdir",
            (_, PathState::Dir) => "replace",
            (_, PathState::Symlink { .. }) => "link",
            (PathState::Absent, PathState::File { .. }) => "new",
            (PathState::File { digest: here, .. }, PathState::File { digest: there, .. })
                if here == there =>
            {
                "chmod"
            }
            (PathState::File { .. }, PathState::File { .. }) => "update",
            (_, PathState::File { .. }) => "replace",
        }
    }

    /// The parenthesised half of a report line: what actually differs.
    pub fn detail(&self) -> String {
        match (&self.from, &self.to) {
            (
                PathState::File {
                    digest: here,
                    mode: was,
                    ..
                },
                PathState::File {
                    digest: there,
                    mode: now,
                    ..
                },
            ) if here == there => format!("{was:04o} -> {now:04o}"),
            (PathState::File { size: was, .. }, PathState::File { size: now, .. }) => {
                format!("{} -> {}", format_size(*was), format_size(*now))
            }
            (PathState::Absent, PathState::File { size, .. }) => format_size(*size),
            (from, PathState::File { size, .. }) => {
                format!("{} -> {}", brief(from), format_size(*size))
            }
            (_, PathState::Symlink { target }) => format!("-> {target}"),
            (PathState::Absent, PathState::Dir) => String::new(),
            (from, PathState::Dir) => format!("{} -> directory", brief(from)),
            (from, PathState::Absent) => brief(from),
        }
    }

    /// Does carrying this out mean transferring the file?
    ///
    /// A file whose bytes both sides already have and whose permissions differ
    /// does not: there is nothing to send, and asking for a megabyte to change
    /// one octal digit would be absurd.
    pub fn needs_content(&self) -> bool {
        match (&self.from, &self.to) {
            (PathState::File { digest: here, .. }, PathState::File { digest: there, .. }) => {
                here != there
            }
            (_, PathState::File { .. }) => true,
            _ => false,
        }
    }

    /// Would a diff of the two versions mean anything? Both sides have to have
    /// a file there — there is nothing to compare a new file against.
    pub fn is_diffable(&self) -> bool {
        matches!(
            (&self.from, &self.to),
            (PathState::File { .. }, PathState::File { .. })
        ) && self.needs_content()
    }

    /// The digest of the sending side's version, when it has one. What a fetch
    /// for a diff asks for.
    pub fn source_digest(&self) -> Option<crate::hash::Digest> {
        match &self.to {
            PathState::File { digest, .. } => Some(*digest),
            _ => None,
        }
    }

    pub fn is_delete(&self) -> bool {
        self.to.is_absent()
    }

    /// Does this take a directory — and therefore everything in it — away?
    fn drops_a_directory(&self) -> bool {
        matches!(self.from, PathState::Dir) && !matches!(self.to, PathState::Dir)
    }
}

/// A difference deliberately left out of the plan, and why. Reported rather than
/// dropped: a tool that says "3 changes" while quietly declining to mention
/// eleven more is worse than one that refuses to do anything at all.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Skip {
    pub path: String,
    pub why: String,
}

/// Everything one run would do, and everything it decided not to.
#[derive(Clone, Default, Debug)]
pub struct Plan {
    pub steps: Vec<Step>,
    pub skipped: Vec<Skip>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// How many steps of each verb, in the order the verbs are declared, for a
    /// one-line summary.
    pub fn tally(&self) -> Vec<(&'static str, usize)> {
        let mut out: Vec<(&'static str, usize)> = Vec::new();
        for step in &self.steps {
            let verb = step.verb();
            match out.iter_mut().find(|(v, _)| *v == verb) {
                Some((_, n)) => *n += 1,
                None => out.push((verb, 1)),
            }
        }
        out
    }
}

/// One path the two trees disagree about, as the comparison found it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Found {
    pub path: String,
    pub here: PathState,
    pub there: PathState,
    pub here_mtime: Stamp,
    pub there_mtime: Stamp,
}

/// The descent: compare two trees a directory at a time, without either side
/// enumerating itself at the other.
///
/// Drive it by taking the paths it wants listed, listing them at the peer, and
/// feeding each answer back. It is finished when it has no outstanding requests
/// and nothing queued, at which point [`Survey::into_found`] is the complete
/// symmetric difference of the two trees.
pub struct Survey {
    /// Follow directories the peer has and we do not. Off for a push that is not
    /// deleting: what is inside a directory only the peer has cannot then affect
    /// anything, and each level of it would cost a round trip to learn.
    explore: bool,
    pending: Vec<String>,
    outstanding: usize,
    /// Directories already asked for, so a peer cannot walk us in circles.
    asked: BTreeSet<String>,
    found: Vec<Found>,
}

impl Survey {
    pub fn new(explore: bool) -> Survey {
        Survey {
            explore,
            pending: Vec::new(),
            outstanding: 0,
            asked: BTreeSet::new(),
            found: Vec::new(),
        }
    }

    /// Begin at the root.
    pub fn start(&mut self) {
        self.want("");
    }

    /// The directories to ask the peer for, and none of them twice.
    pub fn take_requests(&mut self) -> Vec<String> {
        let requests = std::mem::take(&mut self.pending);
        self.outstanding += requests.len();
        requests
    }

    pub fn done(&self) -> bool {
        self.outstanding == 0 && self.pending.is_empty()
    }

    pub fn into_found(self) -> Vec<Found> {
        self.found
    }

    /// Compare one directory level against the peer's listing of it.
    pub fn absorb(&mut self, local: &Index, dir: &str, children: &[Child]) {
        self.outstanding = self.outstanding.saturating_sub(1);
        let here = local.children(dir);
        let mut names: BTreeSet<&str> = children.iter().map(|c| c.name.as_str()).collect();
        for child in &here {
            names.insert(child.name.as_str());
        }

        for name in names {
            let rel = if dir.is_empty() {
                name.to_string()
            } else {
                format!("{dir}/{name}")
            };
            let mine = here.iter().find(|c| c.name == name);
            let theirs = children.iter().find(|c| c.name == name);

            // Both directories: one digest comparison settles the whole subtree.
            // This is the line the descent exists for.
            if let (Some(mine), Some(theirs)) = (mine, theirs) {
                if mine.kind == Kind::Dir && theirs.kind == Kind::Dir {
                    if mine.digest != theirs.digest {
                        self.want(&rel);
                    }
                    continue;
                }
            }

            let (here_state, here_mtime) = state_of(mine);
            let (there_state, there_mtime) = state_of(theirs);
            if here_state == there_state {
                continue;
            }
            self.found.push(Found {
                path: rel.clone(),
                here: here_state.clone(),
                there: there_state.clone(),
                here_mtime,
                there_mtime,
            });

            // A directory on one side facing something else on the other: its
            // contents have no counterpart, and every one of them is a change in
            // its own right. Ours are already in the index; the peer's have to be
            // asked for.
            if here_state == PathState::Dir {
                for (path, entry) in local.range_under(&rel) {
                    self.found.push(Found {
                        path: path.clone(),
                        here: entry.state(),
                        there: PathState::Absent,
                        here_mtime: entry.mtime,
                        there_mtime: Stamp::default(),
                    });
                }
            }
            if there_state == PathState::Dir && self.explore {
                self.want(&rel);
            }
        }
    }

    fn want(&mut self, dir: &str) {
        if relpath::depth(dir) > MAX_DEPTH || !self.asked.insert(dir.to_string()) {
            return;
        }
        self.pending.push(dir.to_string());
    }
}

/// A state in as few words as a prompt can get away with.
///
/// Not [`PathState::describe`], which prints a digest: at a question someone is
/// answering, the digest of the thing being replaced is thirty characters of
/// noise between them and the decision.
fn brief(state: &PathState) -> String {
    match state {
        PathState::Absent => "nothing".to_string(),
        PathState::File { size, .. } => format_size(*size),
        PathState::Symlink { target } => format!("symlink -> {target}"),
        PathState::Dir => "directory".to_string(),
    }
}

fn state_of(child: Option<&Child>) -> (PathState, Stamp) {
    match child {
        Some(child) => (
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
            },
            child.mtime,
        ),
        None => (PathState::Absent, Stamp::default()),
    }
}

/// Turn the differences into the steps the receiving side would carry out.
///
/// `local` is this side's index, consulted for one thing only: a file skipped
/// for its size is absent as far as the comparison is concerned, and a plan that
/// treated it as absent would propose writing over it. Those are reported as
/// skipped instead.
pub fn plan(found: Vec<Found>, local: &Index, way: Way, delete: bool) -> Plan {
    let mut plan = Plan::default();
    for difference in found {
        let (from, to, mtime) = match way {
            Way::Pull => (difference.here, difference.there, difference.there_mtime),
            Way::Push => (difference.there, difference.here, difference.here_mtime),
        };
        if from == to {
            continue;
        }
        let step = Step {
            path: difference.path,
            from,
            to,
            mtime,
        };

        // Nothing is removed unless removing was asked for. Without a base there
        // is no telling a file added on the receiving side from one deleted on
        // the sending side, and the two want opposite things done about them.
        if step.is_delete() && !delete {
            plan.skipped.push(Skip {
                path: step.path,
                why: format!("only on {}; --delete would remove it", way.receiver()),
            });
            continue;
        }
        // Replacing a directory destroys everything inside it, which is a
        // deletion however it is spelled.
        if step.drops_a_directory() && !delete {
            plan.skipped.push(Skip {
                path: step.path,
                why: format!(
                    "a directory on {}; --delete would replace it and its contents",
                    way.receiver()
                ),
            });
            continue;
        }
        if way == Way::Pull {
            if let Some(size) = local.oversize().get(&step.path) {
                plan.skipped.push(Skip {
                    path: step.path,
                    why: format!("{} here, over the size limit", format_size(*size)),
                });
                continue;
            }
        }
        plan.steps.push(step);
    }
    order(&mut plan.steps);
    plan.skipped.sort_by(|a, b| a.path.cmp(&b.path));
    plan
}

/// Creations parents-first, deletions children-first.
///
/// Anything else and a file arrives before the directory holding it exists, or a
/// directory refuses to go because something inside it is still there.
pub fn order(steps: &mut [Step]) {
    steps.sort_by(|a, b| match (a.is_delete(), b.is_delete()) {
        (false, true) => std::cmp::Ordering::Less,
        (true, false) => std::cmp::Ordering::Greater,
        (false, false) => a.path.cmp(&b.path),
        (true, true) => b.path.cmp(&a.path),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::file_digest;

    fn file(content: &str) -> PathState {
        PathState::File {
            digest: file_digest(content.as_bytes()),
            size: content.len() as u64,
            mode: 0o644,
        }
    }

    fn step(path: &str, from: PathState, to: PathState) -> Step {
        Step {
            path: path.to_string(),
            from,
            to,
            mtime: Stamp::default(),
        }
    }

    #[test]
    fn a_verb_names_what_the_step_does_to_the_receiving_side() {
        assert_eq!(step("a", PathState::Absent, file("x")).verb(), "new");
        assert_eq!(step("a", file("x"), file("y")).verb(), "update");
        assert_eq!(step("a", file("x"), PathState::Absent).verb(), "del");
        assert_eq!(step("a", PathState::Absent, PathState::Dir).verb(), "mkdir");
        assert_eq!(step("a", file("x"), PathState::Dir).verb(), "replace");
        assert_eq!(step("a", PathState::Dir, file("x")).verb(), "replace");

        // Same bytes, different permissions: nothing to transfer.
        let mut chmod = step("a", file("x"), file("x"));
        if let PathState::File { mode, .. } = &mut chmod.to {
            *mode = 0o755;
        }
        assert_eq!(chmod.verb(), "chmod");
        assert!(!chmod.needs_content());
        assert_eq!(chmod.detail(), "0644 -> 0755");
        assert!(step("a", file("x"), file("y")).needs_content());
    }

    #[test]
    fn creations_come_parents_first_and_deletions_children_first() {
        let mut steps = vec![
            step("a/b/c.txt", PathState::Absent, file("x")),
            step("z/gone.txt", file("x"), PathState::Absent),
            step("a", PathState::Absent, PathState::Dir),
            step("z", PathState::Dir, PathState::Absent),
            step("a/b", PathState::Absent, PathState::Dir),
        ];
        order(&mut steps);
        let paths: Vec<&str> = steps.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, ["a", "a/b", "a/b/c.txt", "z/gone.txt", "z"]);
    }

    #[test]
    fn a_deletion_is_only_proposed_when_deleting_was_asked_for() {
        let found = vec![Found {
            path: "extra.txt".to_string(),
            here: file("x"),
            there: PathState::Absent,
            here_mtime: Stamp::default(),
            there_mtime: Stamp::default(),
        }];
        let index = Index::new();

        let quiet = plan(found.clone(), &index, Way::Pull, false);
        assert!(quiet.steps.is_empty());
        assert_eq!(quiet.skipped.len(), 1);
        assert!(quiet.skipped[0].why.contains("--delete"));

        let loud = plan(found.clone(), &index, Way::Pull, true);
        assert_eq!(loud.steps.len(), 1);
        assert_eq!(loud.steps[0].verb(), "del");

        // The same difference pushed is a file the peer does not have yet, which
        // is a creation and needs no permission to be proposed.
        let pushed = plan(found, &index, Way::Push, false);
        assert_eq!(pushed.steps.len(), 1);
        assert_eq!(pushed.steps[0].verb(), "new");
    }
}
