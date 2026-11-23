//! The decision: given what we last agreed with the peer, what we have now, and
//! what the peer says it has, what happens to this path?
//!
//! A three-way merge, and deliberately nothing more. Every rule is stated here
//! rather than spread across the session, because these five cases are the whole
//! semantics of the tool and they are worth being able to read in one screen —
//! and to unit-test without a filesystem or a socket in sight.

use crate::tree::PathState;

/// How a conflict arose. Only used to phrase the report; every variant is
//  handled the same way.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Conflict {
    /// Both sides edited the content.
    BothEdited,
    /// We deleted it, the peer edited it.
    DeletedHereEditedThere,
    /// We edited it, the peer deleted it.
    EditedHereDeletedThere,
    /// One side has a file where the other has a directory or a symlink.
    TypeClash,
    /// Neither side's state matches the base and neither is a plain edit — the
    /// residual case, most often a base lost to an interrupted sync.
    Diverged,
}

impl Conflict {
    pub fn describe(self) -> &'static str {
        match self {
            Conflict::BothEdited => "edited on both sides",
            Conflict::DeletedHereEditedThere => "deleted here, edited on the peer",
            Conflict::EditedHereDeletedThere => "edited here, deleted on the peer",
            Conflict::TypeClash => "different kinds of entry on each side",
            Conflict::Diverged => "diverged with no common base",
        }
    }
}

/// What to do with one path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    /// Both sides already agree. Nothing to transfer; the base moves up.
    Converged,
    /// Adopt the peer's state.
    Take {
        /// Whether the current local version is an unsynced change that would be
        /// destroyed. When true it is copied into quarantine first — the peer is
        /// still right to win, but nothing is thrown away to make that happen.
        save_local: bool,
    },
    /// Ours is the version that moved. Offer it; the peer decides.
    Keep,
    /// Both sides moved, in different directions. Nothing is overwritten: the
    /// local version stays put, the peer's copy is fetched into quarantine, and
    /// the path is frozen until someone says which they wanted.
    Hold(Conflict),
}

/// Resolve one path.
///
/// * `base` — the state both sides agreed on at the end of the last sync.
/// * `local` — what is on this filesystem now.
/// * `remote` — what the peer says it has.
/// * `from` — the peer's *own* base for this path: its belief about us.
///
/// The rules, in order, and the reason each comes where it does:
///
/// 1. `local == remote`: converged. Checked first so a path both sides changed
///    identically — the same edit applied twice, a file restored from the same
///    backup — is never called a conflict.
/// 2. `from == local`: a fast-forward. The peer built its change on precisely
///    the state we are holding, so adopting it discards nothing. This is also
///    what makes conflict resolution work without a special message: a side
///    that resolves in favour of its own copy rewinds its base to the peer's
///    version, and its next announcement arrives here as a fast-forward.
/// 3. `local == base`: we have not touched it since the last agreement, so the
///    peer's change is the only change.
/// 4. `remote == base`: the mirror image — ours is the only change.
/// 5. Otherwise both sides moved independently: a conflict.
///
/// Rules 2 and 3 overlap in the steady state and disagree only when our local
/// version is an unsynced edit that the peer has explicitly built on top of.
/// Rule 2 wins there, and sets `save_local` so the edit survives in quarantine.
pub fn resolve(
    base: &PathState,
    local: &PathState,
    remote: &PathState,
    from: &PathState,
) -> Decision {
    if local == remote {
        return Decision::Converged;
    }
    if from == local {
        return Decision::Take {
            save_local: local != base && !local.is_absent(),
        };
    }
    if local == base {
        return Decision::Take { save_local: false };
    }
    if remote == base {
        return Decision::Keep;
    }
    Decision::Hold(classify(base, local, remote))
}

/// Which flavour of conflict this is, for the message the user reads.
fn classify(base: &PathState, local: &PathState, remote: &PathState) -> Conflict {
    match (local.is_absent(), remote.is_absent()) {
        (true, false) if !base.is_absent() => Conflict::DeletedHereEditedThere,
        (false, true) if !base.is_absent() => Conflict::EditedHereDeletedThere,
        (false, false) => match (local.kind(), remote.kind()) {
            (Some(a), Some(b)) if a != b => Conflict::TypeClash,
            _ if base.is_absent() => Conflict::Diverged,
            _ => Conflict::BothEdited,
        },
        _ => Conflict::Diverged,
    }
}

/// Which way changes are allowed to flow in a session.
///
/// Not a merge rule but a filter over the outcome of one: the merge still decides
/// what each path's situation *is*, and this decides whether this session is
/// willing to act on it. Keeping it out of [`resolve`] is deliberate — a `--pull`
/// that quietly reclassified conflicts, or that advanced the base for a change it
/// declined to send, would make the next full sync wrong.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Direction {
    /// Changes flow both ways. The default, and what a sync is for.
    #[default]
    Both,
    /// Take the peer's changes; do not offer ours.
    Pull,
    /// Offer ours; do not take the peer's.
    Push,
}

impl Direction {
    /// The same instruction as the other end must read it.
    ///
    /// Like [`Policy::inverted`], and for the same reason: a direction names a
    /// way along the link, not "away from me". If both ends read `pull` as "take
    /// what I am given", both would sit waiting to be given something.
    pub fn inverted(self) -> Direction {
        match self {
            Direction::Both => Direction::Both,
            Direction::Pull => Direction::Push,
            Direction::Push => Direction::Pull,
        }
    }

    /// May this side apply what the peer has?
    pub fn may_take(self) -> bool {
        matches!(self, Direction::Both | Direction::Pull)
    }

    /// May this side offer what it has?
    pub fn may_offer(self) -> bool {
        matches!(self, Direction::Both | Direction::Push)
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "both" => Some(Direction::Both),
            "pull" => Some(Direction::Pull),
            "push" => Some(Direction::Push),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Direction::Both => "both",
            Direction::Pull => "pull",
            Direction::Push => "push",
        }
    }
}

/// What to do with a conflict, from the config.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Policy {
    /// Change nothing, keep the peer's copy aside, tell the user. The default,
    /// because it is the only option that cannot lose work unattended.
    #[default]
    Quarantine,
    /// The local version wins. The peer's copy still goes to quarantine.
    Local,
    /// The peer's version wins. The local copy goes to quarantine.
    Remote,
    /// Whichever was modified more recently wins; the loser goes to quarantine.
    /// Depends on two machines' clocks agreeing, which is why it is not default.
    Newer,
}

impl Policy {
    /// The policy as the responding end must apply it.
    ///
    /// `local` and `remote` name sides of the *link*, not "whoever happens to be
    /// deciding". Were each end to read them as "me" and "the other", `local`
    /// would leave both sides keeping their own copy — a stalemate that never
    /// converges — and `remote` would have them swap versions and still differ.
    /// The side that opens the session sets the terms, so `local` is its copy and
    /// the responder inverts. `quarantine` and `newer` are symmetric already:
    /// both ends compare the same two versions and reach the same answer.
    pub fn inverted(self) -> Policy {
        match self {
            Policy::Local => Policy::Remote,
            Policy::Remote => Policy::Local,
            other => other,
        }
    }
}

impl Policy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "quarantine" => Some(Policy::Quarantine),
            "local" => Some(Policy::Local),
            "remote" => Some(Policy::Remote),
            "newer" => Some(Policy::Newer),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Policy::Quarantine => "quarantine",
            Policy::Local => "local",
            Policy::Remote => "remote",
            Policy::Newer => "newer",
        }
    }
}

/// Turn a `Hold` into an action under the configured policy. Anything that is
/// not a hold passes through untouched.
///
/// `local_mtime` and `remote_mtime` are only consulted by [`Policy::Newer`], and
/// a tie there falls back to quarantining: if two machines report the same
/// nanosecond for two different versions, the timestamps are not evidence.
pub fn under_policy(
    decision: Decision,
    policy: Policy,
    local_mtime: crate::tree::Stamp,
    remote_mtime: crate::tree::Stamp,
) -> Decision {
    let Decision::Hold(conflict) = decision else {
        return decision;
    };
    match policy {
        Policy::Quarantine => Decision::Hold(conflict),
        Policy::Local => Decision::Keep,
        Policy::Remote => Decision::Take { save_local: true },
        Policy::Newer => {
            let local_key = (local_mtime.secs, local_mtime.nanos);
            let remote_key = (remote_mtime.secs, remote_mtime.nanos);
            if remote_key > local_key {
                Decision::Take { save_local: true }
            } else if local_key > remote_key {
                Decision::Keep
            } else {
                Decision::Hold(conflict)
            }
        }
    }
}
