//! The three-way merge. Five rules, and between them the whole semantics of the
//! tool, so each is pinned here on its own.

use bisync::hash::file_digest;
use bisync::merge::{Conflict, Decision, Policy, resolve, under_policy};
use bisync::tree::{PathState, Stamp};

fn file(content: &str) -> PathState {
    PathState::File {
        digest: file_digest(content.as_bytes()),
        size: content.len() as u64,
        mode: 0o644,
    }
}

fn file_mode(content: &str, mode: u32) -> PathState {
    PathState::File {
        digest: file_digest(content.as_bytes()),
        size: content.len() as u64,
        mode,
    }
}

const GONE: PathState = PathState::Absent;

/// Rule 1, and first for a reason: the same edit made on both sides — a file
/// restored from the same backup, a formatter run in both places — is agreement,
/// not a conflict.
#[test]
fn identical_states_are_converged_whatever_the_base_says() {
    assert_eq!(
        resolve(&file("old"), &file("new"), &file("new"), &file("old")),
        Decision::Converged
    );
    assert_eq!(
        resolve(&GONE, &file("x"), &file("x"), &GONE),
        Decision::Converged
    );
    assert_eq!(
        resolve(&file("x"), &GONE, &GONE, &file("x")),
        Decision::Converged
    );
    assert_eq!(
        resolve(&GONE, &PathState::Dir, &PathState::Dir, &GONE),
        Decision::Converged
    );
}

/// Rule 2: the peer built its change on exactly what we are holding, so taking
/// it discards nothing. This is also what carries a conflict resolution across:
/// resolving in favour of the local copy rewinds the base to the peer's version,
/// and the announcement that follows arrives as a fast-forward.
#[test]
fn a_change_built_on_our_exact_state_is_a_fast_forward() {
    // Steady state: base, local and the peer's `from` all agree.
    assert_eq!(
        resolve(&file("v1"), &file("v1"), &file("v2"), &file("v1")),
        Decision::Take { save_local: false }
    );
    // The resolution case: our local version is not the base, and the peer has
    // deliberately built on it. Taken, but not thrown away.
    assert_eq!(
        resolve(
            &file("theirs"),
            &file("ours"),
            &file("theirs2"),
            &file("ours")
        ),
        Decision::Take { save_local: true }
    );
    // Nothing to save when there was nothing there.
    assert_eq!(
        resolve(&file("base"), &GONE, &file("new"), &GONE),
        Decision::Take { save_local: false }
    );
}

/// Rule 3: we have not touched it since the last agreement, so the peer's change
/// is the only change there is.
#[test]
fn an_untouched_path_takes_the_peers_change() {
    assert_eq!(
        resolve(&file("v1"), &file("v1"), &file("v2"), &file("v0")),
        Decision::Take { save_local: false }
    );
    // Including a deletion.
    assert_eq!(
        resolve(&file("v1"), &file("v1"), &GONE, &file("v0")),
        Decision::Take { save_local: false }
    );
    // And a creation.
    assert_eq!(
        resolve(&GONE, &GONE, &file("new"), &GONE),
        Decision::Take { save_local: false }
    );
}

/// Rule 4: the mirror image. Ours moved, theirs did not, so we offer.
#[test]
fn our_own_change_is_offered_rather_than_overwritten() {
    assert_eq!(
        resolve(&file("v1"), &file("v2"), &file("v1"), &file("v1")),
        Decision::Keep
    );
    // A local deletion is a change like any other, and propagates as one.
    assert_eq!(
        resolve(&file("v1"), &GONE, &file("v1"), &file("v1")),
        Decision::Keep
    );
    assert_eq!(resolve(&GONE, &file("new"), &GONE, &GONE), Decision::Keep);
}

/// Rule 5, and the one that matters: neither side's version descends from the
/// other, so nothing is overwritten.
#[test]
fn independent_changes_on_both_sides_are_conflicts() {
    assert_eq!(
        resolve(&file("v1"), &file("mine"), &file("theirs"), &file("v1")),
        Decision::Hold(Conflict::BothEdited)
    );
    assert_eq!(
        resolve(&file("v1"), &GONE, &file("theirs"), &file("v1")),
        Decision::Hold(Conflict::DeletedHereEditedThere)
    );
    assert_eq!(
        resolve(&file("v1"), &file("mine"), &GONE, &file("v1")),
        Decision::Hold(Conflict::EditedHereDeletedThere)
    );
    assert_eq!(
        resolve(&file("v1"), &PathState::Dir, &file("theirs"), &file("v1")),
        Decision::Hold(Conflict::TypeClash)
    );
    // No common base at all: two trees that were populated independently.
    assert_eq!(
        resolve(&GONE, &file("mine"), &file("theirs"), &GONE),
        Decision::Hold(Conflict::Diverged)
    );
}

/// A base lost to a crash must not become a licence to overwrite. Without one,
/// every difference is a conflict — noisy, and the only safe answer.
#[test]
fn a_lost_base_makes_differences_conflicts_rather_than_guesses() {
    let decision = resolve(&GONE, &file("a"), &file("b"), &GONE);
    assert!(matches!(decision, Decision::Hold(_)));
    // Unless one side simply does not have the path, in which case there is
    // nothing to lose by copying it.
    assert_eq!(
        resolve(&GONE, &GONE, &file("b"), &GONE),
        Decision::Take { save_local: false }
    );
    assert_eq!(resolve(&GONE, &file("a"), &GONE, &GONE), Decision::Keep);
}

/// Permissions are part of a file's state, so a `chmod` propagates — the session
/// then applies it without a transfer, since the bytes have not moved.
#[test]
fn permissions_are_part_of_the_state() {
    let a = file_mode("same", 0o644);
    let b = file_mode("same", 0o600);
    assert_ne!(a, b);
    assert_eq!(
        resolve(&a, &a, &b, &a),
        Decision::Take { save_local: false }
    );
    assert_eq!(resolve(&a, &b, &a, &a), Decision::Keep);
}

/// A directory carries no mode in its state. Directory permissions are far more
/// often a local decision than something to force on a peer, and making them
/// part of the comparison means the two ends fight over every directory forever.
#[test]
fn directories_do_not_carry_a_mode_to_argue_about() {
    assert_eq!(
        resolve(
            &PathState::Dir,
            &PathState::Dir,
            &PathState::Dir,
            &PathState::Dir
        ),
        Decision::Converged
    );
}

#[test]
fn policies_break_a_conflict_in_the_direction_asked_for() {
    let old = Stamp {
        secs: 1000,
        nanos: 0,
    };
    let new = Stamp {
        secs: 2000,
        nanos: 0,
    };
    let conflict = Decision::Hold(Conflict::BothEdited);

    assert_eq!(
        under_policy(conflict, Policy::Quarantine, old, new),
        conflict
    );
    assert_eq!(
        under_policy(conflict, Policy::Local, old, new),
        Decision::Keep
    );
    assert_eq!(
        under_policy(conflict, Policy::Remote, old, new),
        Decision::Take { save_local: true }
    );
    assert_eq!(
        under_policy(conflict, Policy::Newer, old, new),
        Decision::Take { save_local: true }
    );
    assert_eq!(
        under_policy(conflict, Policy::Newer, new, old),
        Decision::Keep
    );
    // Two different versions reported at the same nanosecond: the timestamps are
    // not evidence, so nothing is thrown away on the strength of them.
    assert_eq!(under_policy(conflict, Policy::Newer, new, new), conflict);
    // Sub-second differences still count.
    let later = Stamp {
        secs: 2000,
        nanos: 1,
    };
    assert_eq!(
        under_policy(conflict, Policy::Newer, new, later),
        Decision::Take { save_local: true }
    );
}

/// A policy only ever breaks a tie. It must not turn a settled decision into a
/// different one.
#[test]
fn policies_leave_non_conflicts_alone() {
    for policy in [
        Policy::Quarantine,
        Policy::Local,
        Policy::Remote,
        Policy::Newer,
    ] {
        let s = Stamp::default();
        assert_eq!(
            under_policy(Decision::Converged, policy, s, s),
            Decision::Converged
        );
        assert_eq!(under_policy(Decision::Keep, policy, s, s), Decision::Keep);
        assert_eq!(
            under_policy(Decision::Take { save_local: false }, policy, s, s),
            Decision::Take { save_local: false }
        );
    }
}

#[test]
fn policy_names_round_trip() {
    for policy in [
        Policy::Quarantine,
        Policy::Local,
        Policy::Remote,
        Policy::Newer,
    ] {
        assert_eq!(Policy::parse(policy.name()), Some(policy));
    }
    assert_eq!(Policy::parse("mine"), None);
    assert_eq!(Policy::default(), Policy::Quarantine);
}
