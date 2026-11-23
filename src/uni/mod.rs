//! `unisync`: one directory copied to another, over ssh, one change at a time.
//!
//! The same machinery as `bisync` — the same digests, the same Merkle descent,
//! the same message set, the same guarded store — arranged around a different
//! question. `bisync` asks "what has each side done since they last agreed?",
//! which needs a remembered base and gives conflicts, quarantine and a state
//! file. This asks "how do these two directories differ, right now?", which
//! needs nothing remembered at all:
//!
//! * Both ends hash their tree. The descent compares the two, skipping every
//!   subtree whose digest already matches, and what comes out is the plain
//!   difference between them.
//! * The run goes one way. The sending side's version of a path is what the
//!   receiving side's becomes, so there is nothing to merge and nothing to
//!   freeze.
//! * Every change is put to the user before it happens: yes, no, or show me the
//!   diff. That is what stands in for the base — the judgement about which side
//!   is right is a person's, made once, at the moment it matters.
//!
//! Nothing is written to the tree until the whole plan has been answered, and
//! nothing is left behind afterwards but the copies of anything that was
//! replaced, under `.unisync/diffs`.
//!
//! [`plan`] is pure: the descent state machine and the change list, testable
//! with no link. [`ask`] is the interaction, testable with a string of
//! keystrokes. [`session`] is the protocol, driven entirely by messages in and
//! messages out. [`run`] is the outside world — ssh, the terminal, the loop.

pub mod ask;
pub mod plan;
pub mod run;
pub mod session;
