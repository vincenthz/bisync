//! bisync — bidirectional directory synchronisation over ssh.
//!
//! Two copies of a directory, on two machines, kept the same in both directions,
//! with the transport rsync uses and none of rsync's one-way semantics.
//!
//! # How it decides what to send
//!
//! Every file has a BLAKE2b-256 digest over its contents, and every directory
//! has one over its children's digests, so the root digest covers the tree.
//! Comparing two roots costs one comparison; when they differ, the descent asks
//! for one directory listing per level along the paths that actually changed and
//! skips every subtree whose digest already matches. A tree of a hundred
//! thousand files with one edit in it is reconciled in as many round trips as
//! that file is deep, and no side ever enumerates its tree at the other.
//!
//! While connected, the side that notices a change says so directly:
//! `from -> to`, a pair of states rather than a pair of trees. The receiver
//! answers with what it actually wants. `from` is the sender's belief about the
//! receiver, which is what lets the receiver distinguish a fast-forward from a
//! genuine divergence without either side trusting a clock.
//!
//! # How it avoids losing anything
//!
//! * Content is written to `.bisync/tmp`, hashed on the way in, and renamed over
//!   the destination only once the digest matches. A dropped connection leaves a
//!   temporary file, never a half-written one.
//! * Every overwrite and every unlink re-reads the target immediately beforehand.
//!   If it is not what the decision was made about, the operation is refused and
//!   the path becomes a conflict.
//! * Nothing local is destroyed without a copy of it. Anything an incoming
//!   version overwrites, anything a propagated deletion unlinks, and any symlink
//!   repointed at something else is first copied to
//!   `.bisync/diffs/<path>.<timestamp>`. The guards above establish that the
//!   change is right; this is what makes being wrong about it survivable.
//! * A sender hashes as it reads and compares the result against what it
//!   announced, so a file edited during its own transfer is withdrawn rather than
//!   delivered as something it is not.
//! * Content is deflated a chunk at a time and travels compressed only when that
//!   came out smaller, so compression never costs bytes. The digest is over the
//!   content either way, which is why the verification above is untouched by it.
//! * A conflict — both sides changed, neither is a descendant of the other —
//!   changes nothing. The local version stays, the peer's is fetched into
//!   `.bisync/quarantine`, and the path is frozen until someone chooses.
//!
//! # Direction
//!
//! A sync goes both ways by default. `--pull` and `--push` restrict it, and the
//! restriction is a session term the far end mirrors. The merge still decides
//! what every path's situation is either way — the base does not advance for
//! something the direction declined to act on, so a later full sync sees it
//! unchanged — and a conflict still freezes, because which side wins is not a
//! question a direction answers.
//!
//! # Layout
//!
//! [`hash`], [`tree`], [`merge`], [`compress`] and [`proto`] are pure: digests,
//! the tree model, the three-way merge, the chunk codec, and the wire format,
//! none of which touch a filesystem or a socket. [`scan`] and [`store`] are the only modules that do — every
//! mutation and its guard is in `store`. [`session`] is the protocol state
//! machine, driven entirely by messages in and messages out, which is why a
//! whole two-way sync can be tested by wiring two of them together with no
//! transport at all. [`transport`], [`watch`] and [`run`] are the outside world.
//!
//! [`uni`] is a second tool built from the same parts: `unisync`, which copies
//! one directory to another one way, keeps nothing at all between runs, and puts
//! every change to the user before making it. It shares the digests, the tree
//! model, the wire format, the scan and the store, and differs in what it does
//! with a difference once it has found one.
//!
//! The command lines are not here. They live in `src/main.rs` and
//! `src/bin/unisync.rs`, because a shell is their only caller and the shape of
//! an argument list is not something anything else should be built against.

pub mod compress;
pub mod config;
pub mod diff;
pub mod hash;
pub mod ignore;
pub mod merge;
pub mod proto;
pub mod relpath;
pub mod run;
pub mod scan;
pub mod session;
pub mod state;
pub mod store;
pub mod transport;
pub mod tree;
pub mod uni;
pub mod util;
pub mod wake;
pub mod watch;
pub mod wire;
