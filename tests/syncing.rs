//! Whole syncs, through the real protocol.
//!
//! Two sessions with their outboxes wired to each other — no ssh, no sockets,
//! but every message, every decision and every filesystem effect is the real
//! one. See `common::reconcile`.

mod common;

use bisync::merge::{Conflict, Policy};
use bisync::session::Settings;
use bisync::tree::PathState;

use common::{Temp, assert_converged, assert_converged_at, reconcile, settings, sync};

fn pair(tag: &str) -> (Temp, Temp) {
    (
        Temp::new(&format!("{tag}-a")),
        Temp::new(&format!("{tag}-b")),
    )
}

/// A first sync of two trees that have never met: everything each has, the other
/// gets. Both directions in one pass.
#[test]
fn a_first_sync_unions_two_trees() {
    let (a, b) = pair("first");
    a.write("only-a.txt", "from a");
    a.write("dir/nested.txt", "nested in a");
    a.mkdir("empty-in-a");
    b.write("only-b.txt", "from b");
    b.write("other/deep/leaf.txt", "deep in b");

    let out = sync(&a, &b);
    assert_converged(&a, &b);
    assert_eq!(a.read("only-b.txt"), "from b");
    assert_eq!(a.read("other/deep/leaf.txt"), "deep in b");
    assert_eq!(b.read("only-a.txt"), "from a");
    assert_eq!(b.read("dir/nested.txt"), "nested in a");
    assert!(b.exists("empty-in-a"));
    assert!(out.conflicts_a().is_empty());
    assert!(out.conflicts_b().is_empty());
}

/// Once in step, a reconnection settles in two messages and touches nothing.
/// This is what the root digest is for.
#[test]
fn a_second_sync_of_an_unchanged_tree_does_nothing() {
    let (a, b) = pair("noop");
    a.write("f.txt", "content");
    a.write("d/g.txt", "more");
    sync(&a, &b);

    let out = sync(&a, &b);
    assert_eq!(out.a.sent, 0);
    assert_eq!(out.a.received, 0);
    assert_eq!(out.b.sent, 0);
    assert_eq!(out.b.received, 0);
    assert_eq!(out.a.deleted, 0);
    assert_eq!(out.b.deleted, 0);
    // Handshake and goodbyes only: no listing, no announcing.
    assert!(
        out.messages <= 6,
        "{} messages for an unchanged tree",
        out.messages
    );
    assert_eq!(out.a.dirs_listed, 0);
    assert_eq!(out.b.dirs_listed, 0);
}

/// The point of the Merkle tree: a change deep in a large tree is found by
/// descending only the path to it.
#[test]
fn only_the_changed_branch_is_walked() {
    let (a, b) = pair("narrow");
    for i in 0..8 {
        for j in 0..8 {
            a.write(&format!("branch{i}/leaf{j}.txt"), &format!("{i}-{j}"));
        }
    }
    a.write("deep/one/two/three/four/target.txt", "before");
    sync(&a, &b);
    assert_converged(&a, &b);

    a.write("deep/one/two/three/four/target.txt", "after");
    let out = sync(&a, &b);
    assert_eq!(b.read("deep/one/two/three/four/target.txt"), "after");
    assert_eq!(out.a.sent, 1);
    // The announcement settles it, so no descent is needed at all — and if one
    // were, it would visit six directories, not the seventy-three in the tree.
    assert!(
        out.b.dirs_listed <= 6,
        "{} directories listed",
        out.b.dirs_listed
    );
}

#[test]
fn edits_propagate_in_both_directions() {
    let (a, b) = pair("edit");
    a.write("x.txt", "one");
    a.write("y.txt", "two");
    sync(&a, &b);

    a.write("x.txt", "one, edited on a");
    b.write("y.txt", "two, edited on b");
    let out = sync(&a, &b);
    assert_eq!(b.read("x.txt"), "one, edited on a");
    assert_eq!(a.read("y.txt"), "two, edited on b");
    assert_converged(&a, &b);
    assert!(out.conflicts_a().is_empty());
}

#[test]
fn deletions_propagate_rather_than_resurrect() {
    let (a, b) = pair("delete");
    a.write("gone-from-a.txt", "x");
    a.write("gone-from-b.txt", "y");
    a.write("stays.txt", "z");
    sync(&a, &b);

    a.remove("gone-from-a.txt");
    b.remove("gone-from-b.txt");
    sync(&a, &b);

    assert!(!a.exists("gone-from-a.txt"));
    assert!(!b.exists("gone-from-a.txt"));
    assert!(!a.exists("gone-from-b.txt"));
    assert!(!b.exists("gone-from-b.txt"));
    assert!(a.exists("stays.txt"));
    assert!(b.exists("stays.txt"));
    assert_converged(&a, &b);

    // And a third sync does not bring anything back, which is the failure mode
    // a bidirectional sync without a base falls into.
    let out = sync(&a, &b);
    assert_eq!(out.a.sent + out.b.sent, 0);
    assert!(!a.exists("gone-from-a.txt"));
    assert!(!b.exists("gone-from-b.txt"));
}

/// A whole tree deleted on one side. The children have to go before the
/// directories, or a directory refuses to be removed because something is in it.
#[test]
fn a_deleted_directory_tree_is_removed_in_the_right_order() {
    let (a, b) = pair("rmtree");
    a.write("keep.txt", "keep");
    a.write("doomed/one.txt", "1");
    a.write("doomed/two.txt", "2");
    a.write("doomed/sub/three.txt", "3");
    a.write("doomed/sub/deeper/four.txt", "4");
    sync(&a, &b);
    assert!(b.exists("doomed/sub/deeper/four.txt"));

    a.remove("doomed");
    sync(&a, &b);
    assert!(!b.exists("doomed"), "left behind: {:?}", b.list());
    assert!(b.exists("keep.txt"));
    assert_converged(&a, &b);
}

/// The safety property. Both sides edited: neither file is touched, each side
/// ends up holding the other's version where it can be looked at, and the path
/// is frozen until someone decides.
#[test]
fn a_conflict_overwrites_nothing_and_preserves_both_versions() {
    let (a, b) = pair("conflict");
    a.write("shared.txt", "original");
    sync(&a, &b);

    a.write("shared.txt", "a's work");
    b.write("shared.txt", "b's work");
    let out = sync(&a, &b);

    assert_eq!(a.read("shared.txt"), "a's work");
    assert_eq!(b.read("shared.txt"), "b's work");
    assert_eq!(out.conflicts_a(), vec!["shared.txt"]);
    assert_eq!(out.conflicts_b(), vec!["shared.txt"]);

    let in_a = a
        .quarantined_copy("shared.txt")
        .expect("a kept b's version");
    let in_b = b
        .quarantined_copy("shared.txt")
        .expect("b kept a's version");
    assert_eq!(a.read(&in_a), "b's work");
    assert_eq!(b.read(&in_b), "a's work");

    let record = &out.state_a.conflicts["shared.txt"];
    assert_eq!(record.kind, Conflict::BothEdited);
    assert_eq!(record.quarantine, in_a);

    // The conflict is also on the durable record, so it survives a restart.
    let log = a.read(".bisync/conflicts.log");
    assert!(log.contains("shared.txt"), "{log}");
}

/// A frozen path stays frozen: syncing again neither resolves it by accident nor
/// reports it over and over.
#[test]
fn a_frozen_path_stays_frozen_and_quiet() {
    let (a, b) = pair("frozen");
    a.write("shared.txt", "original");
    a.write("untouched.txt", "fine");
    sync(&a, &b);
    a.write("shared.txt", "a's work");
    b.write("shared.txt", "b's work");
    sync(&a, &b);

    let out = sync(&a, &b);
    assert_eq!(a.read("shared.txt"), "a's work");
    assert_eq!(b.read("shared.txt"), "b's work");
    assert_eq!(out.a.sent, 0);
    assert_eq!(out.a.received, 0);
    assert_eq!(out.conflicts_a(), vec!["shared.txt"]);

    // And an unrelated change still gets through while one path is frozen.
    a.write("untouched.txt", "changed anyway");
    sync(&a, &b);
    assert_eq!(b.read("untouched.txt"), "changed anyway");
    assert_eq!(b.read("shared.txt"), "b's work");
}

#[test]
fn deleting_on_one_side_while_editing_on_the_other_is_a_conflict() {
    let (a, b) = pair("del-vs-edit");
    a.write("contested.txt", "original");
    sync(&a, &b);

    a.remove("contested.txt");
    b.write("contested.txt", "b still wants this");
    let out = sync(&a, &b);

    // Neither side's decision is silently overridden.
    assert!(!a.exists("contested.txt"));
    assert_eq!(b.read("contested.txt"), "b still wants this");
    assert_eq!(out.conflicts_a(), vec!["contested.txt"]);
    assert_eq!(
        out.state_a.conflicts["contested.txt"].kind,
        Conflict::DeletedHereEditedThere
    );
    // a has no copy of its own to keep — it deleted it — but it does fetch b's,
    // so the version that exists is not left on one machine only.
    assert!(a.quarantined_copy("contested.txt").is_some());
}

#[test]
fn a_file_on_one_side_and_a_directory_on_the_other_is_a_conflict() {
    let (a, b) = pair("typeclash");
    a.write("thing", "a file here");
    sync(&a, &b);

    a.write("thing", "still a file, edited");
    b.remove("thing");
    b.write("thing/inside.txt", "a directory there");
    let out = sync(&a, &b);

    assert_eq!(a.read("thing"), "still a file, edited");
    assert_eq!(b.read("thing/inside.txt"), "a directory there");
    assert!(!out.conflicts_a().is_empty());
    assert_eq!(out.state_a.conflicts["thing"].kind, Conflict::TypeClash);
}

#[test]
fn the_local_policy_keeps_this_side_and_files_the_other_away() {
    let (a, b) = pair("policy-local");
    a.write("shared.txt", "original");
    sync(&a, &b);
    a.write("shared.txt", "a's work");
    b.write("shared.txt", "b's work");

    let out = reconcile(&a, &b, settings(1 << 20, Policy::Local));
    // The initiator's copy wins on both sides, and b's own version — the one
    // that was replaced — is kept in `diffs`.
    assert_eq!(a.read("shared.txt"), "a's work");
    assert_eq!(b.read("shared.txt"), "a's work");
    assert_eq!(b.read(&b.kept_copy("shared.txt").unwrap()), "b's work");
    assert!(out.conflicts_a().is_empty());
    assert!(out.conflicts_b().is_empty());
    assert_converged(&a, &b);
}

#[test]
fn the_remote_policy_takes_the_peers_version_without_losing_ours() {
    let (a, b) = pair("policy-remote");
    a.write("shared.txt", "original");
    sync(&a, &b);
    a.write("shared.txt", "a's work");
    b.write("shared.txt", "b's work");

    reconcile(&a, &b, settings(1 << 20, Policy::Remote));
    assert_eq!(a.read("shared.txt"), "b's work");
    assert_eq!(b.read("shared.txt"), "b's work");
    // Nothing was destroyed to make that happen.
    assert_eq!(a.read(&a.kept_copy("shared.txt").unwrap()), "a's work");
    assert_converged(&a, &b);
}

/// Ignored paths are not synced, and — more to the point — their existence does
/// not stop the two trees agreeing they are in step.
#[test]
fn ignored_paths_are_left_alone_on_both_sides() {
    let (a, b) = pair("ignored");
    a.write("src/main.rs", "code");
    a.write("target/debug/artifact", "build output from a");
    a.write("notes.txt.swp", "editor swap");
    b.write("target/debug/other", "build output from b");
    b.write(".git/HEAD", "ref: refs/heads/main");

    let out = sync(&a, &b);
    assert_eq!(b.read("src/main.rs"), "code");
    assert!(!b.exists("target/debug/artifact"));
    assert!(!a.exists("target/debug/other"));
    assert!(!a.exists(".git/HEAD"));
    assert!(!b.exists("notes.txt.swp"));
    // Each side keeps its own.
    assert_eq!(a.read("target/debug/artifact"), "build output from a");
    assert_eq!(b.read(".git/HEAD"), "ref: refs/heads/main");
    assert!(out.conflicts_a().is_empty());
    assert_converged(&a, &b);
}

/// A file over the limit is skipped, reported, and — critically — does not stop
/// everything else converging or make the next sync walk the tree again.
#[test]
fn files_over_the_limit_are_skipped_without_blocking_the_rest() {
    let (a, b) = pair("oversize");
    a.write_bytes("huge.bin", &vec![9u8; 4000]);
    a.write("small.txt", "fits");
    b.write_bytes("also-huge.bin", &vec![8u8; 5000]);

    let out = reconcile(&a, &b, settings(1000, Policy::Quarantine));
    assert_eq!(b.read("small.txt"), "fits");
    assert!(!b.exists("huge.bin"));
    assert!(!a.exists("also-huge.bin"));
    assert!(out.conflicts_a().is_empty());
    assert_converged_at(&a, &b, 1000);

    // The second pass is quiet: the skipped files are outside the tree digest,
    // so the two roots match and there is nothing to rediscover.
    let out = reconcile(&a, &b, settings(1000, Policy::Quarantine));
    assert_eq!(out.a.dirs_listed, 0);
    assert_eq!(out.b.dirs_listed, 0);
    assert_eq!(out.a.sent + out.a.received, 0);

    // Raising the limit brings them across.
    reconcile(&a, &b, settings(1 << 20, Policy::Quarantine));
    assert_eq!(b.path().join("huge.bin").metadata().unwrap().len(), 4000);
    assert_eq!(
        a.path().join("also-huge.bin").metadata().unwrap().len(),
        5000
    );
}

#[test]
fn symlinks_are_synced_as_links() {
    let (a, b) = pair("symlink");
    a.write("target.txt", "pointed at");
    a.symlink("here", "target.txt");
    a.symlink("dangling", "../outside/nothing");
    sync(&a, &b);

    let link = b.path().join("here");
    assert!(link.symlink_metadata().unwrap().is_symlink());
    assert_eq!(
        std::fs::read_link(&link).unwrap().to_str(),
        Some("target.txt")
    );
    // A link whose target does not exist is still a link, not an error and not a
    // copy of something.
    let dangling = b.path().join("dangling");
    assert!(dangling.symlink_metadata().unwrap().is_symlink());
    assert_eq!(
        std::fs::read_link(&dangling).unwrap().to_str(),
        Some("../outside/nothing")
    );
    assert_converged(&a, &b);

    // Repointing propagates.
    a.symlink("here", "elsewhere.txt");
    sync(&a, &b);
    assert_eq!(
        std::fs::read_link(b.path().join("here")).unwrap().to_str(),
        Some("elsewhere.txt")
    );
}

/// The bytes have not moved, so nothing should be transferred — but the mode has
/// to arrive all the same.
#[test]
fn a_permission_change_syncs_without_a_transfer() {
    let (a, b) = pair("chmod");
    a.write("script.sh", "#!/bin/sh\necho hello\n");
    sync(&a, &b);
    assert_eq!(b.mode("script.sh"), 0o644);

    a.chmod("script.sh", 0o755);
    let out = sync(&a, &b);
    assert_eq!(b.mode("script.sh"), 0o755);
    assert_eq!(out.a.sent, 0, "a whole file was sent to change four bits");
    assert_eq!(out.b.received, 0);
    assert_converged(&a, &b);
}

/// Large enough to need many `FileData` frames in both directions at once.
#[test]
fn multi_chunk_transfers_arrive_intact() {
    let (a, b) = pair("chunks");
    let from_a: Vec<u8> = (0..500_000u32).map(|i| (i % 251) as u8).collect();
    let from_b: Vec<u8> = (0..400_000u32).map(|i| (i % 241) as u8).collect();
    a.write_bytes("big-a.bin", &from_a);
    b.write_bytes("big-b.bin", &from_b);

    let out = reconcile(&a, &b, settings(1 << 20, Policy::Quarantine));
    assert_eq!(std::fs::read(b.path().join("big-a.bin")).unwrap(), from_a);
    assert_eq!(std::fs::read(a.path().join("big-b.bin")).unwrap(), from_b);
    assert_eq!(out.a.sent_bytes, from_a.len() as u64);
    assert_eq!(out.a.received_bytes, from_b.len() as u64);
    assert_converged(&a, &b);
}

/// Renaming a file is a deletion and a creation as far as the tree is concerned,
/// and must not leave the old name behind on the peer.
#[test]
fn a_rename_moves_the_file_on_the_peer_too() {
    let (a, b) = pair("rename");
    a.write("before.txt", "same bytes either way");
    sync(&a, &b);

    std::fs::rename(a.path().join("before.txt"), a.path().join("after.txt")).unwrap();
    sync(&a, &b);
    assert!(!b.exists("before.txt"));
    assert_eq!(b.read("after.txt"), "same bytes either way");
    assert_converged(&a, &b);
}

/// Empty directories are part of the tree; a sync that only carried files would
/// quietly drop them.
#[test]
fn empty_directories_are_created_and_removed() {
    let (a, b) = pair("emptydirs");
    a.mkdir("scaffolding/deep/nested");
    sync(&a, &b);
    assert!(b.exists("scaffolding/deep/nested"));
    assert_converged(&a, &b);

    a.remove("scaffolding");
    sync(&a, &b);
    assert!(!b.exists("scaffolding"));
    assert_converged(&a, &b);
}

/// The base is what tells a deletion from a change the peer has not seen. Losing
/// it must make bisync cautious, not destructive.
#[test]
fn a_lost_base_produces_conflicts_rather_than_deletions() {
    let (a, b) = pair("lostbase");
    a.write("shared.txt", "agreed");
    a.write("same.txt", "identical on both");
    sync(&a, &b);
    assert_converged(&a, &b);

    // Both sides forget everything they ever agreed, then diverge.
    std::fs::remove_file(a.path().join(".bisync/state")).unwrap();
    std::fs::remove_file(b.path().join(".bisync/state")).unwrap();
    a.write("shared.txt", "a went this way");
    b.write("shared.txt", "b went that way");

    let out = sync(&a, &b);
    // Nothing was deleted and nothing was overwritten.
    assert_eq!(a.read("shared.txt"), "a went this way");
    assert_eq!(b.read("shared.txt"), "b went that way");
    assert_eq!(out.conflicts_a(), vec!["shared.txt"]);
    // A path both sides still agree on is not dragged into it.
    assert_eq!(a.read("same.txt"), "identical on both");
    assert_eq!(b.read("same.txt"), "identical on both");
    assert_eq!(out.base_a("same.txt"), out.state_b.base_of("same.txt"));
}

/// A change made while the tree is converged, on the side that did not start the
/// session. The responder announces on its own initiative.
#[test]
fn the_responder_announces_its_own_changes() {
    let (a, b) = pair("responder");
    a.write("f.txt", "one");
    sync(&a, &b);
    b.write("f.txt", "changed on the responder");
    b.write("new-on-b.txt", "also new");

    let out = sync(&a, &b);
    assert_eq!(a.read("f.txt"), "changed on the responder");
    assert_eq!(a.read("new-on-b.txt"), "also new");
    assert_eq!(out.a.received, 2);
    assert_converged(&a, &b);
}

/// Both sides making the same edit is agreement, not a conflict — a formatter
/// run in two places, or a file restored from the same backup.
#[test]
fn the_same_edit_on_both_sides_is_not_a_conflict() {
    let (a, b) = pair("sameedit");
    a.write("f.txt", "before");
    sync(&a, &b);
    a.write("f.txt", "after");
    b.write("f.txt", "after");

    let out = sync(&a, &b);
    assert!(out.conflicts_a().is_empty());
    assert!(out.conflicts_b().is_empty());
    assert_eq!(out.a.sent + out.a.received, 0);
    // And the base moved up, so nothing is re-offered next time.
    let out = sync(&a, &b);
    assert!(out.messages <= 6, "{} messages", out.messages);
}

/// A dry run must decide everything and change nothing.
#[test]
fn a_dry_run_reports_without_touching_anything() {
    let (a, b) = pair("dryrun");
    a.write("new.txt", "would be sent");
    a.write("dir/inside.txt", "also");
    b.write("theirs.txt", "would be received");

    let before_a = a.list();
    let before_b = b.list();
    let out = reconcile(
        &a,
        &b,
        Settings {
            dry_run: true,
            ..Settings::default()
        },
    );
    assert_eq!(a.list(), before_a);
    assert_eq!(b.list(), before_b);
    assert_eq!(out.a.sent, 0);
    assert_eq!(out.a.received, 0);
    assert!(
        out.state_a.base.is_empty(),
        "a dry run must not record agreements"
    );
    // It did have something to say about each path.
    let mentioned: Vec<String> = out
        .events_a
        .iter()
        .filter_map(|e| match e {
            bisync::session::Event::Change {
                verb: "would",
                path,
                ..
            } => Some(path.clone()),
            _ => None,
        })
        .collect();
    assert!(mentioned.contains(&"new.txt".to_string()), "{mentioned:?}");
    assert!(
        mentioned.contains(&"dir/inside.txt".to_string()),
        "{mentioned:?}"
    );
}

/// After a conflict is resolved in favour of one side, that version must reach
/// the other — which needs the peer's freeze on the path to give way to it.
#[test]
fn resolving_in_favour_of_one_side_propagates() {
    let (a, b) = pair("resolve");
    a.write("shared.txt", "original");
    sync(&a, &b);
    a.write("shared.txt", "a's work");
    b.write("shared.txt", "b's work");
    sync(&a, &b);
    assert!(!a.list().is_empty());

    bisync::run::resolve(a.path(), &["shared.txt".to_string()], false, false).unwrap();

    let out = sync(&a, &b);
    assert_eq!(a.read("shared.txt"), "a's work");
    assert_eq!(b.read("shared.txt"), "a's work");
    assert!(out.conflicts_a().is_empty());
    assert!(out.conflicts_b().is_empty(), "the peer stayed frozen");
    // b's own version was not simply destroyed to make room: it was replaced, so
    // it is in `diffs` — alongside, in `quarantine`, the copy of a's version that
    // b fetched when the conflict was first found.
    assert_eq!(b.read(&b.kept_copy("shared.txt").unwrap()), "b's work");
    assert_eq!(
        b.read(&b.quarantined_copy("shared.txt").unwrap()),
        "a's work"
    );
    assert_converged(&a, &b);
}

/// The same, resolved the other way: the peer's copy is already in quarantine,
/// so settling it needs no transfer at all.
#[test]
fn resolving_in_favour_of_the_peer_uses_the_copy_already_here() {
    let (a, b) = pair("resolve-remote");
    a.write("shared.txt", "original");
    sync(&a, &b);
    a.write("shared.txt", "a's work");
    b.write("shared.txt", "b's work");
    sync(&a, &b);

    bisync::run::resolve(a.path(), &["shared.txt".to_string()], true, false).unwrap();
    assert_eq!(a.read("shared.txt"), "b's work");

    let out = sync(&a, &b);
    assert_eq!(a.read("shared.txt"), "b's work");
    assert_eq!(b.read("shared.txt"), "b's work");
    assert!(out.conflicts_a().is_empty());
    assert!(out.conflicts_b().is_empty());
    assert_eq!(out.a.received, 0, "the version was already on disk");
    assert_converged(&a, &b);
}

/// Many paths at once, in both directions, including nesting and deletions. Not
/// a scenario so much as a check that nothing in the batching, ordering or
/// base-advancing falls over at scale.
#[test]
fn a_large_mixed_change_set_converges() {
    let (a, b) = pair("mixed");
    for i in 0..60 {
        a.write(&format!("a{i:03}.txt"), &format!("a content {i}"));
        b.write(&format!("b{i:03}.txt"), &format!("b content {i}"));
        a.write(
            &format!("shared/dir{}/f{i}.txt", i % 7),
            &format!("shared {i}"),
        );
    }
    sync(&a, &b);
    assert_converged(&a, &b);

    for i in 0..60 {
        if i % 3 == 0 {
            a.write(&format!("a{i:03}.txt"), &format!("a edited {i}"));
        }
        if i % 5 == 0 {
            b.remove(&format!("b{i:03}.txt"));
        }
        if i % 7 == 0 {
            b.write(
                &format!("shared/dir{}/f{i}.txt", i % 7),
                &format!("b touched {i}"),
            );
        }
    }
    let out = sync(&a, &b);
    assert_converged(&a, &b);
    assert!(out.conflicts_a().is_empty(), "{:?}", out.conflicts_a());
    assert_eq!(a.list(), b.list());
    assert_eq!(out.a.sent, 20);
    assert_eq!(out.a.deleted, 12);
}

/// The base must end up agreeing on both sides, or the next sync starts from two
/// different ideas of what was agreed.
#[test]
fn both_sides_end_with_the_same_base() {
    let (a, b) = pair("bases");
    a.write("one.txt", "1");
    a.write("d/two.txt", "2");
    b.write("three.txt", "3");
    b.symlink("l", "three.txt");
    b.mkdir("empty");
    let out = sync(&a, &b);
    assert_converged(&a, &b);

    let mut mismatches = Vec::new();
    let paths: std::collections::BTreeSet<&String> = out
        .state_a
        .base
        .keys()
        .chain(out.state_b.base.keys())
        .collect();
    for path in paths {
        let (in_a, in_b) = (out.state_a.base_of(path), out.state_b.base_of(path));
        if in_a != in_b {
            mismatches.push((path.clone(), in_a, in_b));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    assert_eq!(out.state_a.base_of("one.txt"), a_state(&a, "one.txt"));
}

fn a_state(t: &Temp, rel: &str) -> PathState {
    let store = bisync::store::Store::open(t.path()).unwrap();
    store.current_state(rel).unwrap()
}
