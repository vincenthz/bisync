//! Keeping the local version of anything an incoming file replaces.
//!
//! The guards in `store` establish that an overwrite is the right thing to do.
//! This is the mechanism that makes being wrong about that survivable: before a
//! received file lands, whatever was there is copied to
//! `.bisync/diffs/<path>.<timestamp>`.

mod common;

use bisync::proto::Dest;
use bisync::session::Settings;
use bisync::store::{Placement, Store};
use bisync::tree::{PathState, Stamp};

use common::{Temp, assert_converged, reconcile, sync};

/// A timestamp suffix as bisync writes them: `20260821T140311Z`.
fn looks_like_a_stamp(kept: &str) -> bool {
    let Some((_, stamp)) = kept.rsplit_once('.') else {
        return false;
    };
    stamp.len() == 16
        && stamp.ends_with('Z')
        && stamp.as_bytes()[8] == b'T'
        && stamp.bytes().filter(|c| c.is_ascii_digit()).count() == 14
}

/// The case the whole thing exists for: an edit arrives from the peer, and the
/// version it replaced is still on disk afterwards.
#[test]
fn a_replaced_file_is_kept_with_a_timestamp() {
    let (a, b) = (Temp::new("kept-a"), Temp::new("kept-b"));
    a.write("notes.md", "what a had");
    sync(&a, &b);
    assert_converged(&a, &b);

    b.write("notes.md", "what b changed it to");
    let out = sync(&a, &b);

    assert_eq!(a.read("notes.md"), "what b changed it to");
    let kept = a
        .kept_copy("notes.md")
        .expect("the replaced version was kept");
    assert_eq!(a.read(&kept), "what a had");
    assert!(kept.starts_with(".bisync/diffs/notes.md."), "{kept}");
    assert!(looks_like_a_stamp(&kept), "{kept}");
    assert_eq!(out.a.kept, 1);
    // And the peer, which replaced nothing, kept nothing.
    assert!(b.kept().is_empty(), "{:?}", b.kept());
}

/// A file arriving for the first time replaces nothing, so nothing is kept — and
/// no empty directories are left behind under `.bisync` either, which is what a
/// first sync of a large tree would otherwise fill it with.
#[test]
fn a_new_file_leaves_nothing_behind() {
    let (a, b) = (Temp::new("new-a"), Temp::new("new-b"));
    b.write("one.txt", "first");
    b.write("deep/nest/two.txt", "also first");
    b.mkdir("empty");

    let out = sync(&a, &b);
    assert_converged(&a, &b);
    assert_eq!(a.read("one.txt"), "first");
    assert!(a.kept().is_empty(), "{:?}", a.kept());
    assert_eq!(out.a.kept, 0);
    assert!(
        !a.exists(".bisync/diffs"),
        "an empty diffs directory was left behind"
    );
}

/// The tree's shape is kept inside `diffs`, so a replaced file is found where it
/// lived rather than in a flat heap of basenames.
#[test]
fn the_kept_copy_mirrors_the_trees_shape() {
    let (a, b) = (Temp::new("shape-a"), Temp::new("shape-b"));
    a.write("src/module/thing.rs", "the old one");
    a.write("thing.rs", "a different file with the same name");
    sync(&a, &b);

    b.write("src/module/thing.rs", "the new one");
    b.write("thing.rs", "also new");
    sync(&a, &b);

    let nested = a.kept_copy("src/module/thing.rs").expect("nested kept");
    let top = a.kept_copy("thing.rs").expect("top-level kept");
    assert_eq!(a.read(&nested), "the old one");
    assert_eq!(a.read(&top), "a different file with the same name");
    assert!(nested.starts_with(".bisync/diffs/src/module/"), "{nested}");
}

/// Successive replacements of one path each leave their own copy, including two
/// within the same second — which is when the timestamp alone stops being enough
/// to tell them apart.
#[test]
fn successive_replacements_do_not_overwrite_each_other() {
    let (a, b) = (Temp::new("succ-a"), Temp::new("succ-b"));
    a.write("f.txt", "version one");
    sync(&a, &b);

    for version in ["version two", "version three", "version four"] {
        b.write("f.txt", version);
        sync(&a, &b);
    }

    assert_eq!(a.read("f.txt"), "version four");
    let kept = a.kept();
    assert_eq!(kept.len(), 3, "{kept:?}");
    let contents: Vec<String> = kept.iter().map(|p| a.read(p)).collect();
    for expected in ["version one", "version two", "version three"] {
        assert!(contents.contains(&expected.to_string()), "{contents:?}");
    }
}

/// A deletion destroys local content as surely as an overwrite does, and an
/// agreement that a path should go is not a guarantee that whoever agreed meant
/// it.
#[test]
fn a_propagated_deletion_keeps_the_local_file() {
    let (a, b) = (Temp::new("del-a"), Temp::new("del-b"));
    a.write("doomed.txt", "the only copy of this");
    a.write("survivor.txt", "untouched");
    sync(&a, &b);

    b.remove("doomed.txt");
    let out = sync(&a, &b);

    assert!(!a.exists("doomed.txt"));
    assert_eq!(a.read("survivor.txt"), "untouched");
    let kept = a
        .kept_copy("doomed.txt")
        .expect("the deleted version was kept");
    assert_eq!(a.read(&kept), "the only copy of this");
    assert!(looks_like_a_stamp(&kept), "{kept}");
    assert_eq!(out.a.deleted, 1);
    assert_eq!(out.a.kept, 1);
    // The side that did the deleting had already lost the file; it keeps nothing.
    assert!(b.kept().is_empty(), "{:?}", b.kept());
}

/// A whole tree deleted on the peer: every file in it is preserved, and the
/// directories — which have no content of their own — are not.
#[test]
fn a_deleted_tree_keeps_every_file_in_it() {
    let (a, b) = (Temp::new("deltree-a"), Temp::new("deltree-b"));
    a.write("doomed/one.txt", "1");
    a.write("doomed/two.txt", "2");
    a.write("doomed/sub/three.txt", "3");
    a.mkdir("doomed/empty");
    sync(&a, &b);

    b.remove("doomed");
    let out = sync(&a, &b);

    assert!(!a.exists("doomed"), "{:?}", a.list());
    let kept = a.kept();
    assert_eq!(kept.len(), 3, "{kept:?}");
    let contents: Vec<String> = kept.iter().map(|p| a.read(p)).collect();
    for expected in ["1", "2", "3"] {
        assert!(contents.contains(&expected.to_string()), "{contents:?}");
    }
    // Directory structure is mirrored, so a deleted file is found where it lived.
    assert!(a.kept_copy("doomed/sub/three.txt").is_some(), "{kept:?}");
    assert_eq!(out.a.kept, 3);
}

/// A deletion the guard refuses touches nothing, and so preserves nothing: the
/// file is still live, and a copy of a live file is not evidence of anything.
#[test]
fn a_refused_deletion_preserves_nothing() {
    let t = Temp::new("del-refused");
    let store = Store::open(t.path()).unwrap();
    t.write("d/unexpected.txt", "nobody agreed to delete this");

    let refused = store.remove("d", &PathState::Dir).unwrap();
    assert!(
        matches!(refused, bisync::store::Guarded::Refused(_)),
        "{refused:?}"
    );
    assert!(t.exists("d/unexpected.txt"));
    assert!(t.kept().is_empty(), "{:?}", t.kept());

    // Nor does a deletion of something that has already gone.
    assert!(matches!(
        store.remove("nowhere", &PathState::Absent).unwrap(),
        bisync::store::Guarded::Applied { kept: None }
    ));
    assert!(t.kept().is_empty());
}

/// A deletion refused because the file is not what was agreed leaves both the
/// file and `diffs` alone.
#[test]
fn a_deletion_of_something_changed_preserves_nothing() {
    let t = Temp::new("del-changed");
    let store = Store::open(t.path()).unwrap();
    t.write("f.txt", "original");
    let expected = store.current_state("f.txt").unwrap();
    t.write("f.txt", "someone else's work");

    let outcome = store.remove("f.txt", &expected).unwrap();
    assert!(
        matches!(outcome, bisync::store::Guarded::Changed(_)),
        "{outcome:?}"
    );
    assert_eq!(t.read("f.txt"), "someone else's work");
    assert!(t.kept().is_empty(), "{:?}", t.kept());
}

/// A link's target is its content, so repointing one loses something. Twenty
/// bytes, and it keeps the rule free of exceptions to remember.
#[test]
fn a_repointed_symlink_keeps_its_old_target() {
    let (a, b) = (Temp::new("link-a"), Temp::new("link-b"));
    a.write("one.txt", "one");
    a.write("two.txt", "two");
    a.symlink("current", "one.txt");
    sync(&a, &b);

    b.symlink("current", "two.txt");
    sync(&a, &b);

    assert_eq!(
        std::fs::read_link(a.path().join("current"))
            .unwrap()
            .to_str(),
        Some("two.txt")
    );
    let kept = a.kept_copy("current").expect("the old link was kept");
    let at = a.path().join(&kept);
    assert!(at.symlink_metadata().unwrap().is_symlink());
    assert_eq!(std::fs::read_link(&at).unwrap().to_str(), Some("one.txt"));
}

/// A deleted symlink is preserved as a symlink too, not as a copy of whatever it
/// pointed at.
#[test]
fn a_deleted_symlink_is_kept_as_a_symlink() {
    let (a, b) = (Temp::new("dellink-a"), Temp::new("dellink-b"));
    a.write("target.txt", "content");
    a.symlink("l", "target.txt");
    sync(&a, &b);

    b.remove("l");
    sync(&a, &b);

    assert!(!a.exists("l"));
    let kept = a.kept_copy("l").expect("the deleted link was kept");
    let at = a.path().join(&kept);
    assert!(at.symlink_metadata().unwrap().is_symlink());
    assert_eq!(
        std::fs::read_link(&at).unwrap().to_str(),
        Some("target.txt")
    );
}

/// A conflict puts the two sides in different places, and the distinction is the
/// point: `diffs` is what was replaced here, `quarantine` is what was not
/// applied from there. A frozen path replaces nothing, so it has no `diffs` entry
/// at all.
#[test]
fn a_frozen_path_keeps_nothing_because_nothing_was_replaced() {
    let (a, b) = (Temp::new("frozen-a"), Temp::new("frozen-b"));
    a.write("shared.txt", "common");
    sync(&a, &b);
    a.write("shared.txt", "a's work");
    b.write("shared.txt", "b's work");

    let out = sync(&a, &b);
    assert_eq!(out.conflicts_a(), vec!["shared.txt"]);
    assert_eq!(a.read("shared.txt"), "a's work");
    // The peer's version is held aside, but the local one was never touched.
    assert_eq!(
        a.read(&a.quarantined_copy("shared.txt").unwrap()),
        "b's work"
    );
    assert!(a.kept().is_empty(), "nothing was replaced: {:?}", a.kept());
    assert_eq!(out.a.kept, 0);
}

/// `bisync resolve --remote` replaces the local version with the peer's, which is
/// a replacement like any other.
#[test]
fn resolving_towards_the_peer_keeps_the_local_version() {
    let (a, b) = (Temp::new("resolve-a"), Temp::new("resolve-b"));
    a.write("shared.txt", "common");
    sync(&a, &b);
    a.write("shared.txt", "a's work");
    b.write("shared.txt", "b's work");
    sync(&a, &b);

    bisync::run::resolve(a.path(), &["shared.txt".to_string()], true, false).unwrap();
    assert_eq!(a.read("shared.txt"), "b's work");
    assert_eq!(a.read(&a.kept_copy("shared.txt").unwrap()), "a's work");
}

/// Compression must not change what is kept: the copy is of what was on disk,
/// not of what came off the wire.
#[test]
fn what_is_kept_is_content_not_wire_bytes() {
    let (a, b) = (Temp::new("zkept-a"), Temp::new("zkept-b"));
    let old = "the old line, repeated\n".repeat(3000);
    let new = "the new line, repeated\n".repeat(3000);
    a.write("big.txt", &old);
    reconcile(
        &a,
        &b,
        Settings {
            compress: 9,
            ..Settings::default()
        },
    );

    b.write("big.txt", &new);
    let out = reconcile(
        &a,
        &b,
        Settings {
            compress: 9,
            ..Settings::default()
        },
    );
    assert!(out.a.inbound.saved() > 0, "the transfer was not compressed");

    assert_eq!(a.read("big.txt"), new);
    assert_eq!(a.read(&a.kept_copy("big.txt").unwrap()), old);
}

/// Whatever is kept is under `.bisync`, which is force-ignored, so it never
/// becomes something to sync — and never grows a copy of a copy.
#[test]
fn kept_copies_are_not_themselves_synced() {
    let (a, b) = (Temp::new("noloop-a"), Temp::new("noloop-b"));
    a.write("f.txt", "one");
    sync(&a, &b);
    b.write("f.txt", "two");
    sync(&a, &b);
    assert_eq!(a.kept().len(), 1);

    let out = sync(&a, &b);
    assert_converged(&a, &b);
    assert_eq!(out.a.sent, 0, "a kept copy was offered to the peer");
    assert_eq!(out.a.received, 0);
    assert!(b.kept().is_empty());
    assert!(!b.exists(".bisync/diffs"));
    // Still exactly one, not one per sync.
    assert_eq!(a.kept().len(), 1);
}

// ------------------------------------------------------------------- the store

#[test]
fn keeping_a_copy_preserves_content_and_permissions() {
    let t = Temp::new("store-keep");
    let store = Store::open(t.path()).unwrap();
    t.write("dir/f.txt", "precious");
    t.chmod("dir/f.txt", 0o600);

    let kept = store.preserve("dir/f.txt").unwrap().expect("kept");
    assert_eq!(t.read(&kept), "precious");
    assert_eq!(t.mode(&kept), 0o600);
    // The live file is untouched: it is the one someone is working in.
    assert_eq!(t.read("dir/f.txt"), "precious");

    // Nothing there, nothing kept, and no directory made in the attempt.
    assert_eq!(store.preserve("dir/absent.txt").unwrap(), None);
    assert!(!t.exists(".bisync/diffs/dir/absent.txt"));
    // A directory has no content of its own to preserve.
    assert_eq!(store.preserve("dir").unwrap(), None);
}

#[test]
fn a_replaced_symlink_is_kept_as_a_symlink() {
    let t = Temp::new("store-link");
    let store = Store::open(t.path()).unwrap();
    t.write("target.txt", "pointed at");
    t.symlink("l", "target.txt");

    let kept = store.preserve("l").unwrap().expect("kept");
    let at = t.path().join(&kept);
    assert!(at.symlink_metadata().unwrap().is_symlink());
    assert_eq!(
        std::fs::read_link(&at).unwrap().to_str(),
        Some("target.txt")
    );
}

/// Two copies of one path taken in the same second must not collide: each may be
/// the only remaining version of something.
#[test]
fn two_copies_in_the_same_second_both_survive() {
    let t = Temp::new("store-collide");
    let store = Store::open(t.path()).unwrap();

    t.write("f.txt", "first");
    let one = store.preserve("f.txt").unwrap().unwrap();
    t.write("f.txt", "second");
    let two = store.preserve("f.txt").unwrap().unwrap();
    t.write("f.txt", "third");
    let three = store.preserve("f.txt").unwrap().unwrap();

    assert_ne!(one, two);
    assert_ne!(two, three);
    assert_eq!(t.read(&one), "first");
    assert_eq!(t.read(&two), "second");
    assert_eq!(t.read(&three), "third");
}

/// A placement the guard refuses must leave nothing in `diffs`: the file is
/// still live, so a copy of it is not evidence of anything and would just
/// accumulate. The preservation happens *after* the guard, which is what makes
/// this true rather than something the caller has to undo.
#[test]
fn a_refused_placement_preserves_nothing() {
    let t = Temp::new("store-backout");
    let store = Store::open(t.path()).unwrap();
    t.write("f.txt", "as it was");
    let expected = store.current_state("f.txt").unwrap();

    let content = b"from the peer";
    let mut incoming = store
        .receive(
            1,
            "f.txt",
            Dest::Live,
            bisync::hash::file_digest(content),
            content.len() as u64,
            0o644,
            Stamp::default(),
        )
        .unwrap();
    incoming.write(content).unwrap();
    let sealed = store.seal(incoming).unwrap();

    // Someone edits it before the placement, so the guard refuses.
    t.write("f.txt", "edited meanwhile");
    let Placement::Changed { .. } = store.place(sealed, &expected).unwrap() else {
        panic!("the guard let it through");
    };
    assert!(t.kept().is_empty(), "{:?}", t.kept());
    assert_eq!(t.read("f.txt"), "edited meanwhile");
}

/// A placement the guard allows preserves what it overwrote, and says where.
#[test]
fn an_allowed_placement_preserves_and_reports_it() {
    let t = Temp::new("store-place-keep");
    let store = Store::open(t.path()).unwrap();
    t.write("f.txt", "as it was");
    let expected = store.current_state("f.txt").unwrap();

    let content = b"from the peer";
    let mut incoming = store
        .receive(
            1,
            "f.txt",
            Dest::Live,
            bisync::hash::file_digest(content),
            content.len() as u64,
            0o644,
            Stamp::default(),
        )
        .unwrap();
    incoming.write(content).unwrap();
    let sealed = store.seal(incoming).unwrap();

    let Placement::Done(landed) = store.place(sealed, &expected).unwrap() else {
        panic!("the placement was refused");
    };
    let kept = landed.kept.expect("place did not preserve the old version");
    assert_eq!(t.read(&kept), "as it was");
    assert_eq!(t.read("f.txt"), "from the peer");
}

#[test]
fn the_kept_total_is_reported() {
    let t = Temp::new("store-total");
    let store = Store::open(t.path()).unwrap();
    assert_eq!(store.preserved(), (0, 0));

    t.write("a.txt", "1234567890");
    t.write("deep/b.txt", "12345");
    store.preserve("a.txt").unwrap();
    store.preserve("deep/b.txt").unwrap();
    assert_eq!(store.preserved(), (2, 15));
}

/// A clean run leaves no empty aside directories.
#[test]
fn tidy_removes_the_directory_only_when_it_is_empty() {
    let t = Temp::new("store-tidy");
    let store = Store::open(t.path()).unwrap();
    store.tidy();
    assert!(!t.exists(".bisync/diffs"));

    t.write("f.txt", "content");
    store.preserve("f.txt").unwrap();
    store.tidy();
    assert!(
        t.exists(".bisync/diffs"),
        "tidy removed a copy someone may need"
    );
}

/// A path a peer could name must not be able to place a copy outside `.bisync`.
/// The name goes straight into a path, so this is the same boundary as everywhere
/// else — asserted here because it is a second place that joins one.
#[test]
fn a_kept_copy_cannot_escape_the_control_directory() {
    let t = Temp::new("store-escape");
    let store = Store::open(t.path()).unwrap();
    t.write("f.txt", "content");
    let kept = store.preserve("f.txt").unwrap().unwrap();
    assert!(kept.starts_with(".bisync/diffs/"), "{kept}");
    assert!(!kept.contains(".."), "{kept}");
    assert_eq!(
        bisync::relpath::validate(&kept),
        Ok(()),
        "the kept path is not a usable relative path"
    );
    let _ = PathState::Absent;
}
