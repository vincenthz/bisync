//! One-way sessions, and the diff a dry run can show.

mod common;

use bisync::diff::{self, Kind};
use bisync::merge::Direction;
use bisync::session::{Event, Settings};

use common::{Temp, assert_converged, reconcile, sync};

fn going(direction: Direction) -> Settings {
    Settings {
        direction,
        ..Settings::default()
    }
}

/// A direction names a way along the link, not "away from me". Read as "me" by
/// both ends, `pull` would have both sitting waiting to be given something.
#[test]
fn a_direction_is_mirrored_by_the_other_end() {
    assert_eq!(Direction::Pull.inverted(), Direction::Push);
    assert_eq!(Direction::Push.inverted(), Direction::Pull);
    assert_eq!(Direction::Both.inverted(), Direction::Both);

    assert!(Direction::Both.may_take() && Direction::Both.may_offer());
    assert!(Direction::Pull.may_take() && !Direction::Pull.may_offer());
    assert!(!Direction::Push.may_take() && Direction::Push.may_offer());

    for d in [Direction::Both, Direction::Pull, Direction::Push] {
        assert_eq!(Direction::parse(d.name()), Some(d));
    }
    assert_eq!(Direction::parse("sideways"), None);
    assert_eq!(Direction::default(), Direction::Both);
}

#[test]
fn pulling_takes_the_peers_changes_and_offers_nothing() {
    let (a, b) = (Temp::new("pull-a"), Temp::new("pull-b"));
    a.write("shared.txt", "common");
    a.write("mine.txt", "only here");
    sync(&a, &b);
    b.write("shared.txt", "changed on the peer");
    b.write("theirs.txt", "only there");
    a.write("mine.txt", "changed here");

    let out = reconcile(&a, &b, going(Direction::Pull));

    // Everything the peer had arrives.
    assert_eq!(a.read("shared.txt"), "changed on the peer");
    assert_eq!(a.read("theirs.txt"), "only there");
    // Nothing of ours leaves.
    assert_eq!(b.read("mine.txt"), "only here");
    assert!(out.a.sent == 0, "a sent {} files", out.a.sent);
    assert!(out.a.declined > 0);
    // And the base did not advance for what was not offered, so a later full
    // sync still finds it. This is the part that makes a one-way run safe.
    assert_ne!(out.state_a.base_of("mine.txt"), a_state(&a, "mine.txt"));

    let out = sync(&a, &b);
    assert_eq!(b.read("mine.txt"), "changed here");
    assert_eq!(out.a.sent, 1);
    assert_converged(&a, &b);
}

#[test]
fn pushing_offers_ours_and_takes_nothing() {
    let (a, b) = (Temp::new("push-a"), Temp::new("push-b"));
    a.write("shared.txt", "common");
    sync(&a, &b);
    a.write("shared.txt", "changed here");
    b.write("theirs.txt", "only there");

    let out = reconcile(&a, &b, going(Direction::Push));

    assert_eq!(b.read("shared.txt"), "changed here");
    assert!(
        !a.exists("theirs.txt"),
        "a took something in a push-only session"
    );
    assert_eq!(out.a.received, 0);
    assert!(out.a.declined > 0);

    // The peer's change is still pending, not forgotten.
    let out = sync(&a, &b);
    assert_eq!(a.read("theirs.txt"), "only there");
    assert_eq!(out.a.received, 1);
    assert_converged(&a, &b);
}

/// A one-way session must not resolve a conflict by walking past it: both sides
/// changed, and which one wins is not a question a direction answers.
#[test]
fn a_one_way_session_does_not_settle_conflicts() {
    for direction in [Direction::Pull, Direction::Push] {
        let (a, b) = (Temp::new("conf-a"), Temp::new("conf-b"));
        a.write("shared.txt", "common");
        sync(&a, &b);
        a.write("shared.txt", "a's work");
        b.write("shared.txt", "b's work");

        let out = reconcile(&a, &b, going(direction));
        assert_eq!(a.read("shared.txt"), "a's work", "{direction:?}");
        assert_eq!(b.read("shared.txt"), "b's work", "{direction:?}");
        assert_eq!(out.conflicts_a(), vec!["shared.txt"], "{direction:?}");
    }
}

/// Deletions are changes like any other, and follow the direction.
#[test]
fn deletions_follow_the_direction() {
    let (a, b) = (Temp::new("del-a"), Temp::new("del-b"));
    a.write("theirs.txt", "will go on the peer");
    a.write("ours.txt", "will go here");
    sync(&a, &b);
    b.remove("theirs.txt");
    a.remove("ours.txt");

    reconcile(&a, &b, going(Direction::Pull));
    // Their deletion arrives; ours is not offered.
    assert!(!a.exists("theirs.txt"));
    assert!(b.exists("ours.txt"));
    // And the file they deleted here was kept, as any replaced version is.
    assert_eq!(
        a.read(&a.kept_copy("theirs.txt").unwrap()),
        "will go on the peer"
    );
}

/// With nothing to do, a one-way session is as quiet as a two-way one — the
/// direction filters decisions, it does not manufacture them.
#[test]
fn a_one_way_session_on_an_unchanged_tree_does_nothing() {
    let (a, b) = (Temp::new("quiet-a"), Temp::new("quiet-b"));
    a.write("f.txt", "content");
    sync(&a, &b);

    for direction in [Direction::Pull, Direction::Push] {
        let out = reconcile(&a, &b, going(direction));
        assert_eq!(out.a.sent + out.a.received, 0, "{direction:?}");
        assert_eq!(out.a.declined, 0, "{direction:?}");
        assert!(
            out.messages <= 6,
            "{direction:?}: {} messages",
            out.messages
        );
    }
}

// ------------------------------------------------------------------- the diff

#[test]
fn a_diff_shows_the_lines_that_changed() {
    let change = diff::compare(b"one\ntwo\nthree\n", b"one\nTWO\nthree\nfour\n", 3);
    assert_eq!(change.kind, Kind::Text);
    assert_eq!(change.added, 2);
    assert_eq!(change.removed, 1);
    assert!(change.text.contains("-two"), "{}", change.text);
    assert!(change.text.contains("+TWO"), "{}", change.text);
    assert!(change.text.contains("+four"), "{}", change.text);
    assert!(change.text.contains(" three"), "{}", change.text);
    assert!(change.text.contains("@@"), "{}", change.text);
}

#[test]
fn identical_content_has_no_diff() {
    let change = diff::compare(b"same\n", b"same\n", 3);
    assert_eq!(change.kind, Kind::Same);
    assert_eq!((change.added, change.removed), (0, 0));
    assert!(change.text.is_empty());
}

/// A diff of two binaries is either noise or a lie about what changed.
#[test]
fn binary_content_is_not_diffed() {
    let change = diff::compare(b"text\0with a nul\n", b"text\0other\n", 3);
    assert_eq!(change.kind, Kind::Binary);
    assert!(change.text.is_empty());
    // Invalid UTF-8 likewise.
    let change = diff::compare(&[0xff, 0xfe, 0x01], &[0xff, 0xfe, 0x02], 3);
    assert_eq!(change.kind, Kind::Binary);
}

/// The common head and tail are trimmed before the quadratic part, which is what
/// keeps a one-line change in a long file affordable.
#[test]
fn a_small_change_in_a_large_file_is_still_diffed() {
    let mut old: Vec<String> = (0..20_000).map(|i| format!("line {i}")).collect();
    let new = old.clone();
    old[10_000] = "changed".to_string();
    let change = diff::compare(old.join("\n").as_bytes(), new.join("\n").as_bytes(), 1);
    assert_eq!(
        change.kind,
        Kind::Text,
        "trimming did not reduce the region"
    );
    assert_eq!((change.added, change.removed), (1, 1));
    // Context only, not twenty thousand lines of it.
    assert!(change.text.lines().count() < 10, "{}", change.text);
}

/// Two files that share nothing are reported as a count rather than expanded: an
/// LCS table over them is gigabytes to describe a diff nobody would read.
#[test]
fn a_wholly_different_large_file_is_summarised() {
    let old: Vec<String> = (0..3000).map(|i| format!("old {i}")).collect();
    let new: Vec<String> = (0..3000).map(|i| format!("new {i}")).collect();
    let change = diff::compare(old.join("\n").as_bytes(), new.join("\n").as_bytes(), 3);
    assert_eq!(change.kind, Kind::TooLarge);
    assert_eq!(change.added, 3000);
    assert_eq!(change.removed, 3000);
    assert!(change.text.is_empty());
}

#[test]
fn line_numbers_count_from_the_start_of_the_file() {
    let old = "a\nb\nc\nd\ne\nf\ng\nh\n";
    let new = "a\nb\nc\nd\ne\nf\ng\nCHANGED\n";
    let change = diff::compare(old.as_bytes(), new.as_bytes(), 1);
    // The change is on line 8, so the hunk header must say so rather than
    // numbering from the trimmed region.
    assert!(change.text.contains("@@ -7,2 +7,2 @@"), "{}", change.text);
}

/// The point of the whole thing: a dry run that says what a file would become,
/// having fetched the peer's version to find out, and written nothing anywhere.
#[test]
fn a_dry_run_can_diff_what_would_arrive() {
    let (a, b) = (Temp::new("diff-a"), Temp::new("diff-b"));
    a.write("f.txt", "one\ntwo\nthree\n");
    a.write("gone.txt", "will be deleted on the peer");
    sync(&a, &b);
    b.write("f.txt", "one\nTWO\nthree\nfour\n");
    b.write("new.txt", "arrived from the peer");
    b.remove("gone.txt");

    let before_a = a.list();
    let before_b = b.list();
    let out = reconcile(
        &a,
        &b,
        Settings {
            dry_run: true,
            diff: true,
            ..Settings::default()
        },
    );

    // Nothing moved, on either side. The second half is what a dry run used to
    // get wrong: the peer applies and requests on its own initiative.
    assert_eq!(a.list(), before_a);
    assert_eq!(b.list(), before_b);
    assert_eq!(a.read("f.txt"), "one\ntwo\nthree\n");
    assert!(out.state_a.base.is_empty() || out.state_a.base_of("new.txt").is_absent());

    let diffs: Vec<&Event> = out
        .events_a
        .iter()
        .filter(|e| matches!(e, Event::Diff { .. }))
        .collect();
    let Some(Event::Diff { path, change, .. }) = diffs.first().copied() else {
        panic!("no diff reported: {:?}", out.events_a);
    };
    assert_eq!(path, "f.txt");
    assert_eq!(change.kind, Kind::Text);
    assert!(change.text.contains("+TWO"), "{}", change.text);
    assert!(change.text.contains("+four"), "{}", change.text);
    // A file arriving for the first time, and one being deleted, have no diff to
    // show — they are reported as `would` lines instead.
    assert_eq!(diffs.len(), 1, "{diffs:?}");
}

/// A dry run with no `--diff` fetches nothing at all: the diff is what costs the
/// transfer, so it has to be asked for.
#[test]
fn a_plain_dry_run_transfers_nothing() {
    let (a, b) = (Temp::new("nodiff-a"), Temp::new("nodiff-b"));
    a.write("f.txt", "one\n");
    sync(&a, &b);
    b.write("f.txt", "two\n");

    let out = reconcile(
        &a,
        &b,
        Settings {
            dry_run: true,
            ..Settings::default()
        },
    );
    assert_eq!(out.a.inbound.plain, 0, "content was fetched without --diff");
    assert!(!out.events_a.iter().any(|e| matches!(e, Event::Diff { .. })));
    assert_eq!(a.read("f.txt"), "one\n");
}

/// A dry run must leave both bases where they were, or a later real sync would
/// skip the very changes the dry run described.
#[test]
fn a_dry_run_does_not_advance_either_base() {
    let (a, b) = (Temp::new("base-a"), Temp::new("base-b"));
    a.write("f.txt", "one\n");
    sync(&a, &b);
    b.write("f.txt", "two\n");
    a.write("g.txt", "ours\n");

    // The base, not the whole state file: a dry run does rescan, so the index
    // legitimately moves. What must not move is the record of what the two ends
    // have agreed on.
    let base = |t: &Temp, peer: &Temp| {
        bisync::state::State::load(
            &t.path().join(".bisync/state"),
            &peer.path().display().to_string(),
        )
        .unwrap()
        .0
        .base
    };
    let before_a = base(&a, &b);
    let before_b = base(&b, &a);
    reconcile(
        &a,
        &b,
        Settings {
            dry_run: true,
            diff: true,
            ..Settings::default()
        },
    );
    assert_eq!(base(&a, &b), before_a, "a's base moved");
    assert_eq!(base(&b, &a), before_b, "b's base moved");

    // And the real sync afterwards does everything the dry run described.
    let out = sync(&a, &b);
    assert_eq!(a.read("f.txt"), "two\n");
    assert_eq!(b.read("g.txt"), "ours\n");
    assert_eq!(out.a.received, 1);
    assert_eq!(out.a.sent, 1);
    assert_converged(&a, &b);
}

fn a_state(t: &Temp, rel: &str) -> bisync::tree::PathState {
    bisync::store::Store::open(t.path())
        .unwrap()
        .current_state(rel)
        .unwrap()
}
