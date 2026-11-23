//! `unisync`: what a comparison proposes, what an answer does about it, and what
//! neither of them can be talked into.
//!
//! Two sessions are wired to each other's inboxes with no transport at all,
//! which is the whole protocol — if a run works here it works over ssh, because
//! the only difference is who copies the bytes between the two `Vec<Msg>`.

mod common;

use bisync::hash::file_digest;
use bisync::proto::Msg;
use bisync::store::{self, Store};
use bisync::tree::PathState;
use bisync::uni::plan::{Skip, Step, Way};
use bisync::uni::session::{Event, Phase, Role, Session, Settings, Stats};

use common::Temp;

/// What one run came to.
struct Outcome {
    plan: Vec<Step>,
    skipped: Vec<Skip>,
    /// The side the run was started from.
    local: Stats,
    peer: Stats,
    events: Vec<Event>,
}

impl Outcome {
    fn paths(&self) -> Vec<&str> {
        self.plan.iter().map(|s| s.path.as_str()).collect()
    }

    fn skipped_path(&self, path: &str) -> Option<&Skip> {
        self.skipped.iter().find(|s| s.path == path)
    }
}

fn settings(way: Way, delete: bool) -> Settings {
    Settings {
        way,
        delete,
        ..Settings::default()
    }
}

/// Compare two roots and answer every proposed step with `choose`.
fn run(
    local: &Temp,
    peer: &Temp,
    way: Way,
    delete: bool,
    choose: impl Fn(&Step) -> bool,
) -> Outcome {
    run_with(local, peer, settings(way, delete), choose, || {})
}

/// The same, with the terms spelled out and a chance to meddle with the tree
/// between the plan being made and it being carried out — which is the window
/// every guard in the store exists for.
fn run_with(
    local: &Temp,
    peer: &Temp,
    settings: Settings,
    choose: impl Fn(&Step) -> bool,
    meddle: impl FnOnce(),
) -> Outcome {
    let mut store_local = Store::open_at(local.path(), store::UNI_CONTROL).unwrap();
    let mut store_peer = Store::open_at(peer.path(), store::UNI_CONTROL).unwrap();
    let mut events = Vec::new();

    let mut here = Session::new(Role::Initiator, settings, &mut store_local);
    let mut there = Session::new(Role::Responder, Settings::default(), &mut store_peer);
    here.scan().unwrap();
    here.open();
    converse(&mut here, &mut there, &mut events);

    assert!(
        matches!(here.phase(), Phase::Deciding | Phase::Done),
        "the comparison did not finish: {:?}",
        here.phase()
    );
    let plan = here.take_plan();
    let accepted: Vec<Step> = plan.steps.iter().filter(|s| choose(s)).cloned().collect();
    meddle();
    here.commit(accepted).unwrap();
    converse(&mut here, &mut there, &mut events);
    here.say_bye();
    converse(&mut here, &mut there, &mut events);

    assert_eq!(here.failure(), None, "the local end failed");
    assert_eq!(there.failure(), None, "the peer failed");
    Outcome {
        plan: plan.steps,
        skipped: plan.skipped,
        local: here.stats().clone(),
        peer: there.stats().clone(),
        events,
    }
}

/// Hand each end whatever the other has to say until neither has anything left.
fn converse(here: &mut Session<'_>, there: &mut Session<'_>, events: &mut Vec<Event>) {
    for _ in 0..100_000 {
        let from_here = here.take_out();
        let from_there = there.take_out();
        let spoke = !from_here.is_empty() || !from_there.is_empty();
        for msg in from_here {
            there.handle(msg).unwrap();
        }
        for msg in from_there {
            here.handle(msg).unwrap();
        }
        let pumping_here = here.pump().unwrap();
        let pumping_there = there.pump().unwrap();
        here.settle();
        there.settle();
        events.extend(here.take_events());
        events.extend(there.take_events());
        if !spoke && !pumping_here && !pumping_there {
            return;
        }
    }
    panic!("the two ends never stopped talking");
}

#[test]
fn a_pull_takes_what_was_accepted_and_leaves_the_rest_alone() {
    let (here, peer) = (Temp::new("pull-here"), Temp::new("pull-peer"));
    peer.write("wanted.txt", "from the peer");
    peer.write("declined.txt", "also from the peer");
    peer.write("shared.txt", "the same on both");
    here.write("shared.txt", "the same on both");
    here.write("mine.txt", "only here");

    let out = run(&here, &peer, Way::Pull, false, |step| {
        step.path == "wanted.txt"
    });

    assert_eq!(out.paths(), ["declined.txt", "wanted.txt"]);
    assert_eq!(here.read("wanted.txt"), "from the peer");
    assert!(!here.exists("declined.txt"), "a declined change happened");
    assert!(
        peer.exists("declined.txt"),
        "the peer's own copy was touched"
    );
    assert_eq!(out.local.received, 1);
    assert_eq!(out.peer.sent, 1);

    // A file only this side has is not a difference anyone asked to act on.
    assert_eq!(here.read("mine.txt"), "only here");
    assert!(out.skipped_path("mine.txt").is_some());
}

#[test]
fn nothing_is_removed_unless_removing_was_asked_for() {
    let (here, peer) = (Temp::new("del-here"), Temp::new("del-peer"));
    here.write("extra.txt", "only here");
    here.write("shared.txt", "same");
    peer.write("shared.txt", "same");

    let out = run(&here, &peer, Way::Pull, false, |_| true);
    assert!(out.plan.is_empty(), "{:?} was proposed", out.paths());
    assert!(here.exists("extra.txt"));
    let skip = out.skipped_path("extra.txt").expect("reported as left out");
    assert!(skip.why.contains("--delete"), "{}", skip.why);

    let out = run(&here, &peer, Way::Pull, true, |_| true);
    assert_eq!(out.paths(), ["extra.txt"]);
    assert!(!here.exists("extra.txt"));
    assert_eq!(out.local.deleted, 1);
    // And what was removed is still on disk, which is the difference between
    // this and `rm`.
    let kept = here.preserved_under(".unisync");
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert!(kept[0].contains("extra.txt"), "{kept:?}");
}

#[test]
fn a_push_writes_into_the_peer_and_takes_nothing_back() {
    let (here, peer) = (Temp::new("push-here"), Temp::new("push-peer"));
    here.write("new.txt", "ours");
    here.write("shared.txt", "ours, changed");
    here.write("deep/inside/file.txt", "ours, nested");
    peer.write("shared.txt", "theirs");
    peer.write("theirs.txt", "only there");

    let out = run(&here, &peer, Way::Push, false, |_| true);

    assert_eq!(peer.read("new.txt"), "ours");
    assert_eq!(peer.read("shared.txt"), "ours, changed");
    assert_eq!(peer.read("deep/inside/file.txt"), "ours, nested");
    assert_eq!(out.local.sent, 3);
    assert_eq!(out.peer.received, 3);
    // Every change the peer carried out is acknowledged, directories included.
    assert_eq!(out.local.pushed, out.plan.len());
    assert_eq!(out.peer.created, 2, "deep/ and deep/inside/");

    // Nothing came back, and the peer's own file is where it was.
    assert!(!here.exists("theirs.txt"));
    assert_eq!(peer.read("theirs.txt"), "only there");
    assert_eq!(out.local.received, 0);
    // The peer kept the version it replaced.
    let kept = peer.preserved_under(".unisync");
    assert!(
        kept.iter().any(|p| p.contains("shared.txt")),
        "the peer replaced a file without keeping it: {kept:?}"
    );
}

#[test]
fn identical_trees_are_settled_by_the_handshake_alone() {
    let (here, peer) = (Temp::new("same-here"), Temp::new("same-peer"));
    for tree in [&here, &peer] {
        tree.write("a.txt", "one");
        tree.write("nested/b.txt", "two");
    }

    let out = run(&here, &peer, Way::Pull, true, |_| true);
    assert!(out.plan.is_empty());
    assert!(out.skipped.is_empty());
    // The root digests matched, so not one directory was ever listed.
    assert_eq!(out.peer.dirs_listed, 0);
    assert!(
        out.events
            .iter()
            .any(|e| matches!(e, Event::Info(text) if text.contains("identical"))),
        "nobody said so"
    );
}

#[test]
fn only_the_subtrees_that_differ_are_walked() {
    let (here, peer) = (Temp::new("descend-here"), Temp::new("descend-peer"));
    for tree in [&here, &peer] {
        for n in 0..8 {
            tree.write(&format!("dir{n}/file.txt", n = n), "unchanged");
            tree.write(&format!("dir{n}/deeper/file.txt", n = n), "unchanged");
        }
    }
    peer.write("dir3/deeper/file.txt", "changed on the peer");

    let out = run(&here, &peer, Way::Pull, false, |_| true);

    assert_eq!(out.paths(), ["dir3/deeper/file.txt"]);
    // The root, `dir3`, and `dir3/deeper`. The other seven subtrees were settled
    // by one digest comparison each and never opened.
    assert_eq!(out.peer.dirs_listed, 3);
}

#[test]
fn a_path_that_moved_since_the_plan_is_not_written_over() {
    let (here, peer) = (Temp::new("moved-here"), Temp::new("moved-peer"));
    here.write("contested.txt", "what the plan was made about");
    peer.write("contested.txt", "what the peer has");

    let out = run_with(
        &here,
        &peer,
        settings(Way::Pull, false),
        |_| true,
        // Someone saves the file between the question and the answer being
        // acted on. The guard re-reads it, finds it is not what was proposed,
        // and refuses.
        || here.write("contested.txt", "edited while the run was thinking"),
    );

    assert_eq!(out.paths(), ["contested.txt"]);
    assert_eq!(
        here.read("contested.txt"),
        "edited while the run was thinking"
    );
    assert_eq!(out.local.received, 0);
    assert_eq!(out.local.refused, 1);
    // The transfer had already happened, so the peer's copy is kept rather than
    // thrown away.
    assert!(
        out.events
            .iter()
            .any(|e| matches!(e, Event::Warn(text) if text.contains("during the transfer"))),
        "{:?}",
        out.events
    );
}

#[test]
fn the_peers_copy_can_be_fetched_for_a_diff_without_touching_the_tree() {
    let (here, peer) = (Temp::new("diff-here"), Temp::new("diff-peer"));
    here.write("notes.txt", "one\ntwo\n");
    peer.write("notes.txt", "one\ntwo\nthree\n");

    let mut store_here = Store::open_at(here.path(), store::UNI_CONTROL).unwrap();
    let mut store_peer = Store::open_at(peer.path(), store::UNI_CONTROL).unwrap();
    let mut events = Vec::new();
    let mut a = Session::new(Role::Initiator, settings(Way::Pull, false), &mut store_here);
    let mut b = Session::new(Role::Responder, Settings::default(), &mut store_peer);
    a.scan().unwrap();
    a.open();
    converse(&mut a, &mut b, &mut events);

    let plan = a.take_plan();
    let step = &plan.steps[0];
    assert!(step.is_diffable());
    a.inspect(&step.path, step.source_digest().unwrap());
    converse(&mut a, &mut b, &mut events);

    let fetched = a.take_inspected().expect("an answer either way");
    assert_eq!(fetched.path, "notes.txt");
    assert_eq!(
        fetched.content.as_deref(),
        Some(&b"one\ntwo\nthree\n"[..]),
        "the peer's copy did not arrive"
    );
    // Looking is not taking: the tree is as it was, and nothing was left in the
    // control directory either.
    assert_eq!(here.read("notes.txt"), "one\ntwo\n");
    assert_eq!(a.stats().received, 0);
    assert!(here.preserved_under(".unisync").is_empty());
}

#[test]
fn a_file_over_the_size_limit_here_is_never_written_over() {
    let (here, peer) = (Temp::new("big-here"), Temp::new("big-peer"));
    here.write("big.bin", &"x".repeat(500));
    peer.write("big.bin", "small");

    let out = run_with(
        &here,
        &peer,
        Settings {
            max_size: 64,
            ..settings(Way::Pull, true)
        },
        |_| true,
        || {},
    );

    // The scan leaves it out of the index, so the comparison sees nothing here —
    // which is exactly the reading that would have overwritten it.
    assert!(out.plan.is_empty(), "{:?}", out.paths());
    let skip = out.skipped_path("big.bin").expect("reported as left out");
    assert!(skip.why.contains("size limit"), "{}", skip.why);
    assert_eq!(here.read("big.bin").len(), 500);
}

#[test]
fn a_directory_replacing_a_file_and_a_file_replacing_a_directory() {
    let (here, peer) = (Temp::new("retype-here"), Temp::new("retype-peer"));
    here.write("swap", "a file here");
    peer.write("swap/inside.txt", "a directory there");
    here.write("other/inside.txt", "a directory here");
    peer.write("other", "a file there");

    let out = run(&here, &peer, Way::Pull, true, |_| true);

    assert_eq!(here.read("swap/inside.txt"), "a directory there");
    assert_eq!(here.read("other"), "a file there");
    // Both of the local versions survive somewhere.
    let kept = here.preserved_under(".unisync");
    assert!(kept.iter().any(|p| p.contains("swap")), "{kept:?}");
    assert!(
        kept.iter().any(|p| p.contains("other/inside.txt")),
        "{kept:?}"
    );
    // The one thing deleted is the file inside the directory that gave way; the
    // file that became a directory was replaced rather than removed. Counted
    // once each — emptying a directory deals with entries that are steps in
    // their own right, and doing both would report and count them twice.
    assert_eq!(out.local.deleted, 1, "{:?}", out.events);
    let removals = out
        .events
        .iter()
        .filter(
            |e| matches!(e, Event::Change { verb: "del", path, .. } if path == "other/inside.txt"),
        )
        .count();
    assert_eq!(removals, 1, "{:?}", out.events);
}

#[test]
fn replacing_a_directory_needs_deleting_to_have_been_asked_for() {
    let (here, peer) = (Temp::new("keep-here"), Temp::new("keep-peer"));
    here.write("thing/inside.txt", "work in progress");
    peer.write("thing", "a file there");

    let out = run(&here, &peer, Way::Pull, false, |_| true);

    assert!(out.plan.is_empty(), "{:?}", out.paths());
    assert_eq!(here.read("thing/inside.txt"), "work in progress");
    let skip = out.skipped_path("thing").expect("reported as left out");
    assert!(skip.why.contains("--delete"), "{}", skip.why);
}

#[cfg(unix)]
#[test]
fn a_symlink_arrives_as_a_symlink() {
    let (here, peer) = (Temp::new("link-here"), Temp::new("link-peer"));
    peer.write("target.txt", "pointed at");
    peer.symlink("pointer", "target.txt");

    run(&here, &peer, Way::Pull, false, |_| true);

    let at = here.path().join("pointer");
    assert!(at.symlink_metadata().unwrap().is_symlink());
    assert_eq!(
        std::fs::read_link(&at).unwrap().to_str(),
        Some("target.txt")
    );
}

#[test]
fn a_peer_that_is_not_unisync_is_refused_before_anything_happens() {
    let peer = Temp::new("wrong-peer");
    peer.write("a.txt", "one");
    let mut store = Store::open_at(peer.path(), store::UNI_CONTROL).unwrap();
    let mut responder = Session::new(Role::Responder, Settings::default(), &mut store);

    responder
        .handle(Msg::Hello {
            version: bisync::proto::VERSION,
            program: "bisync 0.1.0".to_string(),
            max_size: 1 << 20,
            ignore: Vec::new(),
            policy: bisync::merge::Policy::default(),
            direction: bisync::merge::Direction::Push,
            dry_run: false,
            compress: 0,
            watch: false,
        })
        .unwrap();

    let failure = responder.failure().expect("a refusal");
    assert!(failure.contains("unisync server"), "{failure}");
    // And the far end is told, rather than being left waiting for a `Welcome`.
    let out = responder.take_out();
    assert!(
        matches!(out.first(), Some(Msg::Error { .. })),
        "{:?}",
        out.iter().map(Msg::name).collect::<Vec<_>>()
    );
}

#[test]
fn permissions_travel_without_the_file_doing_so() {
    if cfg!(not(unix)) {
        return;
    }
    let (here, peer) = (Temp::new("mode-here"), Temp::new("mode-peer"));
    here.write("script.sh", "#!/bin/sh\n");
    peer.write("script.sh", "#!/bin/sh\n");
    #[cfg(unix)]
    peer.chmod("script.sh", 0o755);

    let out = run(&here, &peer, Way::Pull, false, |_| true);

    assert_eq!(out.paths(), ["script.sh"]);
    assert_eq!(out.plan[0].verb(), "chmod");
    assert!(!out.plan[0].needs_content());
    #[cfg(unix)]
    assert_eq!(here.mode("script.sh"), 0o755);
    // Nothing was transferred to change one octal digit.
    assert_eq!(out.local.received, 0);
    assert_eq!(out.peer.sent, 0);
}

#[test]
fn what_arrives_is_checked_against_what_was_promised() {
    // The digest a step names is the digest the receiver enforces: content that
    // hashes to anything else never leaves the temporary directory. Here the
    // step is doctored to ask for a digest the peer does not have, which the
    // peer answers by refusing rather than by sending something else.
    let (here, peer) = (Temp::new("verify-here"), Temp::new("verify-peer"));
    peer.write("a.txt", "the peer's bytes");

    let mut store_here = Store::open_at(here.path(), store::UNI_CONTROL).unwrap();
    let mut store_peer = Store::open_at(peer.path(), store::UNI_CONTROL).unwrap();
    let mut events = Vec::new();
    let mut a = Session::new(Role::Initiator, settings(Way::Pull, false), &mut store_here);
    let mut b = Session::new(Role::Responder, Settings::default(), &mut store_peer);
    a.scan().unwrap();
    a.open();
    converse(&mut a, &mut b, &mut events);

    let mut plan = a.take_plan();
    plan.steps[0].to = PathState::File {
        digest: file_digest(b"something else entirely"),
        size: 16,
        mode: 0o644,
    };
    a.commit(plan.steps).unwrap();
    converse(&mut a, &mut b, &mut events);

    assert!(
        !here.exists("a.txt"),
        "content arrived under a false digest"
    );
    assert_eq!(a.stats().received, 0);
    assert!(a.stats().refused > 0);
}
