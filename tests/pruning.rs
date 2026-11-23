//! `bisync prune`: removing preserved versions from `.bisync/diffs`.
//!
//! Everything in there is a copy of something a sync was about to destroy, so
//! the tests here are as much about what prune leaves alone as about what it
//! removes.

mod common;

use std::time::Duration;

use bisync::run::{self, Prune};
use bisync::store::Store;
use bisync::tree::Stamp;
use bisync::util;

use common::{Temp, sync};

fn quiet() -> run::Overrides {
    run::Overrides {
        quiet: true,
        ..run::Overrides::default()
    }
}

fn dry() -> run::Overrides {
    run::Overrides {
        dry_run: true,
        quiet: true,
        ..run::Overrides::default()
    }
}

/// Put a version into `diffs` by hand, with a chosen age. Prune reads the time
/// out of the name, so this is how a test gets an old one without waiting.
fn plant(t: &Temp, of: &str, ago: Duration, content: &str) -> String {
    let when = Stamp {
        secs: util::now().secs - ago.as_secs() as i64,
        nanos: 0,
    };
    let at = format!(".bisync/diffs/{of}.{}", util::format_compact(when));
    t.write(&at, content);
    at
}

const DAY: Duration = Duration::from_secs(86_400);

#[test]
fn a_timestamp_survives_the_round_trip_through_a_name() {
    for secs in [0i64, 1, 1_775_000_000, 2_000_000_000, -86_400, -1] {
        let stamp = Stamp { secs, nanos: 0 };
        let text = util::format_compact(stamp);
        assert_eq!(util::parse_compact(&text), Some(stamp), "{text}");
    }
    // A known value, so a change to either half is caught rather than cancelling
    // out against the other.
    assert_eq!(
        util::format_compact(Stamp {
            secs: 1_775_000_000,
            nanos: 0
        }),
        "20260331T233320Z"
    );
    assert_eq!(
        util::parse_compact("20260331T233320Z"),
        Some(Stamp {
            secs: 1_775_000_000,
            nanos: 0
        })
    );
    // A leap day, since that is where a calendar conversion goes wrong.
    assert_eq!(
        util::parse_compact("20240229T120000Z").map(|s| s.secs),
        Some(1_709_208_000)
    );
}

#[test]
fn a_name_that_is_not_a_timestamp_is_refused() {
    for bad in [
        "",
        "20260821T140311",
        "20260821T140311ZZ",
        "20260821140311Z",
        "2026081T140311Z",
        "abcdefghTijklmnZ",
        "20261321T140311Z",
        "20260832T140311Z",
        "20260821T250311Z",
        "20260821T146011Z",
    ] {
        assert_eq!(util::parse_compact(bad), None, "{bad:?}");
    }
}

#[test]
fn durations_parse_and_render() {
    assert_eq!(util::parse_duration("90"), Some(Duration::from_secs(90)));
    assert_eq!(util::parse_duration("90s"), Some(Duration::from_secs(90)));
    assert_eq!(util::parse_duration("30m"), Some(Duration::from_secs(1800)));
    assert_eq!(
        util::parse_duration("12h"),
        Some(Duration::from_secs(43_200))
    );
    assert_eq!(
        util::parse_duration("7d"),
        Some(Duration::from_secs(604_800))
    );
    assert_eq!(
        util::parse_duration("2w"),
        Some(Duration::from_secs(1_209_600))
    );
    assert_eq!(
        util::parse_duration(" 3 days "),
        Some(Duration::from_secs(259_200))
    );

    for bad in ["", "d", "-1d", "1y", "3months", "soon", "1.5d"] {
        assert_eq!(util::parse_duration(bad), None, "{bad:?}");
    }
    // Round trip through the largest exact unit.
    assert_eq!(util::format_duration(Duration::from_secs(604_800)), "1w");
    assert_eq!(util::format_duration(Duration::from_secs(86_400)), "1d");
    assert_eq!(util::format_duration(Duration::from_secs(129_600)), "36h");
    assert_eq!(util::format_duration(Duration::from_secs(90)), "90s");
}

/// A listing reports, for each copy, the tree path it belongs to and when it was
/// taken — both read back out of the name, which is where the sync put them.
#[test]
fn a_listing_says_what_each_copy_is_a_version_of() {
    let t = Temp::new("list");
    let store = Store::open(t.path()).unwrap();
    assert!(store.list_preserved().is_empty());

    plant(&t, "src/main.rs", 3 * DAY, "three days ago");
    plant(&t, "src/main.rs", DAY, "yesterday");
    plant(&t, "notes.md", 2 * DAY, "two days ago");
    t.write(".bisync/diffs/put-here-by-hand", "not ours");

    let kept = store.list_preserved();
    assert_eq!(kept.len(), 4);

    // Grouped by path, oldest first within a group.
    let mains: Vec<&bisync::store::Kept> = kept.iter().filter(|k| k.of == "src/main.rs").collect();
    assert_eq!(mains.len(), 2);
    assert!(mains[0].when.unwrap().secs < mains[1].when.unwrap().secs);
    assert_eq!(t.read(&mains[0].at), "three days ago");
    assert_eq!(t.read(&mains[1].at), "yesterday");

    // A name that carries no timestamp is a version of itself at no known time,
    // rather than being left out of the listing.
    let stray = kept
        .iter()
        .find(|k| k.of == "put-here-by-hand")
        .expect("listed");
    assert_eq!(stray.when, None);

    let (count, bytes) = store.preserved();
    assert_eq!(count, 4);
    assert_eq!(bytes, kept.iter().map(|k| k.size).sum::<u64>());
}

/// The collision suffix a second copy in the same second gets sits after the
/// timestamp, so it has to come off before the timestamp can be read.
#[test]
fn a_collision_suffix_does_not_hide_the_timestamp() {
    let t = Temp::new("collide-list");
    let store = Store::open(t.path()).unwrap();
    let base = plant(&t, "f.txt", DAY, "first");
    t.write(&format!("{base}.1"), "second");
    t.write(&format!("{base}.2"), "third");

    let kept = store.list_preserved();
    assert_eq!(kept.len(), 3);
    for version in &kept {
        assert_eq!(version.of, "f.txt", "{}", version.at);
        assert!(version.when.is_some(), "{}", version.at);
    }
    // And they order oldest-first by the suffix, which is assigned in order.
    let names: Vec<&str> = kept.iter().map(|k| k.at.as_str()).collect();
    assert_eq!(
        names,
        vec![base.as_str(), &format!("{base}.1"), &format!("{base}.2")]
    );
}

/// A file whose *name* looks recent but whose mtime is old, and the reverse: the
/// name is what counts, because `fs::copy` does not carry a source's timestamp
/// across on every platform.
#[test]
fn age_comes_from_the_name_not_the_mtime() {
    let t = Temp::new("byname");
    let store = Store::open(t.path()).unwrap();
    // Written just now, but named as though it were ancient.
    let old = plant(&t, "f.txt", 400 * DAY, "old by name");
    let fresh = plant(&t, "g.txt", Duration::from_secs(0), "new by name");

    run::prune(t.path(), Prune::OlderThan(30 * DAY), &quiet()).unwrap();
    assert!(!t.exists(&old), "the name said it was old");
    assert!(t.exists(&fresh), "the name said it was new");
    let _ = store;
}

#[test]
fn older_than_removes_only_what_is_older() {
    let t = Temp::new("older");
    let ancient = plant(&t, "a.txt", 90 * DAY, "ancient");
    let old = plant(&t, "b.txt", 40 * DAY, "old");
    let recent = plant(&t, "c.txt", 3 * DAY, "recent");
    let undated = ".bisync/diffs/mystery";
    t.write(undated, "no timestamp");

    let code = run::prune(t.path(), Prune::OlderThan(30 * DAY), &quiet()).unwrap();
    assert_eq!(code, 0);
    assert!(!t.exists(&ancient));
    assert!(!t.exists(&old));
    assert!(t.exists(&recent));
    // Nothing shows this one to be old, so it stays. `--all` is how to be rid
    // of it, which is a decision rather than a side effect.
    assert!(t.exists(undated));
}

#[test]
fn keeping_the_newest_n_drops_the_rest_per_path() {
    let t = Temp::new("keepn");
    let mut f = Vec::new();
    for days in [5u64, 4, 3, 2, 1] {
        f.push(plant(
            &t,
            "f.txt",
            Duration::from_secs(days * 86_400),
            &format!("f {days}"),
        ));
    }
    let g = plant(&t, "g.txt", 9 * DAY, "the only g");

    run::prune(t.path(), Prune::KeepNewest(2), &quiet()).unwrap();

    // The three oldest of `f` go, the two newest stay.
    assert!(!t.exists(&f[0]));
    assert!(!t.exists(&f[1]));
    assert!(!t.exists(&f[2]));
    assert!(t.exists(&f[3]));
    assert!(t.exists(&f[4]));
    // `g` has only one version, which is fewer than two, so it is untouched —
    // the count is per path, not a total.
    assert!(t.exists(&g), "a path with fewer than n versions lost one");
}

/// `--keep 0` is a coherent request and means the same as `--all` for anything
/// with a name prune understands.
#[test]
fn keeping_none_removes_everything_dated() {
    let t = Temp::new("keep0");
    let one = plant(&t, "f.txt", DAY, "one");
    let two = plant(&t, "g.txt", DAY, "two");
    run::prune(t.path(), Prune::KeepNewest(0), &quiet()).unwrap();
    assert!(!t.exists(&one));
    assert!(!t.exists(&two));
}

#[test]
fn all_removes_everything_including_what_has_no_timestamp() {
    let t = Temp::new("all");
    let dated = plant(&t, "f.txt", DAY, "dated");
    t.write(".bisync/diffs/mystery", "undated");
    t.write(
        ".bisync/diffs/deep/nest/thing.txt.20200101T000000Z",
        "nested",
    );

    run::prune(t.path(), Prune::All, &quiet()).unwrap();
    assert!(!t.exists(&dated));
    assert!(!t.exists(".bisync/diffs/mystery"));
    // Emptied directories go too, including the top one, so a pruned root looks
    // like one that never kept anything.
    assert!(!t.exists(".bisync/diffs/deep"));
    assert!(!t.exists(".bisync/diffs"));
}

/// Emptying one branch must not take a sibling with it.
#[test]
fn tidying_leaves_directories_that_still_hold_something() {
    let t = Temp::new("tidy");
    let doomed = plant(&t, "a/gone.txt", 90 * DAY, "old");
    let staying = plant(&t, "b/stays.txt", DAY, "recent");

    run::prune(t.path(), Prune::OlderThan(30 * DAY), &quiet()).unwrap();
    assert!(!t.exists(&doomed));
    assert!(
        !t.exists(".bisync/diffs/a"),
        "an emptied directory was left behind"
    );
    assert!(t.exists(&staying));
    assert!(t.exists(".bisync/diffs/b"));
    assert!(t.exists(".bisync/diffs"));
}

#[test]
fn a_dry_run_removes_nothing() {
    let t = Temp::new("prune-dry");
    let ancient = plant(&t, "f.txt", 90 * DAY, "ancient");
    let before = t.kept();

    run::prune(t.path(), Prune::OlderThan(DAY), &dry()).unwrap();
    assert!(t.exists(&ancient));
    assert_eq!(t.kept(), before);

    run::prune(t.path(), Prune::All, &dry()).unwrap();
    assert_eq!(t.kept(), before);
}

#[test]
fn pruning_an_empty_area_is_not_an_error() {
    let t = Temp::new("prune-empty");
    let _ = Store::open(t.path()).unwrap();
    for what in [Prune::All, Prune::KeepNewest(3), Prune::OlderThan(DAY)] {
        assert_eq!(run::prune(t.path(), what, &quiet()).unwrap(), 0);
    }
    assert!(!t.exists(".bisync/diffs"));
}

/// Pruning is not allowed to disturb the tree, the state, or the quarantine —
/// only `diffs`. Quarantine copies in particular are referenced by conflict
/// records, and removing one would break `bisync resolve --remote`.
#[test]
fn pruning_touches_nothing_but_diffs() {
    let (a, b) = (Temp::new("scope-a"), Temp::new("scope-b"));
    a.write("kept.txt", "v1");
    sync(&a, &b);
    // A replacement, to fill `diffs`.
    b.write("kept.txt", "v2");
    sync(&a, &b);
    // And a conflict, to fill `quarantine`.
    a.write("contested.txt", "a's");
    b.write("contested.txt", "b's");
    sync(&a, &b);

    let tree_before = a.list();
    let quarantine_before = a.quarantined();
    let state_before = std::fs::read(a.path().join(".bisync/state")).unwrap();
    assert!(!quarantine_before.is_empty());
    assert!(!a.kept().is_empty());

    run::prune(a.path(), Prune::All, &quiet()).unwrap();

    assert_eq!(a.list(), tree_before, "the tree changed");
    assert_eq!(a.quarantined(), quarantine_before, "quarantine changed");
    assert_eq!(
        std::fs::read(a.path().join(".bisync/state")).unwrap(),
        state_before,
        "the state changed"
    );
    assert!(a.kept().is_empty());

    // The conflict is still resolvable, which is what quarantine was for.
    bisync::run::resolve(a.path(), &["contested.txt".to_string()], true, false).unwrap();
    assert_eq!(a.read("contested.txt"), "b's");
}

/// A sync after a prune carries on as though nothing had happened: `diffs` is not
/// part of the tree, the index or the base.
#[test]
fn syncing_still_works_after_a_prune() {
    let (a, b) = (Temp::new("after-a"), Temp::new("after-b"));
    a.write("f.txt", "one");
    sync(&a, &b);
    b.write("f.txt", "two");
    sync(&a, &b);
    run::prune(a.path(), Prune::All, &quiet()).unwrap();

    b.write("f.txt", "three");
    let out = sync(&a, &b);
    assert_eq!(a.read("f.txt"), "three");
    assert_eq!(out.a.received, 1);
    // And the version just replaced was preserved, prune having removed only
    // what was there before.
    assert_eq!(a.read(&a.kept_copy("f.txt").unwrap()), "two");
    common::assert_converged(&a, &b);
}
