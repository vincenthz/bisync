//! The filesystem watcher.
//!
//! Timing-dependent by nature, so the waits here are generous: what is being
//! checked is that an event arrives at all and that it names the right path, not
//! how quickly. A native backend that silently reported nothing would leave
//! `bisync watch` looking like it worked while propagating nothing, which is
//! exactly the failure worth a test.

mod common;

use std::sync::mpsc;
use std::time::{Duration, Instant};

use bisync::ignore::IgnoreSet;
use bisync::wake::Wake;
use bisync::watch::Watcher;

use common::Temp;

const PATIENCE: Duration = Duration::from_secs(10);
const DEBOUNCE: Duration = Duration::from_millis(150);

/// Collect debounced batches until one satisfies `wanted`, or patience runs out.
fn wait_for(
    rx: &mpsc::Receiver<Wake>,
    mut wanted: impl FnMut(&[String]) -> bool,
) -> Option<Vec<String>> {
    let deadline = Instant::now() + PATIENCE;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(remaining) {
            Ok(Wake::Local(paths)) => {
                if wanted(&paths) {
                    return Some(paths);
                }
            }
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    None
}

fn start(t: &Temp, poll_only: bool, heartbeat: Duration) -> (Watcher, mpsc::Receiver<Wake>) {
    let (tx, rx) = mpsc::channel();
    // Canonicalised, because a native backend reports the filesystem's own idea
    // of a path: on macOS the temporary directory is reached through a symlink,
    // and events arrive under the resolved name. `Store::open` canonicalises for
    // the same reason.
    let root = t.path().canonicalize().unwrap();
    let watcher = Watcher::start(
        &root,
        IgnoreSet::defaults(),
        DEBOUNCE,
        heartbeat,
        poll_only,
        tx,
    )
    .unwrap();
    (watcher, rx)
}

#[test]
fn a_new_file_is_noticed() {
    let t = Temp::new("watch-new");
    let (watcher, rx) = start(&t, false, Duration::from_secs(3600));
    // A moment for the backend to be listening before anything happens.
    std::thread::sleep(Duration::from_millis(300));

    t.write("appeared.txt", "hello");
    let batch = wait_for(&rx, |paths| {
        paths.iter().any(|p| p == "appeared.txt" || p.is_empty())
    });
    assert!(
        batch.is_some(),
        "nothing was reported (backend: {})",
        watcher.kind()
    );
}

#[test]
fn an_edit_a_deletion_and_a_new_directory_are_all_noticed() {
    let t = Temp::new("watch-edit");
    t.write("existing.txt", "before");
    t.write("doomed.txt", "goodbye");
    let (watcher, rx) = start(&t, false, Duration::from_secs(3600));
    std::thread::sleep(Duration::from_millis(300));

    t.write("existing.txt", "after");
    t.remove("doomed.txt");
    t.write("fresh/inside.txt", "new");

    // The three may arrive in one batch or several; what matters is that all
    // three paths turn up.
    let mut seen: Vec<String> = Vec::new();
    let found = wait_for(&rx, |paths| {
        seen.extend(paths.iter().cloned());
        seen.iter().any(|p| p.is_empty())
            || (seen.iter().any(|p| p == "existing.txt")
                && seen.iter().any(|p| p == "doomed.txt")
                && seen.iter().any(|p| p.starts_with("fresh")))
    });
    assert!(found.is_some(), "saw {seen:?} via {}", watcher.kind());
}

/// The watcher filters before the session ever hears about it, so a build
/// churning through `target/` costs a pattern match rather than a rescan.
#[test]
fn churn_in_an_ignored_directory_is_not_reported() {
    let t = Temp::new("watch-ignored");
    let (watcher, rx) = start(&t, false, Duration::from_secs(3600));
    std::thread::sleep(Duration::from_millis(300));

    for i in 0..20 {
        t.write(&format!("target/debug/build/artifact{i}"), "output");
        t.write(&format!("notes{i}.txt.swp"), "editor swap");
    }
    t.write(".git/index", "git being git");
    // Then something that is not ignored, to prove the watcher is alive and that
    // the ignored churn simply produced nothing.
    std::thread::sleep(Duration::from_millis(400));
    t.write("real.txt", "this one counts");

    let batch = wait_for(&rx, |paths| !paths.is_empty()).expect("the watcher went quiet");
    assert!(
        batch.iter().all(|p| p == "real.txt" || p.is_empty()),
        "ignored paths reported: {batch:?} via {}",
        watcher.kind()
    );
}

/// With no native backend there is still the heartbeat, which is a full rescan
/// and is spelled as the empty path.
#[test]
fn the_polling_backend_asks_for_a_full_rescan() {
    let t = Temp::new("watch-poll");
    let (watcher, rx) = start(&t, true, Duration::from_millis(200));
    assert_eq!(watcher.kind(), "rescan");

    let batch = wait_for(&rx, |paths| !paths.is_empty()).expect("no heartbeat");
    assert_eq!(batch, vec![String::new()]);
}

/// The heartbeat is also the safety net under a native backend: both FSEvents
/// and inotify can drop events under load, and a dropped event must cost a delay
/// rather than a permanently missed file.
#[test]
fn a_native_watcher_still_rescans_periodically() {
    let t = Temp::new("watch-heartbeat");
    let (_watcher, rx) = start(&t, false, Duration::from_millis(200));
    let batch = wait_for(&rx, |paths| paths.len() == 1 && paths[0].is_empty());
    assert_eq!(batch, Some(vec![String::new()]));
}

/// Dropping the watcher must stop its threads. The channel going quiet is how
/// that shows: the senders are gone with it.
#[test]
fn dropping_the_watcher_stops_it() {
    let t = Temp::new("watch-drop");
    let (watcher, rx) = start(&t, false, Duration::from_millis(50));
    std::thread::sleep(Duration::from_millis(300));
    drop(watcher);

    // Drain whatever was already queued, then expect the channel to close.
    let deadline = Instant::now() + PATIENCE;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "the watcher kept running after being dropped"
        );
        match rx.recv_timeout(remaining) {
            Ok(_) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("the channel neither delivered nor closed")
            }
        }
    }
}
