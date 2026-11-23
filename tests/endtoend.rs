//! The whole tool, as a process.
//!
//! These run the real binary, which means the real transport: `bisync sync`
//! spawns a second copy of itself as `bisync server` and talks the protocol over
//! its stdin and stdout. Over ssh the only difference is that ssh copies the
//! bytes between the two pipes, so this covers the framing, the reader thread,
//! the argument parsing and the exit codes that the in-process tests do not.

mod common;

use std::process::{Command, Output};

use common::{Temp, assert_converged};

fn bisync(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bisync"))
        .args(args)
        .output()
        .expect("run bisync")
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = bisync(args);
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Point two roots at each other with `bisync init`, as a user would.
fn pair(tag: &str) -> (Temp, Temp) {
    let a = Temp::new(&format!("{tag}-a"));
    let b = Temp::new(&format!("{tag}-b"));
    let (code, _, err) = run(&[
        "init",
        a.path().to_str().unwrap(),
        "--peer",
        b.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = run(&[
        "init",
        b.path().to_str().unwrap(),
        "--peer",
        a.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}");
    (a, b)
}

fn sync(t: &Temp) -> (i32, String, String) {
    run(&["sync", t.path().to_str().unwrap()])
}

#[test]
fn two_trees_converge_over_the_real_transport() {
    let (a, b) = pair("e2e");
    a.write("one.txt", "from a");
    a.write("nested/deep/two.txt", "also from a");
    a.symlink("link", "one.txt");
    b.write("three.txt", "from b");
    // Big enough to need many frames, small enough to stay under the limit.
    let bulk: Vec<u8> = (0..600_000u32).map(|i| (i % 253) as u8).collect();
    b.write_bytes("bulk.bin", &bulk);

    let (code, out, err) = sync(&a);
    assert_eq!(code, 0, "stdout:\n{out}\nstderr:\n{err}");
    assert_eq!(b.read("one.txt"), "from a");
    assert_eq!(b.read("nested/deep/two.txt"), "also from a");
    assert_eq!(a.read("three.txt"), "from b");
    assert_eq!(std::fs::read(a.path().join("bulk.bin")).unwrap(), bulk);
    assert!(
        b.path()
            .join("link")
            .symlink_metadata()
            .unwrap()
            .is_symlink()
    );
    assert_converged(&a, &b);

    // A second run has nothing to do and says so.
    let (code, out, _) = sync(&a);
    assert_eq!(code, 0);
    assert!(out.contains("nothing to do"), "{out}");
}

#[test]
fn edits_and_deletions_survive_a_round_trip_through_two_processes() {
    let (a, b) = pair("e2e-edit");
    a.write("x.txt", "one");
    a.write("y.txt", "two");
    a.write("z.txt", "three");
    assert_eq!(sync(&a).0, 0);

    a.write("x.txt", "one, edited on a");
    b.write("y.txt", "two, edited on b");
    b.remove("z.txt");
    assert_eq!(sync(&a).0, 0);

    assert_eq!(b.read("x.txt"), "one, edited on a");
    assert_eq!(a.read("y.txt"), "two, edited on b");
    assert!(!a.exists("z.txt"));
    assert_converged(&a, &b);
}

/// A conflict must be visible from the shell: nothing overwritten, exit status
/// 2, and the paths listed by `bisync conflicts`.
#[test]
fn a_conflict_exits_with_two_and_can_be_resolved_from_the_command_line() {
    let (a, b) = pair("e2e-conflict");
    a.write("shared.txt", "original");
    assert_eq!(sync(&a).0, 0);
    a.write("shared.txt", "a's work");
    b.write("shared.txt", "b's work");

    let (code, out, _) = sync(&a);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("shared.txt"), "{out}");
    assert_eq!(a.read("shared.txt"), "a's work");
    assert_eq!(b.read("shared.txt"), "b's work");

    // Still 2 while it is outstanding, even though this run found nothing new.
    assert_eq!(sync(&a).0, 2);

    let (code, out, _) = run(&["conflicts", a.path().to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(out.contains("edited on both sides"), "{out}");
    assert!(out.contains("bisync resolve"), "{out}");

    let (code, out, err) = run(&[
        "resolve",
        a.path().to_str().unwrap(),
        "shared.txt",
        "--local",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("resolved"), "{out}");

    assert_eq!(sync(&a).0, 0);
    assert_eq!(a.read("shared.txt"), "a's work");
    assert_eq!(b.read("shared.txt"), "a's work");
    assert_converged(&a, &b);
}

#[test]
fn a_dry_run_changes_nothing_on_either_side() {
    let (a, b) = pair("e2e-dry");
    a.write("new.txt", "would be sent");
    let before = b.list();

    let (code, out, err) = run(&["sync", a.path().to_str().unwrap(), "--dry-run"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("would"), "{out}");
    assert!(out.contains("dry run"), "{out}");
    assert_eq!(b.list(), before);
    assert!(!b.exists("new.txt"));
}

#[test]
fn the_size_limit_is_reported_and_can_be_raised_from_the_command_line() {
    let (a, b) = pair("e2e-size");
    a.write_bytes("big.bin", &vec![3u8; 200_000]);
    a.write("small.txt", "fits");

    let root = a.path().to_str().unwrap().to_string();
    let (code, out, err) = run(&["sync", &root, "--max-size", "64k"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("over the size limit"), "{out}");
    assert!(!b.exists("big.bin"));
    assert_eq!(b.read("small.txt"), "fits");

    let (code, _, err) = run(&["sync", &root, "--max-size", "1M"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(b.path().join("big.bin").metadata().unwrap().len(), 200_000);
}

/// The conflict policy is part of the session's terms, not a local preference.
/// Only the initiating side is given the flag, so if it did not travel, one end
/// would resolve and the other would freeze — and the two would disagree about
/// what happened.
#[test]
fn the_conflict_policy_reaches_the_far_end() {
    for (flag, winner) in [("local", "a's work"), ("remote", "b's work")] {
        let (a, b) = pair(&format!("e2e-policy-{flag}"));
        a.write("shared.txt", "original");
        assert_eq!(sync(&a).0, 0);
        a.write("shared.txt", "a's work");
        b.write("shared.txt", "b's work");

        let (code, out, err) = run(&["sync", a.path().to_str().unwrap(), "--conflict", flag]);
        assert_eq!(code, 0, "--conflict {flag} left a conflict:\n{out}\n{err}");
        assert_eq!(a.read("shared.txt"), winner, "--conflict {flag} on a");
        assert_eq!(b.read("shared.txt"), winner, "--conflict {flag} on b");
        assert_converged(&a, &b);
        // The losing version is kept, on whichever side had to give it up — in
        // `diffs` rather than `quarantine`, because it was replaced by the
        // peer's version rather than declined in favour of staying put.
        let (loser, gave_up) = if flag == "local" {
            ("b's work", &b)
        } else {
            ("a's work", &a)
        };
        let kept = gave_up
            .kept_copy("shared.txt")
            .unwrap_or_else(|| panic!("--conflict {flag}: nothing kept"));
        assert_eq!(gave_up.read(&kept), loser, "--conflict {flag}");
    }
}

/// `newer` needs both ends to compare the same two timestamps and agree, which
/// only works if both are applying the same policy.
#[test]
fn the_newer_policy_settles_a_conflict_on_both_sides() {
    let (a, b) = pair("e2e-newer");
    a.write("shared.txt", "original");
    assert_eq!(sync(&a).0, 0);
    a.write("shared.txt", "a's work");
    std::thread::sleep(std::time::Duration::from_millis(1100));
    b.write("shared.txt", "b's work, and later");

    let (code, out, err) = run(&["sync", a.path().to_str().unwrap(), "--conflict", "newer"]);
    assert_eq!(code, 0, "stdout:\n{out}\nstderr:\n{err}");
    assert_eq!(a.read("shared.txt"), "b's work, and later");
    assert_eq!(b.read("shared.txt"), "b's work, and later");
    assert!(!out.contains("unresolved"), "{out}");
    // a's version lost, so a's copy of it is the one that was replaced.
    assert_eq!(a.read(&a.kept_copy("shared.txt").unwrap()), "a's work");
    assert_converged(&a, &b);
}

/// Compression has to reach the far end, and its effect has to be visible from
/// the shell — a saving nobody can see is indistinguishable from CPU spent for
/// nothing.
#[test]
fn compression_reaches_the_far_end_and_is_reported() {
    let (a, b) = pair("e2e-compress");
    // Repetitive source text: the case a working tree is mostly made of.
    let bulk = "fn main() { println!(\"hello\"); } // padding padding\n".repeat(9000);
    a.write("big.rs", &bulk);

    let (code, out, err) = sync(&a);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        b.read("big.rs"),
        bulk,
        "content did not survive compression"
    );
    assert!(out.contains("saved"), "no saving reported:\n{out}");
    assert_converged(&a, &b);

    let (code, status, _) = run(&["status", a.path().to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(status.contains("compress  deflate level 6"), "{status}");
    assert!(
        status.contains("on the wire"),
        "no running total:\n{status}"
    );

    // And the far end received the same content it was sent, by its own account.
    let (code, status, _) = run(&["status", b.path().to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(status.contains("received"), "{status}");
}

#[test]
fn compression_can_be_turned_off_from_the_command_line() {
    let (a, b) = pair("e2e-nocompress");
    let bulk = "the same line over and over\n".repeat(5000);
    a.write("big.txt", &bulk);

    let (code, out, err) = run(&["sync", a.path().to_str().unwrap(), "--no-compress"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(b.read("big.txt"), bulk);
    assert!(!out.contains("saved"), "compression ran anyway:\n{out}");

    let (code, status, _) = run(&["status", a.path().to_str().unwrap(), "--no-compress"]);
    assert_eq!(code, 0);
    assert!(status.contains("compress  off"), "{status}");
}

/// `-z` takes an optional level, so a bare `-z` must not swallow the argument
/// after it.
#[test]
fn the_compress_flag_takes_an_optional_level() {
    let (a, _b) = pair("e2e-zlevel");
    a.write("f.txt", "content");
    let root = a.path().to_str().unwrap().to_string();

    for args in [
        vec!["status", &root, "-z"],
        vec!["status", &root, "-z", "1"],
        vec!["status", "-z", "9", &root],
        vec!["status", &root, "--compress=3"],
    ] {
        let (code, out, err) = run(&args);
        assert_eq!(code, 0, "{args:?}: {err}");
        assert!(out.contains("deflate level"), "{args:?}:\n{out}");
        // The root was still found, so the level did not eat the path.
        assert!(out.contains(&root), "{args:?}:\n{out}");
    }

    let (code, _, err) = run(&["status", &root, "-z", "99"]);
    assert_eq!(code, 1);
    assert!(err.contains("compression level"), "{err}");
}

#[test]
fn status_describes_the_root_without_talking_to_the_peer() {
    let (a, b) = pair("e2e-status");
    a.write("f.txt", "content");
    a.write_bytes("huge.bin", &vec![1u8; 3_000_000]);
    a.write("target/debug/ignored", "build output");

    let (code, out, err) = run(&["status", a.path().to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains(b.path().to_str().unwrap()),
        "peer not shown:\n{out}"
    );
    assert!(out.contains("huge.bin"), "oversize not listed:\n{out}");
    assert!(out.contains("f.txt"), "pending change not listed:\n{out}");
    assert!(
        !out.contains("target/debug/ignored"),
        "ignored path listed:\n{out}"
    );
    assert!(out.contains("1M per file"), "{out}");
}

#[test]
fn the_tree_command_prints_a_digest_per_entry() {
    let a = Temp::new("e2e-tree");
    let (code, _, _) = run(&["init", a.path().to_str().unwrap()]);
    assert_eq!(code, 0);
    a.write("f.txt", "content");
    a.write("d/g.txt", "more");

    let (code, out, err) = run(&["tree", a.path().to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("  ."), "{out}");
    assert!(out.contains("f.txt"), "{out}");
    assert!(out.contains("d/"), "{out}");
    // Every line starts with a 64-character digest, except the skipped ones.
    for line in out.lines() {
        let (digest, _) = line.split_once("  ").expect(line);
        assert_eq!(digest.len(), 64, "{line}");
    }
}

#[test]
fn a_root_with_no_peer_says_what_to_do_about_it() {
    let a = Temp::new("e2e-nopeer");
    let (code, _, _) = run(&["init", a.path().to_str().unwrap()]);
    assert_eq!(code, 0);
    let (code, _, err) = sync(&a);
    assert_eq!(code, 1);
    assert!(err.contains("no peer configured"), "{err}");
    assert!(err.contains("bisync init"), "{err}");
}

/// `prune` from the shell: it has to be told what to remove, and it has to
/// refuse a contradiction rather than pick one.
#[test]
fn prune_needs_to_be_told_what_to_remove() {
    let (a, b) = pair("e2e-prune");
    a.write("f.txt", "one");
    assert_eq!(sync(&a).0, 0);
    b.write("f.txt", "two");
    assert_eq!(sync(&a).0, 0);
    let root = a.path().to_str().unwrap().to_string();
    assert_eq!(a.kept().len(), 1, "nothing to prune: {:?}", a.kept());

    // No criterion: everything in `diffs` is a copy of something that was about
    // to be destroyed, so guessing which are expendable is not bisync's call.
    let (code, _, err) = run(&["prune", &root]);
    assert_eq!(code, 1);
    assert!(err.contains("--older-than"), "{err}");
    assert_eq!(a.kept().len(), 1, "a refused prune removed something");

    // Two criteria at once.
    let (code, _, err) = run(&["prune", &root, "--all", "--keep", "2"]);
    assert_eq!(code, 1);
    assert!(err.contains("alternatives"), "{err}");

    // An unparseable span.
    let (code, _, err) = run(&["prune", &root, "--older-than", "3months"]);
    assert_eq!(code, 1);
    assert!(err.contains("span of time"), "{err}");
    assert_eq!(a.kept().len(), 1);

    // A dry run says what it would do and does nothing.
    let (code, out, err) = run(&["prune", &root, "--all", "--dry-run"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("would remove"), "{out}");
    assert_eq!(a.kept().len(), 1);

    // Recent enough to survive a week's cutoff.
    let (code, out, err) = run(&["prune", &root, "--older-than", "7d"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("removed 0 versions"), "{out}");
    assert_eq!(a.kept().len(), 1);

    // And then for real.
    let (code, out, err) = run(&["prune", &root, "--all"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("removed 1 version"), "{out}");
    assert!(a.kept().is_empty());

    // Pruning an area that is already empty is not an error.
    let (code, out, _) = run(&["prune", &root, "--all"]);
    assert_eq!(code, 0);
    assert!(out.contains("nothing kept"), "{out}");
}

/// `status` says how much has accumulated, which is the thing that makes anyone
/// think to prune in the first place.
#[test]
fn status_reports_what_is_waiting_to_be_pruned() {
    let (a, b) = pair("e2e-prune-status");
    a.write("f.txt", "one");
    assert_eq!(sync(&a).0, 0);

    let (_, out, _) = run(&["status", a.path().to_str().unwrap()]);
    assert!(!out.contains("kept "), "nothing replaced yet:\n{out}");

    b.write("f.txt", "a longer second version");
    assert_eq!(sync(&a).0, 0);
    let (_, out, _) = run(&["status", a.path().to_str().unwrap()]);
    assert!(out.contains("kept      1 old version"), "{out}");
    assert!(out.contains(".bisync/diffs"), "{out}");
}

/// One-way syncs and the dry-run diff, through the real transport — which is
/// where the fact that both are *session terms* actually gets tested: the peer is
/// a separate process that has to be told.
#[test]
fn one_way_and_diff_work_across_the_link() {
    let (a, b) = pair("e2e-oneway");
    a.write("f.txt", "one\ntwo\n");
    assert_eq!(sync(&a).0, 0);
    b.write("f.txt", "one\nTWO\n");
    a.write("mine.txt", "only here");
    let root = a.path().to_str().unwrap().to_string();

    // A diff changes nothing on either side — the second half is what a dry run
    // used to get wrong, the peer applying on its own initiative.
    let (code, out, err) = run(&["sync", &root, "--diff"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("+TWO"), "no diff shown:\n{out}");
    assert!(out.contains("-two"), "{out}");
    assert!(out.contains("dry run"), "{out}");
    assert_eq!(a.read("f.txt"), "one\ntwo\n");
    assert!(!b.exists("mine.txt"), "a dry run wrote to the peer");

    // Pull: their change arrives, ours is not offered.
    let (code, out, err) = run(&["sync", &root, "--pull"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("only pulls"), "{out}");
    assert_eq!(a.read("f.txt"), "one\nTWO\n");
    assert!(!b.exists("mine.txt"));

    // Push: now ours goes over.
    let (code, _, err) = run(&["sync", &root, "--push"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(b.read("mine.txt"), "only here");
    assert_converged(&a, &b);

    let (code, _, err) = run(&["sync", &root, "--pull", "--push"]);
    assert_eq!(code, 1);
    assert!(err.contains("opposites"), "{err}");
}

#[test]
fn help_and_version_work_and_rubbish_does_not() {
    let (code, out, _) = run(&["help"]);
    assert_eq!(code, 0);
    assert!(out.contains("prune"), "{out}");
    assert!(
        out.contains("bidirectional") || out.contains("both directions"),
        "{out}"
    );
    assert!(out.contains("quarantine"), "{out}");

    let (code, out, _) = run(&["version"]);
    assert_eq!(code, 0);
    assert!(out.contains("bisync"), "{out}");
    assert!(out.contains("protocol"), "{out}");

    let (code, _, err) = run(&["frobnicate"]);
    assert_eq!(code, 1);
    assert!(err.contains("unknown command"), "{err}");

    let (code, _, err) = run(&["sync", "--nonsense"]);
    assert_eq!(code, 1);
    assert!(err.contains("unknown option"), "{err}");

    let (code, _, err) = run(&["resolve", "x"]);
    assert_eq!(code, 1);
    assert!(err.contains("--local"), "{err}");
}

/// `init` refuses to overwrite a config, so a stray `bisync init` in a working
/// root cannot silently replace someone's ignore list.
#[test]
fn init_does_not_overwrite_an_existing_config() {
    let a = Temp::new("e2e-init");
    let path = a.path().to_str().unwrap();
    assert_eq!(run(&["init", path, "--peer", "host:/x"]).0, 0);
    let before = a.read(".bisync/config");
    let (code, _, err) = run(&["init", path, "--peer", "other:/y"]);
    assert_eq!(code, 1);
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(a.read(".bisync/config"), before);
}
