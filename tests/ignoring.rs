//! Ignore rules. The defaults matter more than they look: a build directory that
//! is not excluded is a build directory that gets hashed and sent on every
//! `cargo build`.

use bisync::ignore::{DEFAULT_PATTERNS, IgnoreSet};

#[test]
fn the_defaults_exclude_what_a_working_tree_churns() {
    let set = IgnoreSet::defaults();
    for (path, is_dir) in [
        (".git", true),
        ("target", true),
        ("node_modules", true),
        ("src/__pycache__", true),
        ("notes.txt.swp", false),
        ("notes.txt~", false),
        (".DS_Store", false),
        ("deep/nest/.DS_Store", false),
        ("download.part", false),
        ("#locked#", false),
        (".#locked", false),
    ] {
        assert!(set.is_ignored(path, is_dir), "{path} should be ignored");
    }
    for (path, is_dir) in [
        ("src", true),
        ("src/main.rs", false),
        ("targets.txt", false),
        ("my.git.notes", false),
        ("README", false),
    ] {
        assert!(
            !set.is_ignored(path, is_dir),
            "{path} should not be ignored"
        );
    }
}

/// Excluding a directory excludes everything under it, without needing `/**`.
/// This is what lets the scan prune rather than walk.
#[test]
fn excluding_a_directory_excludes_its_contents() {
    let set = IgnoreSet::new(["target/"]);
    assert!(set.is_ignored("target", true));
    assert!(set.is_ignored("target/debug/build/x/out", false));
    assert!(set.is_ignored("a/b/target/deps/lib.rlib", false));
    // A file of the same name is not a directory.
    assert!(!set.is_ignored("target", false));
}

#[test]
fn anchoring_follows_gitignore() {
    let anchored = IgnoreSet::new(["/build"]);
    assert!(anchored.is_ignored("build", false));
    assert!(!anchored.is_ignored("src/build", false));

    // An interior slash anchors just as a leading one does.
    let interior = IgnoreSet::new(["src/generated"]);
    assert!(interior.is_ignored("src/generated", false));
    assert!(!interior.is_ignored("lib/src/generated", false));

    // No slash at all: matches at any depth.
    let floating = IgnoreSet::new(["generated"]);
    assert!(floating.is_ignored("generated", false));
    assert!(floating.is_ignored("a/b/c/generated", false));
}

#[test]
fn stars_stop_at_a_separator_but_double_stars_do_not() {
    let single = IgnoreSet::new(["src/*.rs"]);
    assert!(single.is_ignored("src/main.rs", false));
    assert!(!single.is_ignored("src/bin/main.rs", false));

    let double = IgnoreSet::new(["src/**/*.rs"]);
    assert!(double.is_ignored("src/bin/main.rs", false));
    assert!(double.is_ignored("src/a/b/c/main.rs", false));
    // `**` matches zero components too.
    assert!(double.is_ignored("src/main.rs", false));
}

#[test]
fn question_marks_and_classes() {
    let set = IgnoreSet::new(["log.?", "*.[oa]", "tmp[0-9]", "keep[!0-9]"]);
    assert!(set.is_ignored("log.1", false));
    assert!(!set.is_ignored("log.10", false));
    assert!(set.is_ignored("x.o", false));
    assert!(set.is_ignored("x.a", false));
    assert!(!set.is_ignored("x.b", false));
    assert!(set.is_ignored("tmp7", false));
    assert!(!set.is_ignored("tmpx", false));
    assert!(set.is_ignored("keepx", false));
    assert!(!set.is_ignored("keep4", false));
}

#[test]
fn later_rules_win_and_bang_re_includes() {
    let set = IgnoreSet::new(["target/", "!target/release/tool"]);
    assert!(set.is_ignored("target/debug/tool", false));
    assert!(!set.is_ignored("target/release/tool", false));
    // A negation anywhere disables pruning: something under an excluded
    // directory might be wanted, and the only way to know is to look.
    assert!(!set.can_prune());
    assert!(IgnoreSet::new(["target/"]).can_prune());
}

/// The control directory is not negotiable. A `!` in a config must not be able
/// to make bisync sync its own state file, which would be a fine way to have two
/// machines overwrite each other's idea of what they had agreed.
#[test]
fn the_control_directory_cannot_be_re_included() {
    let set = IgnoreSet::new(["!.bisync/", "!.bisync/state", "!**"]);
    assert!(set.is_ignored(".bisync", true));
    assert!(set.is_ignored(".bisync/state", false));
    assert!(set.is_ignored(".bisync/quarantine/x/y", false));
}

/// A leading `#` is a comment, so a pattern that really starts with one needs
/// escaping — and the default list contains exactly such a pattern.
#[test]
fn a_hash_can_be_escaped_into_a_pattern() {
    let set = IgnoreSet::new(["# a comment", "\\#*#", "\\!literal"]);
    assert!(set.is_ignored("#emacs-lock#", false));
    assert!(set.is_ignored("!literal", false));
    assert!(!set.is_ignored("a comment", false));
}

/// The two ends must compile the same rules, and each has to be able to tell
/// whether they did. `to_lines` and `digest` are how, so a set rebuilt from
/// another's lines must digest identically.
#[test]
fn a_rule_set_survives_the_round_trip_to_a_peer() {
    let mine = IgnoreSet::new(DEFAULT_PATTERNS);
    let theirs = IgnoreSet::new(mine.to_lines());
    assert_eq!(mine.digest(), theirs.digest());
    assert_eq!(mine.len(), theirs.len());
    assert_eq!(mine.to_lines(), theirs.to_lines());
    // And a genuinely different list must not collide.
    assert_ne!(mine.digest(), IgnoreSet::new(["target/"]).digest());
}

#[test]
fn junk_lines_are_dropped_rather_than_fatal() {
    let set = IgnoreSet::new(["", "   ", "# comment", "/", "!", "//", "**"]);
    assert_eq!(set.len(), 0);
    assert!(!set.is_ignored("anything", false));
    // Except the forced prefix, which is always there.
    assert!(set.is_ignored(".bisync", true));
}

#[test]
fn explain_names_the_rule_responsible() {
    let set = IgnoreSet::new(["target/", "*.tmp"]);
    assert_eq!(set.explain("target/debug/x", false), Some("target/"));
    assert_eq!(set.explain("notes.tmp", false), Some("*.tmp"));
    assert_eq!(set.explain("src/main.rs", false), None);
}
