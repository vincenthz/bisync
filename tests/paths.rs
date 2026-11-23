//! Path validation. This is the security boundary: every path in the protocol
//! comes from the far end, and a missed `..` is a remote write anywhere on the
//! filesystem.

use std::path::Path;

use bisync::relpath::{ancestors, basename, depth, from_path, is_under, join, parent, validate};

#[test]
fn ordinary_relative_paths_are_accepted() {
    for path in [
        "",
        "a",
        "a/b",
        "a/b/c.txt",
        "with space/and-dash",
        "üñî/çø∂é",
        "a..b",
        "....",
    ] {
        assert!(validate(path).is_ok(), "{path:?} should be valid");
    }
}

#[test]
fn nothing_that_could_escape_the_root_is_accepted() {
    for path in [
        "..",
        "../x",
        "a/../..",
        "a/../../etc/passwd",
        "/etc/passwd",
        "/",
        "a//b",
        "a/",
        "./a",
        "a/./b",
        "a\0b",
    ] {
        assert!(validate(path).is_err(), "{path:?} should be rejected");
    }
    assert!(validate(&"a/".repeat(4096)).is_err());
}

/// The joined result must stay inside the root for every accepted path. Stated as
/// a property rather than a list, because the list is what an attacker gets to
/// choose.
#[test]
fn accepted_paths_always_join_inside_the_root() {
    let root = Path::new("/srv/data");
    for path in ["a", "a/b", "a..b", "....", "x/y/z", "-", "a b/c"] {
        validate(path).unwrap();
        let joined = join(root, path);
        assert!(joined.starts_with(root), "{path:?} escaped to {joined:?}");
        assert_eq!(joined.components().count(), 3 + depth(path));
    }
    assert_eq!(join(root, ""), root);
}

#[test]
fn parents_and_names() {
    assert_eq!(parent("a/b/c"), "a/b");
    assert_eq!(parent("a"), "");
    assert_eq!(parent(""), "");
    assert_eq!(basename("a/b/c"), "c");
    assert_eq!(basename("a"), "a");
    assert_eq!(ancestors("a/b/c"), vec!["", "a", "a/b"]);
    assert_eq!(ancestors("a"), vec![""]);
    assert_eq!(depth(""), 0);
    assert_eq!(depth("a"), 1);
    assert_eq!(depth("a/b/c"), 3);
}

/// `is_under` decides which paths a directory's removal covers, so a sibling
/// whose name merely starts the same must not be caught by it.
#[test]
fn containment_does_not_confuse_siblings() {
    assert!(is_under("a/b", "a"));
    assert!(is_under("a/b/c", "a"));
    assert!(is_under("anything", ""));
    assert!(!is_under("ab", "a"));
    assert!(!is_under("a-b", "a"));
    assert!(!is_under("a", "a"));
    assert!(!is_under("b/a", "a"));
}

#[test]
fn filesystem_paths_convert_to_wire_form() {
    let root = Path::new("/srv/data");
    assert_eq!(
        from_path(root, Path::new("/srv/data/a/b")).as_deref(),
        Some("a/b")
    );
    assert_eq!(from_path(root, Path::new("/srv/data")).as_deref(), Some(""));
    assert_eq!(from_path(root, Path::new("/srv/other/a")), None);
    assert_eq!(from_path(root, Path::new("/srv/data/../data/a")), None);
}
