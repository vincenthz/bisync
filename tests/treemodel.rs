//! The index and its Merkle tree.

use bisync::hash::{Digest, empty_dir_digest, file_digest};
use bisync::tree::{Entry, Index, Kind, PathState, Stamp};
use bisync::wire::Reader;

fn file(content: &str) -> Entry {
    Entry::file(
        file_digest(content.as_bytes()),
        content.len() as u64,
        0o644,
        Stamp::default(),
    )
}

fn build(paths: &[(&str, Option<&str>)]) -> Index {
    let mut index = Index::new();
    for (path, content) in paths {
        match content {
            Some(content) => index.insert(*path, file(content)),
            None => index.insert(*path, Entry::dir(0o755)),
        }
    }
    index.recompute();
    index
}

#[test]
fn an_empty_tree_has_the_empty_directory_digest() {
    let index = build(&[]);
    assert_eq!(index.root_digest(), empty_dir_digest());
    assert_eq!(index.dir_digest(""), Some(empty_dir_digest()));
    assert_eq!(index.len(), 0);
}

/// The property the whole protocol rests on: same tree, same root digest;
/// different tree, different root digest.
#[test]
fn the_root_digest_identifies_the_tree() {
    let one = build(&[
        ("a", None),
        ("a/b.txt", Some("hello")),
        ("c.txt", Some("world")),
    ]);
    let same = build(&[
        ("c.txt", Some("world")),
        ("a/b.txt", Some("hello")),
        ("a", None),
    ]);
    assert_eq!(one.root_digest(), same.root_digest());

    // A leaf's content.
    let edited = build(&[
        ("a", None),
        ("a/b.txt", Some("HELLO")),
        ("c.txt", Some("world")),
    ]);
    assert_ne!(one.root_digest(), edited.root_digest());

    // A leaf's name.
    let renamed = build(&[
        ("a", None),
        ("a/B.txt", Some("hello")),
        ("c.txt", Some("world")),
    ]);
    assert_ne!(one.root_digest(), renamed.root_digest());

    // Where a leaf sits. Same names, same contents, different structure.
    let moved = build(&[
        ("a", None),
        ("b.txt", Some("hello")),
        ("c.txt", Some("world")),
    ]);
    assert_ne!(one.root_digest(), moved.root_digest());

    // An empty directory is part of the tree, so adding one changes the digest.
    let extra = build(&[
        ("a", None),
        ("a/b.txt", Some("hello")),
        ("c.txt", Some("world")),
        ("empty", None),
    ]);
    assert_ne!(one.root_digest(), extra.root_digest());
}

/// A change must propagate to every ancestor and to nothing else — that is what
/// makes the descent prune, and a bug here would either miss changes or descend
/// the whole tree.
#[test]
fn a_change_moves_exactly_its_ancestors_digests() {
    let before = build(&[
        ("x", None),
        ("x/y", None),
        ("x/y/deep.txt", Some("one")),
        ("x/sibling.txt", Some("s")),
        ("other", None),
        ("other/thing.txt", Some("t")),
    ]);
    let after = build(&[
        ("x", None),
        ("x/y", None),
        ("x/y/deep.txt", Some("two")),
        ("x/sibling.txt", Some("s")),
        ("other", None),
        ("other/thing.txt", Some("t")),
    ]);
    assert_ne!(before.root_digest(), after.root_digest());
    assert_ne!(before.dir_digest("x"), after.dir_digest("x"));
    assert_ne!(before.dir_digest("x/y"), after.dir_digest("x/y"));
    // The untouched branch is bit-for-bit the same, so the descent stops there.
    assert_eq!(before.dir_digest("other"), after.dir_digest("other"));
}

/// Directory ranges are computed from string bounds, and `/` sits between `-`
/// and `0` in ASCII. A sloppy bound catches `a-x` or misses `a/b`.
#[test]
fn subtree_ranges_do_not_catch_similarly_named_siblings() {
    let index = build(&[
        ("a", None),
        ("a/inside.txt", Some("i")),
        ("a/deeper", None),
        ("a/deeper/x.txt", Some("x")),
        ("a-dash.txt", Some("d")),
        ("a0zero.txt", Some("z")),
        ("ab.txt", Some("b")),
        ("a.txt", Some("dot")),
    ]);
    let under: Vec<&str> = index.range_under("a").map(|(p, _)| p.as_str()).collect();
    assert_eq!(under, vec!["a/deeper", "a/deeper/x.txt", "a/inside.txt"]);

    let children: Vec<String> = index.children("a").into_iter().map(|c| c.name).collect();
    assert_eq!(children, vec!["deeper", "inside.txt"]);

    let mut index = index;
    let removed = index.remove_subtree("a");
    assert_eq!(
        removed,
        vec!["a/deeper", "a/deeper/x.txt", "a/inside.txt", "a"]
    );
    assert!(index.contains("a-dash.txt"));
    assert!(index.contains("a0zero.txt"));
    assert!(index.contains("ab.txt"));
    assert!(index.contains("a.txt"));
    assert!(!index.contains("a/inside.txt"));
}

#[test]
fn children_reports_kinds_and_metadata() {
    let mut index = Index::new();
    index.insert("d", Entry::dir(0o700));
    index.insert("d/f", file("body"));
    index.insert(
        "d/l",
        Entry::symlink(bisync::hash::symlink_digest(b"f"), "f".into()),
    );
    index.insert("d/sub", Entry::dir(0o755));
    index.insert("d/sub/deep", file("deep"));
    index.recompute();

    let children = index.children("d");
    assert_eq!(children.len(), 3);
    let by_name: Vec<(&str, Kind)> = children.iter().map(|c| (c.name.as_str(), c.kind)).collect();
    assert_eq!(
        by_name,
        vec![("f", Kind::File), ("l", Kind::Symlink), ("sub", Kind::Dir)]
    );
    assert_eq!(children[0].size, 4);
    assert_eq!(children[0].mode, 0o644);
    assert_eq!(children[2].name, "sub");
    // A directory child carries its subtree digest, which is what lets one
    // comparison settle a whole subtree.
    assert_eq!(children[2].digest, index.dir_digest("d/sub").unwrap());
}

/// Oversized files take no part in any digest. If they did, a tree holding one
/// 4 GiB file that will never be transferred would have a root digest that never
/// matched, and every session would walk the whole tree to rediscover that.
#[test]
fn oversized_files_are_outside_the_tree_entirely() {
    let plain = build(&[("keep.txt", Some("k"))]);
    let mut with_big = build(&[("keep.txt", Some("k"))]);
    with_big.mark_oversize("huge.bin", 4 << 30);
    with_big.recompute();

    assert_eq!(plain.root_digest(), with_big.root_digest());
    assert_eq!(with_big.state("huge.bin"), PathState::Absent);
    assert_eq!(with_big.oversize().get("huge.bin"), Some(&(4u64 << 30)));
    assert!(with_big.children("").iter().all(|c| c.name != "huge.bin"));
    assert_eq!(with_big.total_bytes(), 1);
}

/// Marking a path oversized must drop any index entry it had, or a file that
/// grew past the limit would still be announced at its old digest.
#[test]
fn a_file_that_grows_past_the_limit_leaves_the_tree() {
    let mut index = build(&[("f.bin", Some("small"))]);
    assert!(index.contains("f.bin"));
    index.mark_oversize("f.bin", 9_999_999);
    index.recompute();
    assert!(!index.contains("f.bin"));
    assert_eq!(index.root_digest(), empty_dir_digest());
}

#[test]
fn path_states_reflect_their_entries() {
    let index = build(&[("f", Some("body")), ("d", None)]);
    assert_eq!(
        index.state("f"),
        PathState::File {
            digest: file_digest(b"body"),
            size: 4,
            mode: 0o644
        }
    );
    assert_eq!(index.state("d"), PathState::Dir);
    assert_eq!(index.state("nowhere"), PathState::Absent);

    let link = PathState::Symlink {
        target: "elsewhere".into(),
    };
    assert_eq!(link.digest(), bisync::hash::symlink_digest(b"elsewhere"));
    assert!(!link.needs_content());
    assert!(index.state("f").needs_content());
    assert!(!index.state("d").needs_content());
    assert_eq!(PathState::Absent.digest(), Digest::default());
}

#[test]
fn an_index_survives_the_round_trip_through_bytes() {
    let mut index = build(&[
        ("dir", None),
        ("dir/file.txt", Some("content")),
        ("dir/link", Some("x")),
        ("top.bin", Some("bytes")),
    ]);
    index.insert(
        "dir/link",
        Entry::symlink(bisync::hash::symlink_digest(b"../t"), "../t".into()),
    );
    index.mark_oversize("big.bin", 12_345_678);
    index.recompute();

    let bytes = index.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = Index::decode(&mut reader).unwrap();
    reader.finish().unwrap();

    assert_eq!(decoded.root_digest(), index.root_digest());
    assert_eq!(decoded.len(), index.len());
    assert_eq!(decoded.oversize(), index.oversize());
    for (path, entry) in index.iter() {
        assert_eq!(decoded.get(path), Some(entry), "{path}");
    }
    // And the digests it was given are the digests it would compute.
    let mut recomputed = decoded.clone();
    recomputed.recompute();
    assert_eq!(recomputed.root_digest(), index.root_digest());
}

#[test]
fn a_decoded_index_rejects_a_hostile_path() {
    let mut index = Index::new();
    index.insert("ok", file("x"));
    let bytes = index.encode();
    // Replace the two-byte path "ok" with "..", the shape a traversal takes once
    // it has been split into components.
    let at = bytes
        .windows(2)
        .position(|w| w == b"ok")
        .expect("path bytes present");
    let mut hostile = bytes.clone();
    hostile[at..at + 2].copy_from_slice(b"..");
    let mut reader = Reader::new(&hostile);
    assert!(Index::decode(&mut reader).is_err());
}

#[test]
fn counts_and_totals() {
    let mut index = build(&[
        ("d", None),
        ("d/a.txt", Some("aaaa")),
        ("d/b.txt", Some("bb")),
        ("e", None),
    ]);
    index.insert(
        "l",
        Entry::symlink(bisync::hash::symlink_digest(b"t"), "t".into()),
    );
    index.recompute();
    assert_eq!(index.count_of(Kind::File), 2);
    assert_eq!(index.count_of(Kind::Dir), 2);
    assert_eq!(index.count_of(Kind::Symlink), 1);
    assert_eq!(index.total_bytes(), 6);
}

/// The scan's fast path trusts this test and nothing else: all four of kind,
/// size, mtime and inode must agree before a file's digest is carried over.
#[test]
fn the_unchanged_test_needs_every_field_to_agree() {
    let base = Entry {
        kind: Kind::File,
        digest: file_digest(b"x"),
        size: 10,
        mode: 0o644,
        mtime: Stamp {
            secs: 100,
            nanos: 5,
        },
        ino: 42,
        target: String::new(),
    };
    assert!(base.looks_unchanged(&base.clone()));
    // The mode is deliberately not part of it: a `chmod` changes no bytes, so the
    // digest is still good and only the mode needs updating.
    assert!(base.looks_unchanged(&Entry {
        mode: 0o600,
        ..base.clone()
    }));

    for different in [
        Entry {
            size: 11,
            ..base.clone()
        },
        Entry {
            mtime: Stamp {
                secs: 100,
                nanos: 6,
            },
            ..base.clone()
        },
        Entry {
            mtime: Stamp {
                secs: 101,
                nanos: 5,
            },
            ..base.clone()
        },
        // A file replaced wholesale by a rename can land with the size and
        // timestamp of the original. The inode is what catches it.
        Entry {
            ino: 43,
            ..base.clone()
        },
        Entry {
            kind: Kind::Symlink,
            ..base.clone()
        },
    ] {
        assert!(
            !base.looks_unchanged(&different),
            "{different:?} should differ"
        );
    }
}
