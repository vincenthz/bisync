//! Digests, and the properties the whole design leans on.

use bisync::hash::{
    Child, ChildKind, Digest, Hasher, digest_reader, dir_digest, empty_dir_digest, file_digest,
    symlink_digest,
};

fn child(name: &str, kind: ChildKind, digest: Digest, mode: u32) -> Child {
    Child::new(name.as_bytes(), kind, digest, mode)
}

/// Known answers, computed independently with Python's `hashlib.blake2b`.
///
/// The point is not that BLAKE2b works — cryptoxide's own tests cover that — but
/// that bisync's framing of it is what it claims: a one-byte domain tag followed
/// by the content, digested to 32 bytes. Two peers running different builds must
/// agree on these bytes exactly, so they are pinned here rather than derived.
#[test]
fn digests_match_an_independent_implementation() {
    assert_eq!(
        file_digest(b"abc").to_string(),
        "dc4de427ae6bedec4d12128a638a811251ab883c1636e5e835dd7e4dc4f5f43d"
    );
    assert_eq!(
        file_digest(b"").to_string(),
        "ee155ace9c40292074cb6aff8c9ccdd273c81648ff1149ef36bcea6ebb8a3e25"
    );
    assert_eq!(
        symlink_digest(b"one.txt").to_string(),
        "55984778eaffc7b3c6e5775162f86a822bf3746c36b949321e4043bee82fd5f1"
    );
    assert_eq!(
        empty_dir_digest().to_string(),
        "e88bd757ad5b9bedf372d8d3f0cf6c962a469db61a265f6418e1ffed86da29ec"
    );
    let mut children = vec![child("x", ChildKind::File, file_digest(b"hi"), 0)];
    assert_eq!(
        dir_digest(&mut children).to_string(),
        "18b92fb59f219001dad27702d2ff3aebcc62d2bc87940e4a21420d64ed3e04ff"
    );
    let mut children = vec![child("x", ChildKind::File, file_digest(b"hi"), 0o644)];
    assert_eq!(
        dir_digest(&mut children).to_string(),
        "63a457a587da6a14e7695c4def66e0fa7d6b11bcb1ab71e97d465ec2f6f725d6"
    );
}

/// A file, a symlink and a directory whose contents are the same bytes must not
/// digest alike, or a file could impersonate the listing of a directory.
#[test]
fn the_three_domains_are_separated() {
    assert_ne!(file_digest(b"x"), symlink_digest(b"x"));
    let mut empty: Vec<Child> = Vec::new();
    assert_ne!(file_digest(b""), dir_digest(&mut empty));
    assert_ne!(symlink_digest(b""), dir_digest(&mut empty));
}

/// Two filesystems return directory entries in different orders. If the digest
/// depended on that order, two identical trees would never compare equal and
/// bisync would sync forever.
#[test]
fn directory_digests_do_not_depend_on_readdir_order() {
    let a = file_digest(b"a");
    let b = file_digest(b"b");
    let c = file_digest(b"c");
    let mut forwards = vec![
        child("alpha", ChildKind::File, a, 0o644),
        child("beta", ChildKind::Dir, b, 0o755),
        child("gamma", ChildKind::Symlink, c, 0),
    ];
    let mut backwards = vec![
        child("gamma", ChildKind::Symlink, c, 0),
        child("alpha", ChildKind::File, a, 0o644),
        child("beta", ChildKind::Dir, b, 0o755),
    ];
    assert_eq!(dir_digest(&mut forwards), dir_digest(&mut backwards));
}

/// Names are length-prefixed for this reason: without it, a directory holding
/// `ab` and `c` would hash identically to one holding `a` and `bc`.
#[test]
fn child_names_cannot_run_together() {
    let d = file_digest(b"same");
    let mut one = vec![
        child("ab", ChildKind::File, d, 0),
        child("c", ChildKind::File, d, 0),
    ];
    let mut two = vec![
        child("a", ChildKind::File, d, 0),
        child("bc", ChildKind::File, d, 0),
    ];
    assert_ne!(dir_digest(&mut one), dir_digest(&mut two));
}

/// A child's kind is part of its parent's digest, so replacing a file with a
/// directory of the same name is a change even if the digests coincide.
#[test]
fn a_childs_kind_is_part_of_the_digest() {
    let d = file_digest(b"x");
    let mut as_file = vec![child("n", ChildKind::File, d, 0)];
    let mut as_dir = vec![child("n", ChildKind::Dir, d, 0)];
    assert_ne!(dir_digest(&mut as_file), dir_digest(&mut as_dir));
}

/// A `chmod` changes no bytes, so nothing but the parent's digest can carry it.
/// Without this, making a script executable would move no digest at all: the
/// descent would never look, and the two ends would compare equal while
/// disagreeing about whether the file runs.
#[test]
fn a_files_mode_is_part_of_its_parents_digest() {
    let d = file_digest(b"#!/bin/sh\n");
    let mut plain = vec![child("script", ChildKind::File, d, 0o644)];
    let mut executable = vec![child("script", ChildKind::File, d, 0o755)];
    assert_ne!(dir_digest(&mut plain), dir_digest(&mut executable));
}

/// A directory's own mode is deliberately not in the tree: it is usually a local
/// decision, and including it would have the two ends arguing over every
/// directory in perpetuity.
#[test]
fn a_directorys_own_mode_is_not_part_of_the_digest() {
    let d = empty_dir_digest();
    let mut open = vec![child("d", ChildKind::Dir, d, 0o755)];
    let mut shut = vec![child("d", ChildKind::Dir, d, 0o700)];
    assert_eq!(dir_digest(&mut open), dir_digest(&mut shut));

    // Nor a symlink's, which is meaningless on most platforms anyway.
    let t = symlink_digest(b"target");
    let mut one = vec![child("l", ChildKind::Symlink, t, 0o777)];
    let mut two = vec![child("l", ChildKind::Symlink, t, 0o644)];
    assert_eq!(dir_digest(&mut one), dir_digest(&mut two));
}

/// The sender hashes as it reads and the receiver as it writes, in chunks of
/// whatever size the transport hands them. All three routes must agree.
#[test]
fn streaming_and_one_shot_digests_agree() {
    let content: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let (streamed, len) = digest_reader(&content[..]).unwrap();
    assert_eq!(len, content.len() as u64);
    assert_eq!(streamed, file_digest(&content));

    for chunk in [1usize, 7, 4096, 65_536, 128 * 1024] {
        let mut hasher = Hasher::new();
        for part in content.chunks(chunk) {
            hasher.update(part);
        }
        assert_eq!(hasher.len(), content.len() as u64);
        assert_eq!(hasher.finish(), file_digest(&content), "chunk size {chunk}");
    }
}

#[test]
fn hex_round_trips_and_rejects_rubbish() {
    let d = file_digest(b"round trip");
    assert_eq!(Digest::parse_hex(&d.to_string()), Some(d));
    assert_eq!(d.short().len(), 12);
    assert!(d.to_string().starts_with(&d.short()));
    assert_eq!(Digest::parse_hex(""), None);
    assert_eq!(Digest::parse_hex(&"0".repeat(63)), None);
    assert_eq!(Digest::parse_hex(&"0".repeat(65)), None);
    assert_eq!(Digest::parse_hex(&"g".repeat(64)), None);
    // Uppercase in, canonical lowercase out.
    let upper = d.to_string().to_uppercase();
    assert_eq!(Digest::parse_hex(&upper), Some(d));
}
