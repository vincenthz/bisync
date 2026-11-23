//! The wire format: every message must survive the round trip, and no malformed
//! frame may become a plausible one.

use bisync::compress::Encoding;
use bisync::hash::file_digest;
use bisync::proto::{Change, Dest, Level, Msg, Reject, Root, WantItem};
use bisync::tree::{Child, Kind, PathState, Stamp};
use bisync::wire::DecodeError;

fn stamp() -> Stamp {
    Stamp {
        secs: 1_775_000_000,
        nanos: 123_456_789,
    }
}

fn root() -> Root {
    Root {
        digest: file_digest(b"root"),
        files: 12,
        dirs: 3,
        symlinks: 1,
        bytes: 987_654,
        oversize: 2,
        oversize_bytes: 5_000_000,
    }
}

/// Round-trip a message through the framing the transport uses: a `u32` length
/// then the body.
fn round_trip(msg: &Msg) -> Msg {
    let frame = msg.encode();
    let len = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
    assert_eq!(
        len,
        frame.len() - 4,
        "length prefix disagrees with the frame"
    );
    Msg::decode(&frame[4..]).unwrap_or_else(|e| panic!("{}: {e}", msg.name()))
}

#[test]
fn every_message_survives_the_round_trip() {
    let digest = file_digest(b"content");
    let messages = vec![
        Msg::Hello {
            version: 1,
            program: "bisync 0.1.0".into(),
            max_size: 1 << 20,
            ignore: vec!["target/".into(), "*.tmp".into()],
            policy: bisync::merge::Policy::Newer,
            direction: bisync::merge::Direction::Pull,
            dry_run: true,
            compress: 6,
            watch: true,
        },
        Msg::Welcome {
            version: 1,
            program: "bisync 0.1.0".into(),
            own_ignore: file_digest(b"rules"),
            root: root(),
        },
        Msg::Rescan,
        Msg::Root(root()),
        Msg::ListDir { path: "a/b".into() },
        Msg::DirList {
            path: "a/b".into(),
            exists: true,
            digest,
            children: vec![
                Child {
                    name: "file.txt".into(),
                    kind: Kind::File,
                    digest,
                    size: 42,
                    mode: 0o644,
                    mtime: stamp(),
                    target: String::new(),
                },
                Child {
                    name: "sub".into(),
                    kind: Kind::Dir,
                    digest,
                    size: 0,
                    mode: 0o755,
                    mtime: Stamp::default(),
                    target: String::new(),
                },
                Child {
                    name: "link".into(),
                    kind: Kind::Symlink,
                    digest,
                    size: 0,
                    mode: 0,
                    mtime: stamp(),
                    target: "../elsewhere".into(),
                },
            ],
        },
        Msg::Announce {
            changes: vec![
                Change {
                    path: "a.txt".into(),
                    from: PathState::Absent,
                    to: PathState::File {
                        digest,
                        size: 7,
                        mode: 0o600,
                    },
                    mtime: stamp(),
                },
                Change {
                    path: "gone".into(),
                    from: PathState::File {
                        digest,
                        size: 1,
                        mode: 0o644,
                    },
                    to: PathState::Absent,
                    mtime: Stamp::default(),
                },
                Change {
                    path: "l".into(),
                    from: PathState::Dir,
                    to: PathState::Symlink { target: "t".into() },
                    mtime: stamp(),
                },
            ],
        },
        Msg::Want {
            items: vec![
                WantItem {
                    path: "a.txt".into(),
                    digest,
                    dest: Dest::Live,
                },
                WantItem {
                    path: "b.txt".into(),
                    digest,
                    dest: Dest::Quarantine,
                },
            ],
        },
        Msg::Applied {
            paths: vec!["a".into(), "b/c".into()],
        },
        Msg::Rejected {
            items: vec![
                ("a".into(), Reject::HaveNewer, "newer here".into()),
                ("b".into(), Reject::Conflict, "both edited".into()),
                ("c".into(), Reject::Held, String::new()),
                ("d".into(), Reject::Ignored, "target/".into()),
                ("e".into(), Reject::TooLarge, "4M".into()),
                ("f".into(), Reject::Failed, "disk full".into()),
            ],
        },
        Msg::FileStart {
            xfer: 7,
            path: "a/b.bin".into(),
            dest: Dest::Live,
            digest,
            size: 1234,
            mode: 0o600,
            mtime: stamp(),
        },
        Msg::FileData {
            xfer: 7,
            encoding: Encoding::Raw,
            plain_len: 5,
            data: vec![0, 1, 2, 254, 255],
        },
        Msg::FileData {
            xfer: 7,
            encoding: Encoding::Raw,
            plain_len: 0,
            data: Vec::new(),
        },
        Msg::FileData {
            xfer: 7,
            encoding: Encoding::Deflate,
            plain_len: 4096,
            data: vec![9; 40],
        },
        Msg::FileEnd { xfer: 7 },
        Msg::FileAbort {
            xfer: 7,
            reason: "changed while being sent".into(),
        },
        Msg::Note {
            level: Level::Info,
            text: "hello".into(),
        },
        Msg::Note {
            level: Level::Warn,
            text: "careful".into(),
        },
        Msg::Note {
            level: Level::Conflict,
            text: "frozen".into(),
        },
        Msg::Error {
            text: "protocol mismatch".into(),
        },
        Msg::Bye,
        Msg::Ping { token: u64::MAX },
        Msg::Pong { token: 0 },
    ];
    for msg in &messages {
        assert_eq!(&round_trip(msg), msg, "{}", msg.name());
        assert!(!msg.name().is_empty());
    }
}

/// Pre-epoch and negative timestamps do occur, in restored archives and on
/// filesystems with odd clocks. They must not become a different instant.
#[test]
fn timestamps_survive_including_before_the_epoch() {
    for (secs, nanos) in [
        (0i64, 0u32),
        (-1, 0),
        (-1, 999_999_999),
        (i64::MIN / 2, 5),
        (i64::MAX / 2, 999_999_999),
    ] {
        let msg = Msg::FileEnd { xfer: 1 };
        let _ = msg;
        let stamp = Stamp { secs, nanos };
        let announced = Msg::Announce {
            changes: vec![Change {
                path: "x".into(),
                from: PathState::Absent,
                to: PathState::Dir,
                mtime: stamp,
            }],
        };
        let Msg::Announce { changes } = round_trip(&announced) else {
            panic!()
        };
        assert_eq!(changes[0].mtime, stamp);
    }
    // And the conversion to and from `SystemTime` is lossless for times a
    // filesystem can actually hold.
    for (secs, nanos) in [(0i64, 0u32), (1_775_000_000, 123_456_789), (-86_400, 500)] {
        let stamp = Stamp { secs, nanos };
        assert_eq!(Stamp::from_system(stamp.to_system()), stamp);
    }
}

/// A path arriving from a peer is validated at the point of decoding, so no
/// later code has to remember to.
#[test]
fn paths_from_a_peer_are_refused_at_the_door() {
    for path in ["../escape", "..", "/etc/passwd", "a/../../b", "a//b"] {
        let frame = Msg::ListDir {
            path: "PLACEHOLDER".into(),
        }
        .encode();
        // Rebuild the frame by hand with the hostile path, since `encode` is
        // given a value the type system cannot constrain.
        let mut body = Vec::new();
        body.push(0x12u8); // T_LIST_DIR
        body.extend_from_slice(&(path.len() as u32).to_le_bytes());
        body.extend_from_slice(path.as_bytes());
        let _ = frame;
        match Msg::decode(&body) {
            Err(DecodeError::BadPath(_)) => {}
            other => panic!("{path:?} was accepted as {other:?}"),
        }
    }
}

/// The root is a legal `ListDir` target and an illegal target for anything that
/// writes: `Announce`, `Want` and `FileStart` all name something to change.
#[test]
fn the_root_is_not_a_writable_target() {
    let mut body = vec![0x21u8]; // T_WANT
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // empty path
    body.extend_from_slice(file_digest(b"x").as_bytes());
    body.push(0);
    assert!(matches!(Msg::decode(&body), Err(DecodeError::BadPath(_))));

    // But listing it is exactly how a descent starts.
    let mut body = vec![0x12u8];
    body.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        Msg::decode(&body).unwrap(),
        Msg::ListDir {
            path: String::new()
        }
    );
}

#[test]
fn malformed_frames_are_errors_rather_than_guesses() {
    assert_eq!(Msg::decode(&[]), Err(DecodeError::Truncated));
    assert!(matches!(
        Msg::decode(&[0xff]),
        Err(DecodeError::BadTag { .. })
    ));
    // A complete message with rubbish appended: the two ends disagree about the
    // format, which is worth an error rather than a shrug.
    let mut frame = Msg::Bye.encode();
    frame.push(0);
    assert!(matches!(
        Msg::decode(&frame[4..]),
        Err(DecodeError::Trailing(1))
    ));
    // A truncated body.
    let frame = Msg::Ping { token: 1 }.encode();
    assert_eq!(
        Msg::decode(&frame[4..frame.len() - 2]),
        Err(DecodeError::Truncated)
    );
    // A string length prefix beyond what any field may hold: refused before
    // anything is allocated on the strength of it.
    let mut body = vec![0x40u8, 0]; // T_NOTE, Level::Info
    body.extend_from_slice(&1_000_000u32.to_le_bytes());
    assert!(matches!(
        Msg::decode(&body),
        Err(DecodeError::TooLong { .. })
    ));
    // A plausible prefix that the frame simply does not carry.
    let mut body = vec![0x40u8, 0];
    body.extend_from_slice(&64u32.to_le_bytes());
    body.extend_from_slice(b"short");
    assert_eq!(Msg::decode(&body), Err(DecodeError::Truncated));
    // A count that could not possibly be backed by the remaining bytes, so a
    // corrupt length cannot provoke a huge allocation.
    let mut body = vec![0x22u8]; // T_APPLIED
    body.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        Msg::decode(&body),
        Err(DecodeError::TooLong { .. })
    ));
}

/// The body of an encoded frame, for tests that corrupt one byte of a message
/// that was valid to begin with. Building hostile frames by hand tends to trip
/// an unrelated guard first and prove nothing.
fn body_of(msg: &Msg) -> Vec<u8> {
    msg.encode()[4..].to_vec()
}

#[test]
fn unknown_enum_tags_are_rejected() {
    let digest = file_digest(b"x");

    let want = Msg::Want {
        items: vec![WantItem {
            path: "a".into(),
            digest,
            dest: Dest::Live,
        }],
    };
    let mut body = body_of(&want);
    *body.last_mut().unwrap() = 9;
    assert!(matches!(
        Msg::decode(&body),
        Err(DecodeError::BadTag {
            field: "destination",
            ..
        })
    ));

    let listing = Msg::DirList {
        path: String::new(),
        exists: true,
        digest,
        children: vec![Child {
            name: "n".into(),
            kind: Kind::File,
            digest,
            size: 0,
            mode: 0,
            mtime: Stamp::default(),
            target: String::new(),
        }],
    };
    // tag, path length, (empty path), exists, digest, child count, name length,
    // name — and then the kind byte.
    let kind_at = 1 + 4 + 1 + 32 + 4 + 4 + 1;
    let mut body = body_of(&listing);
    assert_eq!(body[kind_at], Kind::File.as_child() as u8);
    body[kind_at] = 7;
    assert!(matches!(
        Msg::decode(&body),
        Err(DecodeError::BadTag {
            field: "child kind",
            ..
        })
    ));

    let announced = Msg::Announce {
        changes: vec![Change {
            path: "a".into(),
            from: PathState::Absent,
            to: PathState::Dir,
            mtime: Stamp::default(),
        }],
    };
    let state_at = 1 + 4 + 4 + 1; // tag, count, path length, name
    let mut body = body_of(&announced);
    body[state_at] = 9;
    assert!(matches!(
        Msg::decode(&body),
        Err(DecodeError::BadTag {
            field: "path state",
            ..
        })
    ));
}

/// A directory listing's child names are single components, so a name that is
/// really a path cannot smuggle one past the descent and be joined onto a
/// directory as if it were a name.
#[test]
fn child_names_cannot_contain_a_separator() {
    let digest = file_digest(b"x");
    let listing = Msg::DirList {
        path: String::new(),
        exists: true,
        digest,
        children: vec![Child {
            name: "ab".into(),
            kind: Kind::File,
            digest,
            size: 0,
            mode: 0,
            mtime: Stamp::default(),
            target: String::new(),
        }],
    };
    let name_at = 1 + 4 + 1 + 32 + 4 + 4;
    let mut body = body_of(&listing);
    assert_eq!(&body[name_at..name_at + 2], b"ab");
    body[name_at..name_at + 2].copy_from_slice(b"a/");
    assert!(matches!(Msg::decode(&body), Err(DecodeError::BadPath(_))));

    // And `..` as a whole name, which is what a traversal attempt looks like
    // once it has been split into components.
    body[name_at..name_at + 2].copy_from_slice(b"..");
    assert!(matches!(Msg::decode(&body), Err(DecodeError::BadPath(_))));
}
