//! What a session does when the far end misbehaves.
//!
//! The peer is a program launched over ssh, but it is still the far side of a
//! link: an older version, a corrupted stream, or something that is not bisync
//! at all. None of that may become a write outside the tree or a write nobody
//! asked for.

mod common;

use bisync::compress::Encoding;
use bisync::hash::file_digest;
use bisync::proto::{Dest, Msg, Reject};
use bisync::session::{Role, Session, Settings};
use bisync::state::State;
use bisync::store::Store;
use bisync::tree::Stamp;

use common::Temp;

/// Drive one session by hand, with no peer at all, and collect what it says.
fn with_session(t: &Temp, f: impl FnOnce(&mut Session<'_>)) -> Vec<Msg> {
    let mut store = Store::open(t.path()).unwrap();
    let (mut state, _) = State::load(&store.state_path(), "peer").unwrap();
    let mut session = Session::new(Role::Responder, Settings::default(), &mut store, &mut state);
    session.rescan().unwrap();
    let mut out = session.take_out();
    f(&mut session);
    out.extend(session.take_out());
    out
}

/// The check that makes the tree writable only by agreement: content is accepted
/// only for a path this side asked for, at the digest it asked for. Without it, a
/// peer could write anywhere in the tree by announcing nothing and simply
/// starting to send.
#[test]
fn content_nobody_asked_for_is_refused() {
    let t = Temp::new("unsolicited");
    t.write("existing.txt", "mine");

    let content = b"planted by the peer";
    let out = with_session(&t, |session| {
        for path in ["planted.txt", "existing.txt", "deep/planted.txt"] {
            session
                .handle(Msg::FileStart {
                    xfer: 1,
                    path: path.into(),
                    dest: Dest::Live,
                    digest: file_digest(content),
                    size: content.len() as u64,
                    mode: 0o644,
                    mtime: Stamp::default(),
                })
                .unwrap();
            session
                .handle(Msg::FileData {
                    xfer: 1,
                    encoding: Encoding::Raw,
                    plain_len: content.len() as u32,
                    data: content.to_vec(),
                })
                .unwrap();
            session.handle(Msg::FileEnd { xfer: 1 }).unwrap();
        }
    });

    assert!(!t.exists("planted.txt"));
    assert!(!t.exists("deep/planted.txt"));
    assert_eq!(t.read("existing.txt"), "mine");
    let rejections: Vec<&(String, Reject, String)> = out
        .iter()
        .filter_map(|m| match m {
            Msg::Rejected { items } => Some(items),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(rejections.len(), 3, "{out:#?}");
    for (_, reason, detail) in rejections {
        assert_eq!(*reason, Reject::Failed);
        assert_eq!(detail, "not requested");
    }
    // And nothing was left in the temporary area on the way to being refused.
    assert_eq!(
        std::fs::read_dir(t.path().join(".bisync/tmp"))
            .unwrap()
            .count(),
        0
    );
}

/// Data for a transfer that was never opened, and an end for one that was never
/// started. Both are noise on a stream, and neither may become a file.
#[test]
fn stray_transfer_frames_are_ignored() {
    let t = Temp::new("stray");
    let out = with_session(&t, |session| {
        session
            .handle(Msg::FileData {
                xfer: 99,
                encoding: Encoding::Raw,
                plain_len: 3,
                data: vec![1, 2, 3],
            })
            .unwrap();
        session.handle(Msg::FileEnd { xfer: 99 }).unwrap();
        session
            .handle(Msg::FileAbort {
                xfer: 99,
                reason: "never mind".into(),
            })
            .unwrap();
    });
    assert!(t.list().is_empty(), "{:?}", t.list());
    assert!(!out.iter().any(|m| matches!(m, Msg::Applied { .. })));
}

/// A peer speaking a different protocol version is refused rather than
/// half-understood. A partial sync is worse than a refused one.
#[test]
fn a_version_mismatch_ends_the_session() {
    let t = Temp::new("version");
    let mut store = Store::open(t.path()).unwrap();
    let (mut state, _) = State::load(&store.state_path(), "peer").unwrap();
    let mut session = Session::new(Role::Responder, Settings::default(), &mut store, &mut state);
    session
        .handle(Msg::Hello {
            version: bisync::proto::VERSION + 99,
            program: "bisync 9.9.9".into(),
            max_size: 1 << 20,
            ignore: vec![],
            policy: bisync::merge::Policy::Quarantine,
            direction: bisync::merge::Direction::Both,
            dry_run: false,
            compress: 0,
            watch: false,
        })
        .unwrap();
    let out = session.take_out();
    assert!(
        out.iter().any(|m| matches!(m, Msg::Error { .. })),
        "no error sent: {out:#?}"
    );
    assert!(session.failure().is_some());
    // And it did not proceed to describe its tree to something it cannot talk to.
    assert!(!out.iter().any(|m| matches!(m, Msg::Welcome { .. })));
}

/// A `Want` for something this side does not have, or has at a different
/// version, is answered rather than guessed at — sending different bytes under
/// the digest the peer asked for would be the worst possible response.
#[test]
fn a_want_for_something_we_do_not_have_is_declined() {
    let t = Temp::new("want");
    t.write("here.txt", "the current version");
    let out = with_session(&t, |session| {
        session
            .handle(Msg::Want {
                items: vec![
                    bisync::proto::WantItem {
                        path: "here.txt".into(),
                        digest: file_digest(b"some older version"),
                        dest: Dest::Live,
                    },
                    bisync::proto::WantItem {
                        path: "nowhere.txt".into(),
                        digest: file_digest(b"never existed"),
                        dest: Dest::Live,
                    },
                ],
            })
            .unwrap();
    });
    let items: Vec<&(String, Reject, String)> = out
        .iter()
        .filter_map(|m| match m {
            Msg::Rejected { items } => Some(items),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(items.len(), 2, "{out:#?}");
    assert_eq!(items[0].1, Reject::HaveNewer);
    assert_eq!(items[1].1, Reject::Failed);
    assert!(!out.iter().any(|m| matches!(m, Msg::FileStart { .. })));
}

/// The size limit is enforced on arrival as well as when deciding, so a peer
/// running a different limit cannot push a file past ours.
#[test]
fn an_oversized_announcement_is_declined() {
    let t = Temp::new("toolarge");
    let mut store = Store::open(t.path()).unwrap();
    let (mut state, _) = State::load(&store.state_path(), "peer").unwrap();
    let settings = Settings {
        max_size: 100,
        ..Settings::default()
    };
    let mut session = Session::new(Role::Responder, settings, &mut store, &mut state);
    session.rescan().unwrap();
    let _ = session.take_out();

    session
        .handle(Msg::Announce {
            changes: vec![bisync::proto::Change {
                path: "big.bin".into(),
                from: bisync::tree::PathState::Absent,
                to: bisync::tree::PathState::File {
                    digest: file_digest(b"pretend this is large"),
                    size: 10_000,
                    mode: 0o644,
                },
                mtime: Stamp::default(),
            }],
        })
        .unwrap();
    let out = session.take_out();
    let declined = out.iter().any(|m| {
        matches!(m, Msg::Rejected { items } if items.iter().any(|(_, r, _)| *r == Reject::TooLarge))
    });
    assert!(declined, "{out:#?}");
    assert!(!out.iter().any(|m| matches!(m, Msg::Want { .. })));
    assert!(!t.exists("big.bin"));
}

/// An announcement for a path this side ignores is declined, not applied. The two
/// ends run the same rules, so this means the peer's scan predates a rule change
/// — which is a thing to say, not a thing to act on.
#[test]
fn an_announcement_for_an_ignored_path_is_declined() {
    let t = Temp::new("ignored-announce");
    let out = with_session(&t, |session| {
        session
            .handle(Msg::Announce {
                changes: vec![bisync::proto::Change {
                    path: "target/debug/artifact".into(),
                    from: bisync::tree::PathState::Absent,
                    to: bisync::tree::PathState::File {
                        digest: file_digest(b"build output"),
                        size: 12,
                        mode: 0o644,
                    },
                    mtime: Stamp::default(),
                }],
            })
            .unwrap();
    });
    let declined = out.iter().any(|m| {
        matches!(m, Msg::Rejected { items } if items.iter().any(|(_, r, _)| *r == Reject::Ignored))
    });
    assert!(declined, "{out:#?}");
    assert!(!t.exists("target/debug/artifact"));
}

/// The descent asks about each directory once. A peer that answers the same
/// listing twice — or a stream that duplicates a frame — must not send this side
/// round again.
#[test]
fn the_descent_asks_about_a_directory_only_once() {
    let t = Temp::new("dived");
    t.mkdir("d");
    let mut store = Store::open(t.path()).unwrap();
    let (mut state, _) = State::load(&store.state_path(), "peer").unwrap();
    let mut session = Session::new(Role::Initiator, Settings::default(), &mut store, &mut state);
    session.rescan().unwrap();
    session.open().unwrap();
    let _ = session.take_out();
    start_descent(&mut session);

    let child = |name: &str| bisync::tree::Child {
        name: name.into(),
        kind: bisync::tree::Kind::Dir,
        digest: file_digest(b"never matches"),
        size: 0,
        mode: 0o755,
        mtime: Stamp::default(),
        target: String::new(),
    };
    // The root listing mentions `d`, which is asked about. Then say the same
    // thing again, five times over.
    let mut asked = 0;
    for _ in 0..6 {
        session
            .handle(Msg::DirList {
                path: String::new(),
                exists: true,
                digest: file_digest(b"never matches"),
                children: vec![child("d")],
            })
            .unwrap();
        asked += session
            .take_out()
            .iter()
            .filter(|m| matches!(m, Msg::ListDir { path } if path == "d"))
            .count();
    }
    assert_eq!(asked, 1, "the same directory was asked about {asked} times");
}

/// A peer describing an infinitely deep tree gets to a bound and stops. Each
/// level is a genuinely new path, so the "asked once" rule does not apply and
/// something else has to.
#[test]
fn the_descent_stops_at_a_depth_bound() {
    let t = Temp::new("deep");
    let mut store = Store::open(t.path()).unwrap();
    let (mut state, _) = State::load(&store.state_path(), "peer").unwrap();
    let mut session = Session::new(Role::Initiator, Settings::default(), &mut store, &mut state);
    session.rescan().unwrap();
    session.open().unwrap();
    let _ = session.take_out();
    start_descent(&mut session);

    let mut listings = 0usize;
    let mut pending = vec![String::new()];
    while let Some(path) = pending.pop() {
        listings += 1;
        assert!(listings < 1000, "the descent did not stop");
        session
            .handle(Msg::DirList {
                path: path.clone(),
                exists: true,
                digest: file_digest(b"never matches"),
                children: vec![bisync::tree::Child {
                    name: "d".into(),
                    kind: bisync::tree::Kind::Dir,
                    digest: file_digest(b"nor this"),
                    size: 0,
                    mode: 0o755,
                    mtime: Stamp::default(),
                    target: String::new(),
                }],
            })
            .unwrap();
        for msg in session.take_out() {
            if let Msg::ListDir { path } = msg {
                pending.push(path);
            }
        }
    }
    // It stopped of its own accord rather than because the test gave up.
    assert!(listings > 1);
}

/// Claim a tree that differs from ours, which is what starts a descent.
fn start_descent(session: &mut Session<'_>) {
    let own_ignore = session.settings.ignore.digest();
    session
        .handle(Msg::Welcome {
            version: bisync::proto::VERSION,
            program: "peer".into(),
            own_ignore,
            root: bisync::proto::Root {
                digest: file_digest(b"different"),
                ..Default::default()
            },
        })
        .unwrap();
}
