//! The message set the two ends speak, and its framing.
//!
//! There are three conversations layered on one connection:
//!
//! * **Descent.** `Rescan`/`Root` compare tree digests; `ListDir`/`DirList` walk
//!   into whatever differs. Equal digests end the conversation immediately, so
//!   reconnecting to an unchanged peer costs two messages regardless of how big
//!   the tree is.
//! * **Propagation.** `Announce` carries `from -> to` state pairs for paths the
//!   sender has just seen change; the receiver replies `Want` for what it
//!   actually needs, `Applied` for what it settled without any content, and
//!   `Rejected` for what it declines and why.
//! * **Transfer.** `FileStart`/`FileData`/`FileEnd` stream one file into a
//!   temporary, `FileAbort` withdraws it — which is what happens when the file
//!   changes underneath the sender mid-read. Each `FileData` says whether its
//!   payload is deflated, so compression is a per-frame fact rather than a mode
//!   the two ends have to agree on and stay in step about.
//!
//! Both ends may speak at any time; nothing here is request/response at the
//! framing level. The session state machine is what imposes order.

use crate::compress::Encoding;
use crate::hash::Digest;
use crate::merge::{Direction, Policy};
use crate::relpath;
use crate::tree::{Child, Kind, PathState, Stamp};
use crate::wire::{DecodeError, Reader, Writer};

/// Wire protocol version. Bumped on any change to the message set; the two ends
/// must match exactly, because there is no field-level negotiation to fall back
/// on and a half-understood sync is worse than a refused one.
pub const VERSION: u32 = 1;

/// Largest frame accepted, payload included. `FileData` is chunked well below
/// this; the cap is here so a corrupt length prefix cannot make the receiver
/// allocate its way out of memory.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Bytes of file content per `FileData`. Big enough that framing overhead is
/// noise, small enough that an aborted transfer wastes little and progress
/// reporting stays responsive.
pub const CHUNK: usize = 128 * 1024;

/// Entries per `Announce`, so a first-contact announcement of a large tree
/// becomes several bounded frames rather than one enormous one.
pub const ANNOUNCE_BATCH: usize = 2000;

/// Where a received file is to land.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dest {
    /// Its real path in the tree.
    Live,
    /// The quarantine area — the receiver has a conflicting version of its own
    /// and wants the peer's copy for the user to look at, not to overwrite with.
    Quarantine,
    /// Nowhere. Fetched only to be compared with what is here and then discarded,
    /// which is what `--dry-run --diff` is: the transfer happens, so the diff is
    /// of the real content, and the tree is not touched.
    Inspect,
}

impl Dest {
    fn tag(self) -> u8 {
        match self {
            Dest::Live => 0,
            Dest::Quarantine => 1,
            Dest::Inspect => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, DecodeError> {
        match tag {
            0 => Ok(Dest::Live),
            1 => Ok(Dest::Quarantine),
            2 => Ok(Dest::Inspect),
            tag => Err(DecodeError::BadTag {
                field: "destination",
                tag,
            }),
        }
    }
}

/// Why a receiver is not taking something it was offered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reject {
    /// The receiver's own version is the one that moved on; it will announce it.
    HaveNewer,
    /// Both sides changed the path. The receiver has quarantined and flagged it.
    Conflict,
    /// The path is already flagged as conflicted and is frozen until resolved.
    Held,
    /// The path is ignored on this side. A rule mismatch between the two ends,
    /// or a rule added since the peer last scanned.
    Ignored,
    /// Over the receiver's size limit.
    TooLarge,
    /// The receiver tried and failed. The accompanying text says how.
    Failed,
    /// Changes are not flowing this way in this session (`--pull` / `--push`).
    Direction,
}

impl Reject {
    fn tag(self) -> u8 {
        match self {
            Reject::HaveNewer => 0,
            Reject::Conflict => 1,
            Reject::Held => 2,
            Reject::Ignored => 3,
            Reject::TooLarge => 4,
            Reject::Failed => 5,
            Reject::Direction => 6,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, DecodeError> {
        match tag {
            0 => Ok(Reject::HaveNewer),
            1 => Ok(Reject::Conflict),
            2 => Ok(Reject::Held),
            3 => Ok(Reject::Ignored),
            4 => Ok(Reject::TooLarge),
            5 => Ok(Reject::Failed),
            tag => Err(DecodeError::BadTag {
                field: "reject reason",
                tag,
            }),
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Reject::HaveNewer => "peer has a newer version",
            Reject::Conflict => "conflicting change on both sides",
            Reject::Held => "held: unresolved conflict",
            Reject::Ignored => "ignored by the peer's rules",
            Reject::TooLarge => "over the peer's size limit",
            Reject::Failed => "peer failed to apply it",
            Reject::Direction => "changes are not flowing that way in this session",
        }
    }
}

/// One announced change: what the sender believed the peer had, and what the
/// sender has now.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Change {
    pub path: String,
    /// The sender's sync base for this path — its belief about the peer's state.
    /// The receiver uses it as a cross-check on its own base; a disagreement is
    /// how a base lost to a crash is noticed rather than acted on.
    pub from: PathState,
    pub to: PathState,
    /// Modification time to restore on the receiving side. Carried alongside
    /// rather than inside [`PathState`], because it must not decide anything.
    pub mtime: Stamp,
}

/// A path a receiver wants the content of.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WantItem {
    pub path: String,
    /// The digest wanted. The sender checks it still has exactly this before
    /// sending, and the receiver checks what arrived against it.
    pub digest: Digest,
    pub dest: Dest,
}

/// Summary of a peer's tree.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Root {
    pub digest: Digest,
    pub files: u32,
    pub dirs: u32,
    pub symlinks: u32,
    pub bytes: u64,
    /// Files the peer skipped for their size, and their total. Reported so the
    /// user learns about them from either end.
    pub oversize: u32,
    pub oversize_bytes: u64,
}

/// Severity of a `Note`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    Info,
    Warn,
    Conflict,
}

impl Level {
    fn tag(self) -> u8 {
        match self {
            Level::Info => 0,
            Level::Warn => 1,
            Level::Conflict => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, DecodeError> {
        match tag {
            0 => Ok(Level::Info),
            1 => Ok(Level::Warn),
            2 => Ok(Level::Conflict),
            tag => Err(DecodeError::BadTag {
                field: "note level",
                tag,
            }),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Msg {
    /// Opens the session. Only the side that spawned the other sends this.
    Hello {
        version: u32,
        program: String,
        /// The size limit, ignore rules and conflict policy the session runs
        /// under, all chosen by the initiator.
        ///
        /// Dictated rather than merged, for the same reason in each case: two
        /// peers filtering differently would never agree on a tree digest, two
        /// peers with different limits would each offer what the other declines,
        /// and two peers resolving conflicts differently would have one side
        /// quietly overwrite while the other froze. The initiator's terms are the
        /// session's terms.
        max_size: u64,
        ignore: Vec<String>,
        policy: Policy,
        /// Which way changes may flow. Mirrored by the responder, since a
        /// direction names a way along the link rather than "away from me".
        direction: Direction,
        /// Nothing is to be changed on either side. A session term rather than a
        /// local flag: the responder applies and requests on its own initiative,
        /// so a promise that a run will change nothing is one only both ends can
        /// keep.
        dry_run: bool,
        /// DEFLATE level for content, or 0 to send it uncompressed.
        ///
        /// Unlike the others this one needs no agreement to be *safe* — every
        /// frame says how it is encoded, so a receiver decodes whatever arrives.
        /// It is a session term all the same, because the interesting case is a
        /// fast link where the answer is "don't bother", and that is a decision
        /// about the link rather than about either end of it.
        compress: u8,
        /// Whether the initiator intends to keep watching after reconciling.
        watch: bool,
    },
    Welcome {
        version: u32,
        program: String,
        /// Digest of the rules the responder would have used on its own. Equal
        /// means the two configs agree; unequal is worth telling the user about,
        /// since it means one side's config is not what they think it is.
        own_ignore: Digest,
        root: Root,
    },
    /// Rescan and reply with `Root`.
    Rescan,
    Root(Root),
    /// List the direct children of `path` (`""` is the root).
    ListDir {
        path: String,
    },
    DirList {
        path: String,
        /// False when the path is not a directory on this side at all — which is
        /// itself the answer, and saves a round trip to discover it.
        exists: bool,
        digest: Digest,
        children: Vec<Child>,
    },
    Announce {
        changes: Vec<Change>,
    },
    Want {
        items: Vec<WantItem>,
    },
    /// These paths are settled here: the receiver's state now matches what was
    /// announced, so the sender may advance its base.
    Applied {
        paths: Vec<String>,
    },
    Rejected {
        items: Vec<(String, Reject, String)>,
    },
    FileStart {
        xfer: u32,
        path: String,
        dest: Dest,
        digest: Digest,
        size: u64,
        mode: u32,
        mtime: Stamp,
    },
    FileData {
        xfer: u32,
        /// How `data` is encoded. Chosen per frame by whichever is smaller, so a
        /// chunk deflate cannot improve on travels as it is.
        encoding: Encoding,
        /// What `data` decodes to. Equal to `data.len()` when the encoding is
        /// raw; for a deflated frame it is the receiver's bound on the output,
        /// enforced rather than trusted.
        plain_len: u32,
        data: Vec<u8>,
    },
    FileEnd {
        xfer: u32,
    },
    FileAbort {
        xfer: u32,
        reason: String,
    },
    /// Something the user on the far side should see.
    Note {
        level: Level,
        text: String,
    },
    /// Fatal on the sending side; the session is over.
    Error {
        text: String,
    },
    /// Everything this side had to say. Sent before a clean close.
    Bye,
    Ping {
        token: u64,
    },
    Pong {
        token: u64,
    },
}

const T_HELLO: u8 = 0x01;
const T_WELCOME: u8 = 0x02;
const T_RESCAN: u8 = 0x10;
const T_ROOT: u8 = 0x11;
const T_LIST_DIR: u8 = 0x12;
const T_DIR_LIST: u8 = 0x13;
const T_ANNOUNCE: u8 = 0x20;
const T_WANT: u8 = 0x21;
const T_APPLIED: u8 = 0x22;
const T_REJECTED: u8 = 0x23;
const T_FILE_START: u8 = 0x30;
const T_FILE_DATA: u8 = 0x31;
const T_FILE_END: u8 = 0x32;
const T_FILE_ABORT: u8 = 0x33;
const T_NOTE: u8 = 0x40;
const T_ERROR: u8 = 0x41;
const T_BYE: u8 = 0x42;
const T_PING: u8 = 0x43;
const T_PONG: u8 = 0x44;

impl Msg {
    /// A short name for logs. Kept separate from `Debug`, which prints payloads.
    pub fn name(&self) -> &'static str {
        match self {
            Msg::Hello { .. } => "hello",
            Msg::Welcome { .. } => "welcome",
            Msg::Rescan => "rescan",
            Msg::Root(_) => "root",
            Msg::ListDir { .. } => "list-dir",
            Msg::DirList { .. } => "dir-list",
            Msg::Announce { .. } => "announce",
            Msg::Want { .. } => "want",
            Msg::Applied { .. } => "applied",
            Msg::Rejected { .. } => "rejected",
            Msg::FileStart { .. } => "file-start",
            Msg::FileData { .. } => "file-data",
            Msg::FileEnd { .. } => "file-end",
            Msg::FileAbort { .. } => "file-abort",
            Msg::Note { .. } => "note",
            Msg::Error { .. } => "error",
            Msg::Bye => "bye",
            Msg::Ping { .. } => "ping",
            Msg::Pong { .. } => "pong",
        }
    }

    /// Encode to a complete frame: `u32` length, tag, payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        // Placeholder for the length, filled in once the payload is known.
        w.u32(0);
        match self {
            Msg::Hello {
                version,
                program,
                max_size,
                ignore,
                policy,
                direction,
                dry_run,
                compress,
                watch,
            } => {
                w.u8(T_HELLO)
                    .u32(*version)
                    .str(program)
                    .u64(*max_size)
                    .bool(*watch)
                    .u8(*compress)
                    .bool(*dry_run)
                    .str(direction.name());
                // As a name rather than a tag: the set is small, the encoding is
                // then self-explanatory in a packet dump, and `Policy::parse` is
                // already the reader.
                w.str(policy.name());
                w.u32(ignore.len() as u32);
                for line in ignore {
                    w.str(line);
                }
            }
            Msg::Welcome {
                version,
                program,
                own_ignore,
                root,
            } => {
                w.u8(T_WELCOME)
                    .u32(*version)
                    .str(program)
                    .raw(own_ignore.as_bytes());
                put_root(&mut w, root);
            }
            Msg::Rescan => {
                w.u8(T_RESCAN);
            }
            Msg::Root(root) => {
                w.u8(T_ROOT);
                put_root(&mut w, root);
            }
            Msg::ListDir { path } => {
                w.u8(T_LIST_DIR).str(path);
            }
            Msg::DirList {
                path,
                exists,
                digest,
                children,
            } => {
                w.u8(T_DIR_LIST)
                    .str(path)
                    .bool(*exists)
                    .raw(digest.as_bytes());
                w.u32(children.len() as u32);
                for child in children {
                    w.str(&child.name)
                        .u8(child.kind.as_child() as u8)
                        .raw(child.digest.as_bytes())
                        .u64(child.size)
                        .u32(child.mode)
                        .i64(child.mtime.secs)
                        .u32(child.mtime.nanos)
                        .str(&child.target);
                }
            }
            Msg::Announce { changes } => {
                w.u8(T_ANNOUNCE).u32(changes.len() as u32);
                for change in changes {
                    w.str(&change.path);
                    change.from.encode(&mut w);
                    change.to.encode(&mut w);
                    w.i64(change.mtime.secs).u32(change.mtime.nanos);
                }
            }
            Msg::Want { items } => {
                w.u8(T_WANT).u32(items.len() as u32);
                for item in items {
                    w.str(&item.path)
                        .raw(item.digest.as_bytes())
                        .u8(item.dest.tag());
                }
            }
            Msg::Applied { paths } => {
                w.u8(T_APPLIED).u32(paths.len() as u32);
                for path in paths {
                    w.str(path);
                }
            }
            Msg::Rejected { items } => {
                w.u8(T_REJECTED).u32(items.len() as u32);
                for (path, reason, detail) in items {
                    w.str(path).u8(reason.tag()).str(detail);
                }
            }
            Msg::FileStart {
                xfer,
                path,
                dest,
                digest,
                size,
                mode,
                mtime,
            } => {
                w.u8(T_FILE_START)
                    .u32(*xfer)
                    .str(path)
                    .u8(dest.tag())
                    .raw(digest.as_bytes())
                    .u64(*size)
                    .u32(*mode)
                    .i64(mtime.secs)
                    .u32(mtime.nanos);
            }
            Msg::FileData {
                xfer,
                encoding,
                plain_len,
                data,
            } => {
                w.u8(T_FILE_DATA)
                    .u32(*xfer)
                    .u8(encoding.tag())
                    .u32(*plain_len)
                    .u32(data.len() as u32)
                    .raw(data);
            }
            Msg::FileEnd { xfer } => {
                w.u8(T_FILE_END).u32(*xfer);
            }
            Msg::FileAbort { xfer, reason } => {
                w.u8(T_FILE_ABORT).u32(*xfer).str(reason);
            }
            Msg::Note { level, text } => {
                w.u8(T_NOTE).u8(level.tag()).str(text);
            }
            Msg::Error { text } => {
                w.u8(T_ERROR).str(text);
            }
            Msg::Bye => {
                w.u8(T_BYE);
            }
            Msg::Ping { token } => {
                w.u8(T_PING).u64(*token);
            }
            Msg::Pong { token } => {
                w.u8(T_PONG).u64(*token);
            }
        }
        let mut buf = w.finish();
        let len = (buf.len() - 4) as u32;
        buf[..4].copy_from_slice(&len.to_le_bytes());
        buf
    }

    /// Decode a payload — the frame body with its length prefix already removed.
    pub fn decode(body: &[u8]) -> Result<Msg, DecodeError> {
        let mut r = Reader::new(body);
        let tag = r.u8()?;
        let msg = match tag {
            T_HELLO => {
                let version = r.u32()?;
                let program = r.string("program")?;
                let max_size = r.u64()?;
                let watch = r.bool()?;
                let compress = r.u8()?;
                let dry_run = r.bool()?;
                let name = r.str("direction")?;
                let direction = Direction::parse(name)
                    .ok_or_else(|| DecodeError::BadPath(format!("direction {name:?}")))?;
                let name = r.str("conflict policy")?;
                let policy = Policy::parse(name)
                    .ok_or_else(|| DecodeError::BadPath(format!("conflict policy {name:?}")))?;
                let n = r.count("ignore rules", 4)?;
                let mut ignore = Vec::with_capacity(n.min(4096));
                for _ in 0..n {
                    ignore.push(r.string("ignore rule")?);
                }
                Msg::Hello {
                    version,
                    program,
                    max_size,
                    ignore,
                    policy,
                    direction,
                    dry_run,
                    compress,
                    watch,
                }
            }
            T_WELCOME => {
                let version = r.u32()?;
                let program = r.string("program")?;
                let own_ignore = get_digest(&mut r)?;
                let root = get_root(&mut r)?;
                Msg::Welcome {
                    version,
                    program,
                    own_ignore,
                    root,
                }
            }
            T_RESCAN => Msg::Rescan,
            T_ROOT => Msg::Root(get_root(&mut r)?),
            T_LIST_DIR => {
                let path = r.string("path")?;
                relpath::validate(&path)?;
                Msg::ListDir { path }
            }
            T_DIR_LIST => {
                let path = r.string("path")?;
                relpath::validate(&path)?;
                let exists = r.bool()?;
                let digest = get_digest(&mut r)?;
                let n = r.count("children", 58)?;
                let mut children = Vec::with_capacity(n.min(65536));
                for _ in 0..n {
                    let name = r.string("child name")?;
                    // A child name is one path component. Validating it as a
                    // path catches `..`, `/` and NUL in one go — the descent
                    // joins these onto a directory path, so it matters.
                    relpath::validate(&name)?;
                    if name.is_empty() || name.contains('/') {
                        return Err(DecodeError::BadPath(name));
                    }
                    let kind = child_kind(r.u8()?)?;
                    children.push(Child {
                        name,
                        kind,
                        digest: get_digest(&mut r)?,
                        size: r.u64()?,
                        mode: r.u32()?,
                        mtime: Stamp {
                            secs: r.i64()?,
                            nanos: r.u32()?,
                        },
                        target: r.string("symlink target")?,
                    });
                }
                Msg::DirList {
                    path,
                    exists,
                    digest,
                    children,
                }
            }
            T_ANNOUNCE => {
                let n = r.count("changes", 18)?;
                let mut changes = Vec::with_capacity(n.min(ANNOUNCE_BATCH * 2));
                for _ in 0..n {
                    let path = r.string("path")?;
                    relpath::validate(&path)?;
                    if path.is_empty() {
                        return Err(DecodeError::BadPath("<root>".into()));
                    }
                    let from = PathState::decode(&mut r)?;
                    let to = PathState::decode(&mut r)?;
                    let mtime = Stamp {
                        secs: r.i64()?,
                        nanos: r.u32()?,
                    };
                    changes.push(Change {
                        path,
                        from,
                        to,
                        mtime,
                    });
                }
                Msg::Announce { changes }
            }
            T_WANT => {
                let n = r.count("want items", 37)?;
                let mut items = Vec::with_capacity(n.min(65536));
                for _ in 0..n {
                    let path = r.string("path")?;
                    relpath::validate(&path)?;
                    if path.is_empty() {
                        return Err(DecodeError::BadPath("<root>".into()));
                    }
                    items.push(WantItem {
                        path,
                        digest: get_digest(&mut r)?,
                        dest: Dest::from_tag(r.u8()?)?,
                    });
                }
                Msg::Want { items }
            }
            T_APPLIED => {
                let n = r.count("applied paths", 4)?;
                let mut paths = Vec::with_capacity(n.min(65536));
                for _ in 0..n {
                    let path = r.string("path")?;
                    relpath::validate(&path)?;
                    paths.push(path);
                }
                Msg::Applied { paths }
            }
            T_REJECTED => {
                let n = r.count("rejected items", 9)?;
                let mut items = Vec::with_capacity(n.min(65536));
                for _ in 0..n {
                    let path = r.string("path")?;
                    relpath::validate(&path)?;
                    items.push((path, Reject::from_tag(r.u8()?)?, r.string("detail")?));
                }
                Msg::Rejected { items }
            }
            T_FILE_START => {
                let xfer = r.u32()?;
                let path = r.string("path")?;
                relpath::validate(&path)?;
                if path.is_empty() {
                    return Err(DecodeError::BadPath("<root>".into()));
                }
                Msg::FileStart {
                    xfer,
                    path,
                    dest: Dest::from_tag(r.u8()?)?,
                    digest: get_digest(&mut r)?,
                    size: r.u64()?,
                    mode: r.u32()?,
                    mtime: Stamp {
                        secs: r.i64()?,
                        nanos: r.u32()?,
                    },
                }
            }
            T_FILE_DATA => {
                let xfer = r.u32()?;
                let tag = r.u8()?;
                let encoding = Encoding::from_tag(tag).ok_or(DecodeError::BadTag {
                    field: "content encoding",
                    tag,
                })?;
                let plain_len = r.u32()?;
                let len = r.u32()? as usize;
                if len > MAX_FRAME {
                    return Err(DecodeError::TooLong {
                        field: "file data",
                        len,
                    });
                }
                let data = r.raw(len)?.to_vec();
                // An uncompressed frame that disagrees with itself about its own
                // length is a confused peer, not something to guess at.
                if encoding == Encoding::Raw && plain_len as usize != data.len() {
                    return Err(DecodeError::TooLong {
                        field: "raw file data",
                        len: plain_len as usize,
                    });
                }
                Msg::FileData {
                    xfer,
                    encoding,
                    plain_len,
                    data,
                }
            }
            T_FILE_END => Msg::FileEnd { xfer: r.u32()? },
            T_FILE_ABORT => Msg::FileAbort {
                xfer: r.u32()?,
                reason: r.string("reason")?,
            },
            T_NOTE => Msg::Note {
                level: Level::from_tag(r.u8()?)?,
                text: r.string("note")?,
            },
            T_ERROR => Msg::Error {
                text: r.string("error")?,
            },
            T_BYE => Msg::Bye,
            T_PING => Msg::Ping { token: r.u64()? },
            T_PONG => Msg::Pong { token: r.u64()? },
            tag => {
                return Err(DecodeError::BadTag {
                    field: "message",
                    tag,
                });
            }
        };
        r.finish()?;
        Ok(msg)
    }
}

fn put_root(w: &mut Writer, root: &Root) {
    w.raw(root.digest.as_bytes())
        .u32(root.files)
        .u32(root.dirs)
        .u32(root.symlinks)
        .u64(root.bytes)
        .u32(root.oversize)
        .u64(root.oversize_bytes);
}

fn get_root(r: &mut Reader<'_>) -> Result<Root, DecodeError> {
    Ok(Root {
        digest: get_digest(r)?,
        files: r.u32()?,
        dirs: r.u32()?,
        symlinks: r.u32()?,
        bytes: r.u64()?,
        oversize: r.u32()?,
        oversize_bytes: r.u64()?,
    })
}

fn get_digest(r: &mut Reader<'_>) -> Result<Digest, DecodeError> {
    Ok(Digest::from_bytes(r.raw(Digest::LEN)?.try_into().unwrap()))
}

fn child_kind(tag: u8) -> Result<Kind, DecodeError> {
    match tag {
        1 => Ok(Kind::File),
        2 => Ok(Kind::Symlink),
        3 => Ok(Kind::Dir),
        tag => Err(DecodeError::BadTag {
            field: "child kind",
            tag,
        }),
    }
}
