//! `.bisync/config`, and the peer address.
//!
//! The format is one `key = value` per line, `#` for comments, and repeated keys
//! accumulating into a list. That is not TOML and does not pretend to be — there
//! are nine keys, one of them is a list of glob patterns, and glob patterns in
//! TOML need quoting rules nobody wants to think about while editing an ignore
//! list. Values run to the end of the line and are trimmed; nothing is quoted,
//! so nothing needs unquoting.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::compress;
use crate::ignore::{DEFAULT_PATTERNS, IgnoreSet};
use crate::merge::Policy;
use crate::util::{format_size, parse_size};

/// Default ceiling on a file bisync will transfer.
///
/// A bidirectional sync watching a working directory is the wrong tool for
/// multi-gigabyte artefacts: every save re-sends the whole thing, and there is no
/// delta encoding here to soften it. So the default declines them, says so, and
/// leaves raising the limit to someone who has decided they want that.
pub const DEFAULT_MAX_SIZE: u64 = 1024 * 1024;

/// How long the filesystem must go quiet before a change is acted on. An editor
/// writing a file produces several events — truncate, write, rename, chmod — and
/// acting on the first would send a file that is still being written.
pub const DEFAULT_DEBOUNCE_MS: u64 = 400;

/// Rescan interval for the polling watcher, and the ceiling on how long the
/// native watchers wait before checking anyway. A dropped event should cost a
/// delay, not a permanently missed file.
pub const DEFAULT_POLL_SECS: u64 = 60;

#[derive(Clone, Debug)]
pub struct Config {
    /// The other end. `None` until `bisync init`.
    pub peer: Option<Peer>,
    pub max_size: u64,
    pub conflict: Policy,
    /// The ssh client to run, and the options to pass it.
    pub ssh: String,
    pub ssh_options: Vec<String>,
    /// The command that starts bisync on the far side; it must be on the remote
    /// `PATH`, or given as an absolute path.
    pub remote_command: String,
    pub debounce: Duration,
    pub poll_interval: Duration,
    /// DEFLATE level for content in flight, or 0 to send it uncompressed.
    pub compress: u8,
    /// Ignore patterns as written. Empty means [`DEFAULT_PATTERNS`].
    pub ignore: Vec<String>,
    /// Force the polling watcher even where a native one is available. For
    /// network filesystems, which report nothing.
    pub poll_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            peer: None,
            max_size: DEFAULT_MAX_SIZE,
            conflict: Policy::default(),
            ssh: "ssh".to_string(),
            ssh_options: Vec::new(),
            remote_command: "bisync".to_string(),
            debounce: Duration::from_millis(DEFAULT_DEBOUNCE_MS),
            poll_interval: Duration::from_secs(DEFAULT_POLL_SECS),
            compress: compress::DEFAULT_LEVEL,
            ignore: Vec::new(),
            poll_only: false,
        }
    }
}

impl Config {
    /// The compiled ignore rules: what the config lists, or the defaults if it
    /// lists nothing.
    pub fn ignore_set(&self) -> IgnoreSet {
        if self.ignore.is_empty() {
            IgnoreSet::defaults()
        } else {
            IgnoreSet::new(&self.ignore)
        }
    }

    pub fn load(path: &Path) -> io::Result<Config> {
        match fs::read_to_string(path) {
            Ok(text) => Config::parse(&text).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e),
        }
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let mut cfg = Config::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("line {}: expected `key = value`", n + 1));
            };
            let (key, value) = (key.trim(), value.trim());
            let bad = |what: &str| Err(format!("line {}: {what}", n + 1));
            match key {
                "peer" => cfg.peer = Some(Peer::parse(value)),
                "max-size" => match parse_size(value) {
                    Some(size) => cfg.max_size = size,
                    None => return bad(&format!("{value:?} is not a size")),
                },
                "conflict" => match Policy::parse(value) {
                    Some(policy) => cfg.conflict = policy,
                    None => return bad("conflict must be quarantine, local, remote or newer"),
                },
                "ssh" => cfg.ssh = value.to_string(),
                "ssh-option" => cfg.ssh_options.push(value.to_string()),
                "remote-command" => cfg.remote_command = value.to_string(),
                "debounce-ms" => match value.parse() {
                    Ok(ms) => cfg.debounce = Duration::from_millis(ms),
                    Err(_) => return bad("debounce-ms must be a whole number"),
                },
                "poll-secs" => match value.parse() {
                    Ok(s) => cfg.poll_interval = Duration::from_secs(s),
                    Err(_) => return bad("poll-secs must be a whole number"),
                },
                "poll-only" => match value {
                    "yes" | "true" => cfg.poll_only = true,
                    "no" | "false" => cfg.poll_only = false,
                    _ => return bad("poll-only must be yes or no"),
                },
                "compress" => match parse_compress(value) {
                    Some(level) => cfg.compress = level,
                    None => {
                        return bad("compress must be no, yes, or a level from 1 to 10");
                    }
                },
                "ignore" => cfg.ignore.push(value.to_string()),
                key => return bad(&format!("unknown key {key:?}")),
            }
        }
        Ok(cfg)
    }

    /// Render a config file, with the defaults spelled out so they can be edited
    /// rather than guessed at.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# bisync configuration. `key = value`, one per line;\n");
        out.push_str("# `ignore` may be repeated. Values are not quoted.\n\n");
        match &self.peer {
            Some(peer) => out.push_str(&format!("peer = {peer}\n")),
            None => out.push_str("# peer = user@host:/path/to/the/other/copy\n"),
        }
        out.push_str("\n# Files bigger than this are not transferred, and are listed by\n");
        out.push_str("# `bisync status`. Suffixes are powers of 1024.\n");
        out.push_str(&format!("max-size = {}\n", format_size(self.max_size)));
        out.push_str("\n# quarantine: keep both versions and freeze the path (default)\n");
        out.push_str("# local | remote: that side wins, the loser goes to quarantine\n");
        out.push_str("# newer: the later mtime wins; needs the two clocks to agree\n");
        out.push_str(&format!("conflict = {}\n", self.conflict.name()));
        out.push_str("\n# Transport. The remote command must be on the far side's PATH.\n");
        out.push_str(&format!("ssh = {}\n", self.ssh));
        for option in &self.ssh_options {
            out.push_str(&format!("ssh-option = {option}\n"));
        }
        if self.ssh_options.is_empty() {
            out.push_str("# ssh-option = -oBatchMode=yes\n");
        }
        out.push_str(&format!("remote-command = {}\n", self.remote_command));
        out.push_str("\n# Quiet period before a filesystem change is acted on.\n");
        out.push_str(&format!("debounce-ms = {}\n", self.debounce.as_millis()));
        out.push_str("\n# Full rescan interval. Also the polling watcher's period.\n");
        out.push_str(&format!("poll-secs = {}\n", self.poll_interval.as_secs()));
        out.push_str("# Set for network filesystems, which report no events.\n");
        out.push_str(&format!(
            "poll-only = {}\n",
            if self.poll_only { "yes" } else { "no" }
        ));
        out.push_str("\n# Compress content in flight. `no` to send it as it is, or a\n");
        out.push_str("# DEFLATE level from 1 to 10; higher spends more time for less\n");
        out.push_str("# return. Each chunk travels compressed only if that is smaller,\n");
        out.push_str("# so this never costs bytes — only CPU. `bisync status` reports\n");
        out.push_str("# what it has saved on this tree.\n");
        out.push_str(&format!(
            "compress = {}\n",
            if self.compress == 0 {
                "no".to_string()
            } else {
                self.compress.to_string()
            }
        ));
        out.push_str("\n# Ignore rules, in .gitignore syntax. These are the built-in\n");
        out.push_str("# defaults; the side that starts a session imposes its list on\n");
        out.push_str("# the other, so both ends should agree.\n");
        let patterns: Vec<String> = if self.ignore.is_empty() {
            DEFAULT_PATTERNS.iter().map(|s| s.to_string()).collect()
        } else {
            self.ignore.clone()
        };
        for pattern in patterns {
            out.push_str(&format!("ignore = {pattern}\n"));
        }
        out
    }
}

/// Parse the `compress` setting: `no`, `yes`, or a level.
fn parse_compress(value: &str) -> Option<u8> {
    match value {
        "no" | "false" | "off" | "0" => Some(0),
        "yes" | "true" | "on" => Some(compress::DEFAULT_LEVEL),
        level => match level.parse::<u8>() {
            Ok(level) if level <= compress::MAX_LEVEL => Some(level),
            _ => None,
        },
    }
}

/// The other copy: a path on this machine, or one reached over ssh.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Peer {
    /// `[user@]host:path`.
    Remote {
        user: Option<String>,
        host: String,
        path: String,
    },
    /// A plain path. Two directories on one machine still talk over a pipe to a
    /// second process, so this exercises exactly the same code as a real link —
    /// which is why the tests use it, and why it is a supported way to keep two
    /// local trees in step rather than a debugging back door.
    Local(PathBuf),
}

impl Peer {
    /// Parse in rsync's spelling. Anything without a `:` before the first `/` is
    /// a local path, so `/srv/data` and `./copy` mean what they look like, and a
    /// Windows `C:\data` is not mistaken for a host called `C`.
    pub fn parse(s: &str) -> Peer {
        let host_part = match s.find('/') {
            Some(slash) => &s[..slash],
            None => s,
        };
        let Some(colon) = host_part.find(':') else {
            return Peer::Local(PathBuf::from(s));
        };
        if colon == 1 && cfg!(windows) {
            return Peer::Local(PathBuf::from(s));
        }
        let (target, path) = s.split_at(colon);
        let path = &path[1..];
        let (user, host) = match target.split_once('@') {
            Some((user, host)) => (Some(user.to_string()), host.to_string()),
            None => (None, target.to_string()),
        };
        Peer::Remote {
            user,
            host,
            path: if path.is_empty() {
                ".".to_string()
            } else {
                path.to_string()
            },
        }
    }

    pub fn path(&self) -> String {
        match self {
            Peer::Remote { path, .. } => path.clone(),
            Peer::Local(path) => path.display().to_string(),
        }
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Peer::Remote {
                user: Some(user),
                host,
                path,
            } => write!(f, "{user}@{host}:{path}"),
            Peer::Remote {
                user: None,
                host,
                path,
            } => write!(f, "{host}:{path}"),
            Peer::Local(path) => write!(f, "{}", path.display()),
        }
    }
}
