//! Getting messages to the other end.
//!
//! The transport is `ssh` the program, not an ssh library. bisync spawns
//! `ssh host bisync server <path>` and talks its own protocol over that
//! process's stdin and stdout — the same arrangement rsync uses, and it inherits
//! the same benefits: every key, `~/.ssh/config` stanza, agent, jump host,
//! `ControlMaster` and hardware token the user already has working keeps
//! working, and bisync contains no cryptography beyond a hash function.
//!
//! Reading runs on its own thread and delivers decoded messages down a channel.
//! That is what lets the main loop wait on the peer and on the local filesystem
//! at the same time without either starving the other, and it keeps writes
//! single-threaded — the main loop is the only writer, so no lock is needed.

use std::io::{self, BufWriter, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::thread;

use crate::config::{Config, Peer};
use crate::proto::{MAX_FRAME, Msg};
use crate::wake::Wake;
use crate::wire::DecodeError;

/// An open connection to a peer.
///
/// Writes go out from whichever thread owns the `Link` — in practice the driver,
/// and only the driver, so there is no lock. Reads happen on a thread of their
/// own and arrive as [`Wake`] values on the channel the caller supplied, which
/// is the same channel the filesystem watcher uses.
pub struct Link {
    /// `None` once the link has been closed. Dropping the writer is what sends
    /// the far side an EOF, and it has to happen before waiting for it to exit.
    writer: Option<BufWriter<Box<dyn Write + Send>>>,
    child: Option<Child>,
    /// How the peer was described, for error messages.
    label: String,
}

impl Link {
    /// Wrap an already-open pair of streams. Used for `bisync server`, whose
    /// peer is whatever spawned it, and by the tests.
    pub fn new(
        label: String,
        reader: Box<dyn Read + Send>,
        writer: Box<dyn Write + Send>,
        child: Option<Child>,
        tx: Sender<Wake>,
    ) -> Link {
        thread::Builder::new()
            .name("bisync-reader".into())
            .spawn(move || read_loop(reader, tx))
            .expect("spawn reader thread");
        Link {
            writer: Some(BufWriter::new(writer)),
            child,
            label,
        }
    }

    /// Start the far side and connect to it.
    pub fn connect(peer: &Peer, cfg: &Config, watch: bool, tx: Sender<Wake>) -> io::Result<Link> {
        let mut command = match peer {
            Peer::Remote { user, host, path } => {
                let mut command = Command::new(&cfg.ssh);
                for option in &cfg.ssh_options {
                    command.arg(option);
                }
                match user {
                    Some(user) => command.arg(format!("{user}@{host}")),
                    None => command.arg(host),
                };
                // One argument, quoted, because ssh concatenates the tail and
                // hands it to the remote shell. A path with a space in it would
                // otherwise arrive as two arguments — and the flag has to go
                // inside the same string for the same reason.
                command.arg(format!(
                    "{} server {}{}",
                    cfg.remote_command,
                    shell_quote(path),
                    if watch { " --watch" } else { "" }
                ));
                command
            }
            Peer::Local(path) => {
                // The same protocol over a pipe to a second copy of ourselves.
                // `current_exe` rather than `bisync`, so a build under test talks
                // to itself and not to whatever is installed.
                let mut command = Command::new(std::env::current_exe()?);
                command.arg("server").arg(path);
                if watch {
                    command.arg("--watch");
                }
                command
            }
        };
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = command.spawn().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "could not start {:?}: {e}",
                    command.get_program().to_string_lossy()
                ),
            )
        })?;
        let stdout = child.stdout.take().expect("piped stdout");
        let stdin = child.stdin.take().expect("piped stdin");
        Ok(Link::new(
            peer.to_string(),
            Box::new(stdout),
            Box::new(stdin),
            Some(child),
            tx,
        ))
    }

    /// The connection to whoever spawned this process: stdin and stdout.
    pub fn stdio(tx: Sender<Wake>) -> Link {
        Link::new(
            "peer".to_string(),
            Box::new(io::stdin()),
            Box::new(io::stdout()),
            None,
            tx,
        )
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn send(&mut self, msg: &Msg) -> io::Result<()> {
        match self.writer.as_mut() {
            Some(writer) => writer.write_all(&msg.encode()),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "link is closed",
            )),
        }
    }

    /// Push everything buffered to the peer.
    ///
    /// Must happen before the driver blocks, or a session deadlocks with each
    /// end holding a message the other is waiting for.
    pub fn flush(&mut self) -> io::Result<()> {
        match self.writer.as_mut() {
            Some(writer) => writer.flush(),
            None => Ok(()),
        }
    }

    /// Close the link and wait for the far side to exit.
    ///
    /// Dropping our end of its stdin is what tells it to stop; a peer blocked
    /// reading sees EOF and returns.
    pub fn close(&mut self) -> io::Result<()> {
        let _ = self.flush();
        drop(self.writer.take());
        if let Some(mut child) = self.child.take() {
            match child.wait() {
                Ok(status) if status.success() => {}
                Ok(status) => {
                    return Err(io::Error::other(format!("peer exited with {status}")));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        // A session that ended early should not leave an ssh process behind
        // holding a connection open.
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Read frames until the stream ends, decoding each and sending it on.
fn read_loop(mut reader: Box<dyn Read + Send>, tx: Sender<Wake>) {
    let mut header = [0u8; 4];
    let mut body = Vec::new();
    loop {
        match read_exact_or_eof(&mut reader, &mut header) {
            Ok(true) => {}
            Ok(false) => {
                let _ = tx.send(Wake::Closed);
                return;
            }
            Err(e) => {
                let _ = tx.send(Wake::Failed(e.to_string()));
                return;
            }
        }
        let len = u32::from_le_bytes(header) as usize;
        if len == 0 || len > MAX_FRAME {
            let _ = tx.send(Wake::Failed(format!("frame of {len} bytes")));
            return;
        }
        body.resize(len, 0);
        match read_exact_or_eof(&mut reader, &mut body) {
            Ok(true) => {}
            Ok(false) => {
                let _ = tx.send(Wake::Failed("truncated frame".into()));
                return;
            }
            Err(e) => {
                let _ = tx.send(Wake::Failed(e.to_string()));
                return;
            }
        }
        match Msg::decode(&body) {
            Ok(msg) => {
                if tx.send(Wake::Msg(msg)).is_err() {
                    // The session has finished with us.
                    return;
                }
            }
            Err(e) => {
                let _ = tx.send(Wake::Failed(describe(e)));
                return;
            }
        }
    }
}

/// Fill `buf`. `Ok(false)` means a clean end of stream at a frame boundary;
/// anything else short is an error.
fn read_exact_or_eof(reader: &mut dyn Read, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short frame")),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

fn describe(e: DecodeError) -> String {
    format!("malformed message from peer: {e}")
}

/// Wrap a path for a remote shell.
///
/// Single quotes, with embedded single quotes closed and reopened around an
/// escaped one — the only construction that is safe for arbitrary bytes in every
/// POSIX shell, which is what ssh will hand this to.
fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@%_+=:,./-".contains(&b))
    {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Where a sync root lives, resolved from an argument or the working directory.
pub fn resolve_root(arg: Option<&str>) -> io::Result<std::path::PathBuf> {
    let path = match arg {
        Some(arg) => Path::new(arg).to_path_buf(),
        None => std::env::current_dir()?,
    };
    path.canonicalize()
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::shell_quote;

    #[test]
    fn quoting_leaves_plain_paths_alone_and_encloses_the_rest() {
        assert_eq!(shell_quote("/srv/data"), "/srv/data");
        assert_eq!(shell_quote("/srv/my data"), "'/srv/my data'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("a;rm -rf /"), "'a;rm -rf /'");
    }
}
