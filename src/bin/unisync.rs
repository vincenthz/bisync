//! The `unisync` command: argument parsing and dispatch, and nothing else.
//!
//! Everything of substance is in `bisync::uni`, so the comparison, the prompt
//! and the protocol can be tested without a process. Parsing is hand-rolled for
//! the same reason it is in `bisync`: a tool that has to be installed on both
//! ends of every link is better off with a short dependency list than with a
//! nicer `--help`.

use std::io;

use bisync::config::Peer;
use bisync::uni::plan::Way;
use bisync::uni::run::{self, Options};
use bisync::util::parse_size;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
unisync — copy a directory one way over ssh, one change at a time

usage: unisync <command> [options]

commands:
  pull <[user@]host:path> [dir]   make this directory look like the peer's
  push <[user@]host:path> [dir]   make the peer's directory look like this one
  server <dir>                    the far end of a link; speaks the protocol
                                  on stdin and stdout
  help, version

Both ends hash their tree, the two are compared without either enumerating
itself at the other, and every difference is put to you one at a time:

  y  make this change      n  leave this path alone      d  show me the diff
  a  accept the rest       s  stop asking, apply what is accepted
  q  abandon the run

Nothing is written until the whole list has been answered, and nothing is
remembered between runs: no state file, no conflicts to resolve later, and no
way for a change to happen that you did not see. `bisync` is the one that keeps
two directories in step in both directions; this is for the times you want to
look at each change first.

Anything replaced or removed is copied to .unisync/diffs/<path>.<timestamp>
beforehand. Nothing prunes that but you.

options:
  -m, --max-size <size>       per-file ceiling (default 1M; k/M/G/T suffixes)
  -z, --compress [level]      compress content in flight (default level 6)
      --no-compress           send content as it is
      --delete                also propose removing what the sending side does
                              not have; without it nothing is ever taken away
  -y, --yes                   accept every proposed change without asking
  -n, --dry-run               report the plan and stop, changing nothing
  -i, --ignore <pattern>      an extra ignore rule, .gitignore syntax; may be
                              repeated. Added to the built-in list
      --no-default-ignores    start from no ignore rules at all
      --ssh <command>         the ssh client to run (default ssh)
      --ssh-option <option>   passed to ssh; may be repeated
      --remote-command <cmd>  what to run on the far side (default unisync)
  -v, --verbose               list the plan and say more about what happened
  -q, --quiet                 errors only

The peer may also be a plain path, in which case the two trees are on this
machine and the far end is a second copy of this program on a pipe — the same
code as a real link, minus ssh.

Ignore rules are the initiator's: whichever side you run this from imposes its
list on the other, or the two would not agree about what is in the tree.

exit status: 0 done, 1 an error, or a change that could not be carried out.
";

fn main() {
    let code = match dispatch(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("unisync: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn dispatch(args: Vec<String>) -> io::Result<i32> {
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        print!("{HELP}");
        return Ok(0);
    };

    let mut opts = Options::default();
    let mut positional: Vec<String> = Vec::new();

    let rest: Vec<String> = args.collect();
    let mut i = 0;
    while i < rest.len() {
        let arg = rest[i].clone();
        // `--flag=value` as well as `--flag value`; both spellings are common
        // enough that refusing one is just an irritation.
        let (arg, inline) = match arg.split_once('=') {
            Some((flag, value)) if flag.starts_with('-') => {
                (flag.to_string(), Some(value.to_string()))
            }
            _ => (arg, None),
        };
        let mut value = |name: &str| -> io::Result<String> {
            if let Some(value) = inline.clone() {
                return Ok(value);
            }
            i += 1;
            rest.get(i).cloned().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("{name} needs a value"))
            })
        };
        match arg.as_str() {
            "-m" | "--max-size" => {
                let raw = value("--max-size")?;
                opts.max_size = parse_size(&raw).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{raw:?} is not a size"),
                    )
                })?;
            }
            "-z" | "--compress" => {
                // The level is optional: `-z` alone means the default, and
                // `-z 1` or `--compress=9` names one. A bare `-z` before a
                // positional argument must not eat it.
                opts.compress = match inline.clone() {
                    Some(level) => parse_level(&level)?,
                    None => match rest.get(i + 1).map(String::as_str) {
                        Some(next) if next.chars().all(|c| c.is_ascii_digit()) => {
                            i += 1;
                            parse_level(next)?
                        }
                        _ => bisync::compress::DEFAULT_LEVEL,
                    },
                };
            }
            "--no-compress" => opts.compress = 0,
            "--delete" => opts.delete = true,
            "-y" | "--yes" => opts.yes = true,
            "-n" | "--dry-run" => opts.dry_run = true,
            "-i" | "--ignore" => opts.ignore.push(value("--ignore")?),
            "--no-default-ignores" => opts.default_ignores = false,
            "--ssh" => opts.ssh = value("--ssh")?,
            "--ssh-option" => opts.ssh_options.push(value("--ssh-option")?),
            "--remote-command" => opts.remote_command = value("--remote-command")?,
            "-v" | "--verbose" => opts.verbose = true,
            "-q" | "--quiet" => opts.quiet = true,
            "-h" | "--help" => {
                print!("{HELP}");
                return Ok(0);
            }
            other if other.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown option {other:?}; `unisync help` lists them"),
                ));
            }
            _ => positional.push(arg),
        }
        i += 1;
    }

    if opts.yes && opts.dry_run {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--yes accepts every change and --dry-run makes none; pick one",
        ));
    }

    match command.as_str() {
        "pull" | "push" => {
            let way = if command == "pull" {
                Way::Pull
            } else {
                Way::Push
            };
            let Some(peer) = positional.first() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("say where to {command} from: unisync {command} user@host:/path [dir]"),
                ));
            };
            let peer = Peer::parse(peer);
            let root = root_of(positional.get(1).map(String::as_str))?;
            run::transfer(&root, &peer, way, &opts)
        }
        "server" => {
            let root = root_of(positional.first().map(String::as_str))?;
            run::server(&root)
        }
        "help" => {
            print!("{HELP}");
            Ok(0)
        }
        "version" | "--version" | "-V" => {
            println!("unisync {VERSION} (protocol {})", bisync::proto::VERSION);
            Ok(0)
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown command {other:?}; `unisync help` lists them"),
        )),
    }
}

/// A `--compress` level, checked against what the compressor accepts.
fn parse_level(raw: &str) -> io::Result<u8> {
    match raw.parse::<u8>() {
        Ok(level) if level <= bisync::compress::MAX_LEVEL => Ok(level),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "compression level must be 0 to {}, not {raw:?}",
                bisync::compress::MAX_LEVEL
            ),
        )),
    }
}

/// Where the local tree is, from an argument or the working directory.
fn root_of(arg: Option<&str>) -> io::Result<std::path::PathBuf> {
    match arg {
        Some(arg) => std::path::PathBuf::from(arg)
            .canonicalize()
            .map_err(|e| io::Error::new(e.kind(), format!("{arg}: {e}"))),
        None => std::env::current_dir(),
    }
}
