//! The `bisync` command: argument parsing and dispatch, and nothing else.
//!
//! Everything of substance is in the library, so the protocol, the merge and the
//! tree model can be tested without a process. What is left here is the shape of
//! the command line — which is not library surface, and is the one part of the
//! tool whose only caller is a shell.
//!
//! Parsing is hand-rolled, because there are eight subcommands and seven flags,
//! and a synchronisation tool that has to be installed on both ends of every
//! link is better off with a short dependency list than with a nicer `--help`.

use std::io;

use bisync::merge::{Direction, Policy};
use bisync::run::{self, Overrides};
use bisync::util::parse_size;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
bisync — keep two directories the same, in both directions, over ssh

usage: bisync <command> [directory] [options]

commands:
  init [dir]         write .bisync/config and take a first look at the tree
  sync [dir]         reconcile with the peer once, then exit
  watch [dir]        reconcile, then stay and propagate changes as they happen
  status [dir]       what is here, what has changed, what is over the limit
  conflicts [dir]    the frozen paths, and where each side's version is
  resolve <path>...  settle a conflict in favour of one side
  prune [dir]        remove old preserved versions from .bisync/diffs
  tree [dir]         the Merkle tree, for seeing why two roots disagree
  server <dir>       the far end of a link; speaks the protocol on stdin/stdout
  help, version

options:
  -p, --peer <[user@]host:path>   the other copy; also accepts a local path
  -m, --max-size <size>           per-file ceiling (default 1M; k/M/G/T suffixes)
  -c, --conflict <policy>         quarantine (default), local, remote, newer
  -z, --compress [level]          compress content in flight (default level 6)
      --no-compress               send content as it is
  -C, --dir <dir>                 the sync root, instead of a positional argument
      --poll                      rescan on a timer instead of watching natively
      --pull                      take the peer's changes; do not offer ours
      --push                      offer ours; do not take the peer's
  -n, --dry-run                   decide and report, change nothing
      --diff                      dry run, showing a diff of what would change
  -v, --verbose                   also report what did not change
  -q, --quiet                     only errors
      --local                     resolve: this side's version wins
      --remote                    resolve: the peer's version wins
      --all                       resolve: every conflict; prune: everything
      --older-than <duration>     prune: versions older than 7d, 12h, 30m ...
      --keep <n>                  prune: all but the newest n of each path
      --watch                     server: the initiator intends to stay connected

Anything in .bisync is never synced. Config lives in .bisync/config, ignore
rules go in it as repeated `ignore =` lines in .gitignore syntax, and the side
that starts a session imposes its rules and its size limit on the other.

Files over the size limit are reported and skipped, not truncated or partially
sent. Conflicting paths are frozen: nothing is overwritten, the peer's version
is fetched into .bisync/quarantine, and `bisync resolve` decides.

Content is deflated a chunk at a time, and each chunk travels compressed only
if that came out smaller, so compression never costs bytes — only CPU. What it
has saved on a tree is reported by `bisync status`.

Anything a sync overwrites or deletes locally is first copied to
.bisync/diffs/<path>.<timestamp>. Nothing removes those unless asked: `bisync
prune` does, and needs to be told what to remove.

A sync goes both ways unless told otherwise. `--pull` takes the peer's changes
without offering yours, `--push` the reverse; either way the base does not
advance for a path left alone, so a later full sync still sees it.

exit status: 0 in sync, 1 error, 2 conflicts outstanding.
";

fn main() {
    // Exit status: 0 in sync, 1 for an error, 2 while conflicts are outstanding.
    let code = match dispatch(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("bisync: {e}");
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

    let mut overrides = Overrides::default();
    let mut positional: Vec<String> = Vec::new();
    let mut keep_remote = false;
    let mut keep_local = false;
    let mut all = false;
    let mut watch_mode = false;
    let mut pull = false;
    let mut push = false;
    let mut older_than: Option<std::time::Duration> = None;
    let mut keep_newest: Option<usize> = None;

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
            "-p" | "--peer" => overrides.peer = Some(value("--peer")?),
            "-m" | "--max-size" => {
                let raw = value("--max-size")?;
                overrides.max_size = Some(parse_size(&raw).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{raw:?} is not a size"),
                    )
                })?);
            }
            "-z" | "--compress" => {
                // The level is optional: `-z` alone means the default, and
                // `-z 1` or `--compress=9` names one. A bare `-z` before a
                // positional argument must not eat it.
                overrides.compress = Some(match inline.clone() {
                    Some(level) => parse_level(&level)?,
                    None => match rest.get(i + 1).map(String::as_str) {
                        Some(next) if next.chars().all(|c| c.is_ascii_digit()) => {
                            i += 1;
                            parse_level(next)?
                        }
                        _ => bisync::compress::DEFAULT_LEVEL,
                    },
                });
            }
            "--no-compress" => overrides.compress = Some(0),
            "-c" | "--conflict" => {
                let raw = value("--conflict")?;
                overrides.conflict = Some(Policy::parse(&raw).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{raw:?} is not quarantine, local, remote or newer"),
                    )
                })?);
            }
            "-C" | "--dir" => positional.insert(0, value("--dir")?),
            "--poll" => overrides.poll_only = true,
            "--pull" => pull = true,
            "--push" => push = true,
            "-n" | "--dry-run" => overrides.dry_run = true,
            "--diff" => overrides.diff = true,
            "-v" | "--verbose" => overrides.verbose = true,
            "-q" | "--quiet" => overrides.quiet = true,
            "--local" => keep_local = true,
            "--remote" => keep_remote = true,
            "--all" => all = true,
            "--older-than" => {
                let raw = value("--older-than")?;
                older_than = Some(parse_size_of_time(&raw)?);
            }
            "--keep" => {
                let raw = value("--keep")?;
                keep_newest = Some(raw.parse().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("--keep takes a count, not {raw:?}"),
                    )
                })?);
            }
            "--watch" => watch_mode = true,
            "-h" | "--help" => {
                print!("{HELP}");
                return Ok(0);
            }
            other if other.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown option {other:?}; `bisync help` lists them"),
                ));
            }
            _ => positional.push(arg),
        }
        i += 1;
    }

    overrides.direction = match (pull, push) {
        (false, false) => Direction::Both,
        (true, false) => Direction::Pull,
        (false, true) => Direction::Push,
        (true, true) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--pull and --push are opposites; leave both off to sync each way",
            ));
        }
    };
    let overrides = overrides.resolved();

    let dir = || -> io::Result<std::path::PathBuf> {
        run::root_of(positional.first().map(String::as_str))
    };

    match command.as_str() {
        "init" => {
            // `init` may be pointed at a directory that does not exist yet, so it
            // does not go through the canonicalising `dir()`.
            let target = positional
                .first()
                .cloned()
                .unwrap_or_else(|| ".".to_string());
            run::init(
                std::path::Path::new(&target),
                overrides.peer.as_deref(),
                &overrides,
            )
        }
        "sync" => run::sync(&dir()?, &overrides),
        "watch" => run::watch(&dir()?, &overrides),
        "status" | "stat" => run::status(&dir()?, &overrides),
        "conflicts" => run::conflicts(&dir()?),
        "resolve" => {
            if keep_local && keep_remote {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--local and --remote are opposites; pick one",
                ));
            }
            if !keep_local && !keep_remote {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "say which side wins: --local or --remote",
                ));
            }
            // With `-C` the root is the first positional; otherwise the root is
            // the working directory and every positional is a path to resolve.
            let (root, paths) = split_root(&positional)?;
            run::resolve(&root, &paths, keep_remote, all)
        }
        "prune" => {
            let what = match (older_than, keep_newest, all) {
                (Some(age), None, false) => run::Prune::OlderThan(age),
                (None, Some(n), false) => run::Prune::KeepNewest(n),
                (None, None, true) => run::Prune::All,
                // No default, deliberately: everything in `diffs` is there
                // because something was about to be destroyed, so which of those
                // copies is now expendable is not bisync's call to make.
                (None, None, false) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "say what to remove: --older-than <duration>, --keep <n>, or --all",
                    ));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--older-than, --keep and --all are alternatives; pick one",
                    ));
                }
            };
            run::prune(&dir()?, what, &overrides)
        }
        "tree" => run::tree(&dir()?, &overrides),
        "server" => {
            let root = dir()?;
            run::server(&root, watch_mode, &overrides)
        }
        "help" => {
            print!("{HELP}");
            Ok(0)
        }
        "version" | "--version" | "-V" => {
            println!("bisync {VERSION} (protocol {})", bisync::proto::VERSION);
            Ok(0)
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown command {other:?}; `bisync help` lists them"),
        )),
    }
}

/// A `--older-than` span, with the same suffixes `max-size` uses for sizes.
fn parse_size_of_time(raw: &str) -> io::Result<std::time::Duration> {
    bisync::util::parse_duration(raw).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{raw:?} is not a span of time; try 7d, 12h, 30m or 90s"),
        )
    })
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

/// For `resolve`: the root, and the paths within it.
///
/// `-C` puts the root at the front of `positional` (see the parser above), so
/// the two cases are distinguished by whether the first entry is a directory
/// that exists — which is what `root_of` reports on.
fn split_root(positional: &[String]) -> io::Result<(std::path::PathBuf, Vec<String>)> {
    if let Some(first) = positional.first() {
        let candidate = std::path::Path::new(first);
        if candidate.is_dir() && candidate.join(bisync::store::CONTROL).is_dir() {
            return Ok((candidate.canonicalize()?, positional[1..].to_vec()));
        }
    }
    Ok((std::env::current_dir()?, positional.to_vec()))
}
