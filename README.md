# bisync

Keep two directories the same, in both directions, over ssh.

rsync's transport with none of rsync's one-way semantics: bisync maintains a
BLAKE2b Merkle tree over each copy, so it can tell what differs without either
side enumerating its tree at the other, and it remembers what the two sides last
agreed on, so it can tell a deletion from a file the peer has not seen yet.

```
$ bisync init ~/work --peer laptop:/home/me/work
$ bisync init /home/me/work --peer desktop:/home/me/work   # on the other machine
$ bisync watch ~/work
/home/me/work <-> laptop:/home/me/work (watching via fsevents)
1843 entries (1843 hashed, 0 unchanged)
send  src/parser.rs  (4.1K)
recv  notes/today.md  (812B)
del   scratch.txt
```

## What it does

* **Both directions.** A change on either side propagates to the other. There is
  no source and no destination.
* **Only what changed.** File digests roll up into directory digests, which roll
  up into a root digest. Equal roots mean equal trees, so reconnecting to an
  unchanged peer costs two messages however large the tree. When they differ, the
  descent asks for one directory listing per level along the paths that actually
  changed, and skips every subtree whose digest already matches.
* **Live.** `bisync watch` stays connected and propagates changes as they
  happen — FSEvents, inotify, `ReadDirectoryChangesW` or kqueue, whichever the
  platform has — with a periodic full rescan underneath as a safety net, since
  every one of those interfaces can drop events under load.
* **Compressed in flight.** Content is deflated a chunk at a time, and each
  chunk travels compressed only if that came out smaller — so compression costs
  CPU and never bytes. What it saved is reported per file, per run and per tree.
* **Without losing anything.** Content is written to a temporary and hashed on
  the way in, and only renamed into place once the digest matches. Every
  overwrite and every unlink re-reads its target first. Nothing local is
  destroyed without a copy: whatever an incoming version overwrites, whatever a
  propagated deletion unlinks, and any symlink repointed elsewhere is copied to
  `.bisync/diffs/<path>.<timestamp>` first. And when both sides have changed the
  same path, nothing is overwritten at all: the local version stays, the peer's is
  fetched into `.bisync/quarantine`, and the path is frozen until someone says
  which they wanted.
* **Over ssh, using ssh.** bisync runs `ssh host bisync server <path>` and talks
  its own protocol over that process's stdin and stdout. Every key, `ssh_config`
  stanza, agent, jump host, `ControlMaster` and hardware token you already have
  working keeps working, and bisync contains no cryptography beyond a hash
  function.

## Install

```
cargo install --path .
```

That installs two programs: `bisync`, and `unisync` — the one-way, no-state,
ask-first sibling described [below](#unisync-one-way-no-memory-one-change-at-a-time).

The same version must be on both machines — the protocol has one version number
and no field-level negotiation, on the grounds that a refused sync is better than
a half-understood one. `bisync` must be on the remote `PATH`, or named absolutely
with `remote-command` in the config; a `unisync` run needs `unisync` there in the
same way.

Three dependencies: [`cryptoxide`](https://crates.io/crates/cryptoxide) for
BLAKE2b, which has none of its own,
[`notify`](https://crates.io/crates/notify) for filesystem events, and
[`miniz_oxide`](https://crates.io/crates/miniz_oxide) for DEFLATE. Config, the
wire format and glob matching are in-tree.

## Use

```
bisync init [dir] --peer <[user@]host:path>   write .bisync/config, take a first look
bisync sync [dir]                            reconcile once, then exit (--pull/--push for one way)
bisync watch [dir]                           reconcile, then stay and propagate
bisync status [dir]                          what is here, what changed, what was skipped
bisync conflicts [dir]                       the frozen paths and where each version is
bisync resolve <path>... --local|--remote    settle a conflict
bisync prune [dir]                           remove old preserved versions
bisync tree [dir]                            the Merkle tree, for seeing why two roots differ
```

Options: `-p/--peer`, `-m/--max-size`, `-c/--conflict`, `-z/--compress`,
`--no-compress`, `--pull`/`--push`, `-C/--dir`, `--poll`, `-n/--dry-run`,
`--diff`, `-v/--verbose`, `-q/--quiet`; `--local`/`--remote`/`--all` for
`resolve`; `--older-than`/`--keep`/`--all` for `prune`.

Every option overrides the config file, for `status` and `tree` as well as for
`sync`, so `bisync status -z9` describes the sync `bisync sync -z9` would
perform.

Exit status is 0 in sync, 1 for an error, 2 while conflicts are outstanding.

Run `bisync init` on **both** ends. Each side needs to know its peer, because the
record of what was last agreed is only meaningful with respect to one peer and is
discarded if that changes.

## Configuration

`.bisync/config`, one `key = value` per line, `#` for comments, `ignore`
repeatable. Values run to the end of the line and are not quoted.

```
peer = laptop:/home/me/work

# Files bigger than this are not transferred, and are listed by
# `bisync status`. Suffixes are powers of 1024.
max-size = 1M

# quarantine: keep both versions and freeze the path (default)
# local | remote: that side wins, the loser goes to quarantine
# newer: the later mtime wins; needs the two clocks to agree
conflict = quarantine

# Compress content in flight. `no` to send it as it is, or a DEFLATE
# level from 1 to 10; higher spends more time for less return.
compress = 6

ssh = ssh
ssh-option = -oBatchMode=yes
remote-command = bisync

# Quiet period before a filesystem change is acted on.
debounce-ms = 400

# Full rescan interval, and the polling watcher's period.
poll-secs = 60
# Set for network filesystems, which report no local events.
poll-only = no

ignore = .git/
ignore = target/
ignore = *.tmp
```

`ignore` takes the useful subset of `.gitignore` syntax: `!` to re-include, a
trailing `/` for directories only, a leading or interior `/` to anchor at the
root, `?`, `*` (within a component), `**` (across components), and `[a-z]`
classes. Last matching pattern wins. A pattern starting with a literal `#` or `!`
needs a backslash: `\#*#`.

The side that starts a session imposes its ignore rules, size limit, conflict
policy and compression level on the other for the duration. That is not a
convenience: two ends filtering differently would never agree on a tree digest
and would trade metadata for as long as they stayed connected, and two ends
resolving conflicts differently would have one quietly overwrite while the other
froze. Both sides should have the same config; each warns if the other's differs.

`.bisync/` is never synced, and no `!` rule can re-include it.

### The size limit

Files over `max-size` (1 MiB by default) are not transferred. They are reported
by `bisync status` and left out of the digests entirely — deliberately, because a
tree holding one 4 GiB file that will never be sent would otherwise have a root
digest that never matched, and every session would walk the whole tree to
rediscover the same thing.

A bidirectional sync watching a working directory is the wrong tool for large
artefacts: every save re-sends the whole file, and there is no delta encoding
here to soften it. Raise the limit if you have decided you want that.

### Compression

Content is deflated per chunk, and a chunk travels compressed only if the
deflated form is smaller — so incompressible content costs one wasted pass of
the compressor and not a single extra byte. Files whose name says their content
is already compressed (`.jpg`, `.mp4`, `.zst`, `.docx`, …) skip the compressor
entirely, which is where the wasted passes would otherwise be most expensive.

Per chunk rather than per file costs almost nothing: DEFLATE's window is 32 KiB
and a chunk is 128 KiB, so a chunk boundary discards no back-reference a
whole-file stream would have found. What it buys is that every frame decodes on
its own — nothing carries over, an aborted transfer leaves no half-consumed
decompressor, and the digest and size guards still see plain content. The
encoding is a property of the frame, not a mode the two ends have to hold in
common and stay in step about.

What it saved is reported three ways:

```
$ bisync sync
recv  notes.md          (109.4K -> 321B, 99% saved)
send  assets/photo.jpg  (293.0K)
send  src/big.rs        (468.8K -> 1.6K, 99% saved)
received 1 file (109.4K, 321B on the wire, 99% saved), sent 2 files (761.7K, 294.6K on the wire, 61% saved)

$ bisync status
compress  deflate level 6
sent      12.4M plain, 3.1M on the wire, 74% saved
received  8.8M plain, 8.7M on the wire, 1% saved
```

The running totals are kept in `.bisync/state` and accumulate across sessions,
because whether compressing a given tree is worth the CPU is a fact about the
tree and takes more than one run to see. A `received` line reading 1% is telling
you to turn it off.

If ssh is already compressing (`Compression yes`, or `-o Compression=yes`),
turn one of the two off — deflating an already-deflated stream is pure CPU.
bisync's own compression is the better place for it, since it skips content it
knows is dense and tells you what it achieved.

## One-way syncs

A sync goes both ways unless told otherwise:

```
bisync sync           # both ways
bisync sync --pull    # take the peer's changes; do not offer ours
bisync sync --push    # offer ours; do not take the peer's
```

A direction names a way along the *link*, not "away from me", and the far end
mirrors it — read as "me" by both ends, `--pull` would have each sitting waiting
for the other to offer something.

The important part is what a one-way run does *not* do. The merge still works out
what every path's situation is, and the base does not advance for a path the
direction declined to act on, so a later full sync finds it exactly as it was.
Nor does a direction settle a conflict: both sides changed, and which of them
wins is not a question `--pull` answers, so a conflicting path freezes as it
always would.

```
$ bisync sync --pull
skip  mine.txt  (could offer file 6a8d04b05304 10b 0644, but this session only pulls)
recv  theirs.txt  (10B)
```

## unisync: one way, no memory, one change at a time

`bisync sync --pull` still remembers. It compares against the base, freezes what
conflicts, and writes down what it settled — which is what you want for two
copies of a working directory, and more than you want when all you meant was
"show me what differs over there, and let me pick".

`unisync` is that tool, built from the same parts: the same digests, the same
Merkle descent, the same wire format, the same guarded store. It installs
alongside `bisync` from this crate, and has to be on both ends of a link in the
same way.

```
$ unisync pull laptop:/home/me/work ~/work
/home/me/work <- laptop:/home/me/work
3 changes for here (1 update, 1 mkdir, 1 new)
  y accept   n leave it   d show the difference   a accept the rest
  s stop asking and apply what is accepted   q abandon the run
[1/3] update  README.md  (12B -> 23B)  [y/n/d/a/s/q] d

      --- here now (12B)
      +++ the peer (23B)
      @@ -1,2 +1,3 @@
       hello
      -there
      +world
      +third line
[1/3] update  README.md  (12B -> 23B)  [y/n/d/a/s/q] y
[2/3] mkdir   notes  [y/n/d/a/s/q] n
skip    notes/today.md  (inside notes, left alone)
1 change accepted
recv    README.md  (23B)
received 1 file (23B), 1 old version kept in .unisync/diffs
```

```
unisync pull <[user@]host:path> [dir]   make this directory look like the peer's
unisync push <[user@]host:path> [dir]   make the peer's directory look like this one
unisync server <dir>                    the far end of a link
```

Options: `-m/--max-size`, `-z/--compress`, `--no-compress`, `--delete`,
`-y/--yes`, `-n/--dry-run`, `-i/--ignore`, `--no-default-ignores`, `--ssh`,
`--ssh-option`, `--remote-command`, `-v/--verbose`, `-q/--quiet`. The peer may
also be a plain path, in which case both trees are on this machine and the far
end is a second copy of the program on a pipe — the same code as a real link,
minus ssh.

What it does differently:

* **Nothing is remembered.** Both ends hash their tree, the descent finds what
  differs, and that is the entire input to the run. No state file, no base, and
  nothing left over for next time — so no conflicts either: the direction says
  which side wins, and you say whether it wins this particular path.
* **Deletions are opt-in.** Without a base, a path the receiving side has and the
  sending side does not is ambiguous — added there, or deleted here — and the two
  readings want opposite things done. So nothing is ever taken away by default:
  differences of that shape are reported and left out of the plan, and `--delete`
  is what puts them into it. Replacing a directory with a file needs it too,
  since it destroys everything inside.
* **Every change is asked about.** `d` fetches the peer's copy, shows a unified
  diff of it against what is here — coloured, when the output is a terminal —
  throws the copy away, and asks again.
  Declining a directory declines everything inside it, because a plan is ordered
  parents-first and accepting a file inside a directory you refused would create
  the directory after all. Nothing is written until the whole list has been
  answered, so `q` really does leave both trees as they were.
* **The same care with what it replaces.** Content lands in `.unisync/tmp`, is
  hashed on the way in, and is renamed into place only once the digest matches.
  Every overwrite and every unlink re-reads its target first and refuses if it is
  no longer what you were asked about — an edit made while you were reading a
  diff is not written over. Anything replaced or removed is copied to
  `.unisync/diffs/<path>.<timestamp>` beforehand, and a run that replaced nothing
  takes its control directory away with it.

`--yes` accepts everything without asking and `--dry-run` prints the plan and
stops. Answers can be piped in; a stdin with nothing on it abandons the run
rather than reading silence as consent.

Ignore rules are the initiator's, as they are in `bisync`: the side you run from
sends its list and the other adopts it for the run, since two ends filtering
differently would never agree about what is in the tree. `-i` adds to the
built-in list rather than replacing it, and `--no-default-ignores` starts from
nothing.

Both programs speak the same frames and mean different things by `Announce` — one
merges it, the other obeys it — so the handshake carries the program name, and a
`unisync` pointed at a `bisync server` stops before it has done anything.

## Seeing what a sync would do

`--dry-run` decides everything and changes nothing, on either side — it is a
session term, so the far end also declines to apply or request anything for the
duration. `--diff` implies it and goes further: for each file that would be
overwritten it fetches the peer's version, compares it with what is here, and
throws it away.

```
$ bisync sync --diff
would newb.txt  (take peer's file b48b0680aa71 10b 0644)
would newa.txt  (send file 6a8d04b05304 10b 0644)
diff  f.txt  (+2 -1)
      @@ -2,2 +2,3 @@
      -two
      +TWO
       three
      +four
dry run: nothing was changed on either side
```

So `--diff` costs the transfer it is describing, which is why it is opt-in rather
than part of `--dry-run`. Hunks are coloured the way every other diff tool
colours them, and only when the output is a terminal — never down a pipe, into a
log file, or across a link. Content that is not text is reported by size rather
than diffed, and a file that differs wholesale is reported as a line count: an
LCS table over two unrelated ten-thousand-line files is gigabytes spent
describing a diff nobody would read.

## Conflicts

A conflict is a path where both sides changed since the last agreement and
neither version descends from the other. bisync changes nothing:

```
$ bisync sync
!!    notes/today.md  (edited on both sides)
      not overwritten; frozen until `bisync resolve`
kept  notes/today.md  (peer's version at .bisync/quarantine/20260821T140311Z/notes/today.md, 812B)
1 conflict unresolved: run `bisync conflicts`
$ bisync resolve notes/today.md --local
```

Each side keeps its own version live and the peer's in quarantine, so both are on
both machines. The path stays frozen — offered to nobody, accepted from nobody —
until `bisync resolve` picks a side; unrelated paths keep syncing meanwhile.
`--remote` needs no transfer, since the peer's version is already on disk.
Everything is also appended to `.bisync/conflicts.log`.

`bisync resolve --local` rewinds the base to the peer's version, so the next
announcement arrives at the far end as a fast-forward and thaws its freeze too.
One side resolves; both converge.

## How it decides

Every path has a *state*: absent, a file (content digest, size, mode), a symlink
(its target), or a directory. Every decision is a three-way merge between the
**base** (what the two sides last agreed), the **local** state, and the
**remote** state, plus the peer's own base for that path — its belief about us,
sent as the `from` half of `from -> to`.

In order:

1. `local == remote` — converged. First, so the same edit made in both places is
   agreement rather than a conflict.
2. `from == local` — a fast-forward: the peer built on precisely what we hold, so
   adopting it discards nothing.
3. `local == base` — we have not touched it; the peer's change is the only one.
4. `remote == base` — the mirror image; ours is the only change.
5. Otherwise both moved independently: a conflict.

Notably absent from a path's state is its modification time. Two files with the
same bytes are the same file; making a `touch` a transfer, and letting two
machines' clocks argue, buys nothing. The mtime rides along with a transfer so it
can be restored — it just does not decide anything. A file's *mode* is part of the
state and of the tree digest, so making a script executable propagates without
sending the file again; a directory's mode is not, because it is far more often a
local decision than something to force on a peer.

Losing the base — an interrupted sync, a deleted state file — is not fatal.
Without it every difference becomes a conflict, which is noisy and never
destructive.

## What is on disk

```
.bisync/
  config           the file above
  state            last scan, last agreement, frozen paths, running totals
  tmp/             transfers in flight; cleared on startup
  diffs/           local versions that were replaced, by path and time
  quarantine/      peer versions that were not applied, by run
  conflicts.log    every conflict this root has seen
```

`diffs/` and `quarantine/` are easy to mix up and worth keeping straight:

* **`diffs/<path>.<timestamp>`** — a local version that is **gone from the
  tree**: overwritten by a received file, unlinked by a propagated deletion, or a
  symlink pointed somewhere else. The tree's shape is kept, so a replaced
  `src/main.rs` is at `diffs/src/main.rs.20260821T140311Z` and successive
  versions of one file sort together.
* **`quarantine/<timestamp>/<path>`** — a peer version that was **not** applied,
  grouped by the run that fetched it.

A conflicted path therefore ends up with one version in each: yours in `diffs/`
if you later resolve towards the peer, theirs in `quarantine/` from the moment
the conflict was found.

The copies are taken by the operations that do the destroying — `place`,
`remove`, `set_symlink` — rather than by their callers, so the rule holds by
construction and there is no list of covered cases to keep in step with the code.
A change the guard *refuses* preserves nothing, since the file is still there and
a copy of a live file is not evidence of anything.

**Nothing removes anything from `diffs/` unless asked.** It is a safety net, and
a safety net that quietly empties itself is not one. On a busy `watch` session
over a working tree it grows by one copy per incoming edit or deletion, so
`bisync status` reports how much has accumulated:

```
$ bisync status
kept      148 old versions in .bisync/diffs (3.2M)
```

and `bisync prune` removes them:

```
bisync prune --older-than 30d    # versions preserved longer ago than that
bisync prune --keep 3            # all but the newest 3 versions of each path
bisync prune --all               # everything
bisync prune --keep 3 -n         # say what that would remove, and stop
```

There is no default: everything in `diffs/` is there because something was about
to be destroyed and bisync declined to let that be the end of it, so which of
those copies is now expendable is not a judgement it should be making on your
behalf. `prune` with no criterion is an error, not a guess.

Age comes from the timestamp in the name rather than the copy's own mtime, since
`fs::copy` does not carry a source's timestamp across on every platform and the
point of putting the time in the name was to have somewhere it cannot drift. A
file in `diffs/` whose name does *not* end in a timestamp — something put there
by hand, say — cannot be shown to be old, so `--older-than` leaves it alone and
says so; `--all` is how to be rid of it.

`prune` touches nothing but `diffs/`. Quarantine copies in particular are
referenced by conflict records, and removing one would break
`bisync resolve --remote`.

The state file makes startup affordable: a file whose kind, size, mtime and inode
all match the previous scan is not read again, so starting on a large tree is one
`stat` per file rather than a full rehash.

## Layout

`hash`, `tree`, `merge` and `proto` are pure — digests, the tree model, the
three-way merge, and the wire format, none of which touch a filesystem or a
socket. `scan` and `store` are the only modules that do, and every mutation and
its guard is in `store`. `session` is the protocol state machine, driven entirely
by messages in and messages out, which is why a whole two-way sync can be tested
by wiring two of them together with no transport at all. `transport`, `watch` and
`run` are the outside world; `uni` is `unisync` — its own comparison, prompt and
protocol over the same `hash`, `tree`, `proto`, `scan` and `store`; `compress` is
the chunk codec and the accounting;
`watch` is a debouncer and an ignore filter over
`notify`, since what matters here is *that* a path changed, not what an event
thought had happened to it. The command lines are not in the library — they are
`src/main.rs` and `src/bin/unisync.rs`, since a shell is their only caller.

```
cargo test
```

## Limits worth knowing

* Directories themselves are not kept — they have no content of their own — so a
  deleted tree leaves its files in `diffs/` and its (empty) directory structure
  nowhere. Recreating the shape from the kept paths is straightforward; restoring
  it automatically is not something bisync does.
* Whole files, not deltas. There is no rolling checksum: a one-byte change to a
  large file re-sends the file — compressed, but whole. That is what the size
  limit is for.
* One peer per root at a time. The record of what was agreed is stamped with the
  peer it was built against and discarded if that changes.
* Hard links are copied as separate files, and their sharing is not preserved.
  Sockets, fifos and device nodes are reported and skipped.
* Filenames must be valid UTF-8 to cross the wire. Names that are not are
  reported and skipped rather than mangled into something that would sync back as
  a different file.
* setuid, setgid and sticky bits are not carried across a link, and cannot be:
  they are grants of authority on one machine, not properties of the content.

## Licence

MIT OR Apache-2.0
