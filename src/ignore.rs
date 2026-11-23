//! Which paths bisync refuses to look at.
//!
//! The syntax is the useful subset of `.gitignore`: one pattern per line, `#`
//! comments, `!` to re-include, a trailing `/` to mean directories only, a
//! leading or interior `/` to anchor at the sync root, `?` for one character,
//! `*` for any run of characters within a path component, `**` to cross
//! components, and `[abc]` / `[a-z]` / `[!a-z]` classes. Last matching pattern
//! wins.
//!
//! Both peers must agree exactly, or their Merkle trees never converge and the
//! two sides trade metadata forever. So the rules are not merged: the side that
//! opens the session sends its list and the other side adopts it wholesale for
//! the duration. The far side compares it against its own and warns if they
//! differ, which is the only sane failure mode — a silent partial disagreement
//! would look like an endless sync.

use std::fmt::Write as _;

use crate::hash::{Digest, file_digest};

/// Patterns applied before anything the user configures, and not overridable:
/// the control directories are never sync candidates. Kept out of
/// [`DEFAULT_PATTERNS`] so a stray `!` in a config cannot re-include them.
///
/// Both tools' directories are listed here rather than each tool forcing its
/// own, because the two can be pointed at the same tree: a `bisync` root that
/// someone also pulls into with `unisync` would otherwise start synchronising
/// the other tool's temporaries and preserved versions.
const FORCED_PATTERNS: &[&str] = &[".bisync/", ".unisync/"];

/// What almost every tree wants ignored. Used when the config lists nothing;
/// a config that lists patterns replaces these rather than adding to them, so
/// `bisync init` writes them out explicitly for editing.
pub const DEFAULT_PATTERNS: &[&str] = &[
    // Version control metadata: large, chatty, and already synchronised by
    // something better at it than we are.
    ".git/",
    ".hg/",
    ".svn/",
    ".jj/",
    // Build output. Reproducible by definition, and `target/` in particular is
    // usually bigger than everything else in the tree put together.
    "target/",
    "node_modules/",
    "__pycache__/",
    ".venv/",
    "*.pyc",
    // Editor and OS scratch files. These are written and unlinked several times
    // a second while someone is typing, which is exactly the traffic a watcher
    // should not be forwarding.
    "*.swp",
    "*.swo",
    "*~",
    ".#*",
    // Backslash-escaped: an unescaped leading `#` is a comment, here and in
    // `.gitignore`.
    "\\#*#",
    ".DS_Store",
    "Thumbs.db",
    // Partial downloads and other people's temporary files.
    "*.tmp",
    "*.part",
    "*.crdownload",
];

#[derive(Clone, Debug)]
struct Rule {
    /// `!pattern`: a match re-includes rather than excludes.
    negated: bool,
    /// `pattern/`: matches directories only.
    dir_only: bool,
    /// Pattern components, `/`-separated, after anchoring is resolved.
    segments: Vec<Segment>,
    /// The line as written, for `bisync status` to explain itself.
    source: String,
}

#[derive(Clone, Debug, PartialEq)]
enum Segment {
    /// `**`: matches any number of path components, including none.
    AnyDepth,
    /// Anything else: matched against exactly one component.
    Glob(Vec<u8>),
}

/// A compiled list of ignore rules.
#[derive(Clone, Debug, Default)]
pub struct IgnoreSet {
    rules: Vec<Rule>,
    has_negations: bool,
    /// How many leading rules came from [`FORCED_PATTERNS`]. They are added by
    /// every constructor, so [`Self::to_lines`] leaves them out — a peer that
    /// re-compiled a list containing them would end up with them twice, and its
    /// [`Self::digest`] would then differ from ours over nothing.
    forced: usize,
}

impl IgnoreSet {
    /// Compile a rule list. Blank lines and `#` comments are dropped; a pattern
    /// that compiles to nothing (`/`, `!`) is ignored rather than rejected, on
    /// the grounds that a config typo should not stop a sync.
    pub fn new<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = IgnoreSet::default();
        for p in FORCED_PATTERNS {
            set.push(p);
        }
        set.forced = set.rules.len();
        for p in patterns {
            set.push(p.as_ref());
        }
        set
    }

    /// The default set, as used when no config says otherwise.
    pub fn defaults() -> Self {
        IgnoreSet::new(DEFAULT_PATTERNS)
    }

    fn push(&mut self, line: &str) {
        let line = line.trim_end();
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return;
        }
        // A leading backslash escapes the two characters that would otherwise be
        // syntax, so `\#*#` matches Emacs lock files and `\!important` matches a
        // file actually called that. Same convention as `.gitignore`, which needs
        // it for the same reason.
        let (negated, body) = match trimmed.strip_prefix('\\') {
            Some(rest) => (false, rest),
            None => match trimmed.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, trimmed),
            },
        };
        let (dir_only, body) = match body.strip_suffix('/') {
            Some(rest) => (true, rest),
            None => (false, body),
        };
        // Decided before the leading `/` is stripped, because that slash is
        // exactly what anchoring means: `/build` is the root's `build` and
        // `build` is any `build` at any depth.
        let anchored = body.starts_with('/') || body.contains('/');
        let body = body.trim_start_matches('/');
        if body.is_empty() {
            return;
        }

        // An unanchored pattern applies at any depth, which is what a leading
        // `**/` means, so anchoring reduces to whether that prefix is added.
        let mut segments = Vec::new();
        if !anchored {
            segments.push(Segment::AnyDepth);
        }
        for part in body.split('/') {
            if part.is_empty() {
                continue;
            }
            if part == "**" {
                if segments.last() != Some(&Segment::AnyDepth) {
                    segments.push(Segment::AnyDepth);
                }
            } else {
                segments.push(Segment::Glob(part.as_bytes().to_vec()));
            }
        }
        if segments.is_empty() || segments.iter().all(|s| *s == Segment::AnyDepth) {
            return;
        }

        self.has_negations |= negated;
        self.rules.push(Rule {
            negated,
            dir_only,
            segments,
            source: line.to_string(),
        });
    }

    /// Is `rel` — a `/`-separated path relative to the sync root, never leading
    /// with `/` — ignored?
    ///
    /// Ancestors are consulted first: excluding `target/` excludes everything
    /// beneath it without needing `target/**`. A deeper `!` can still win, so
    /// `target/` plus `!target/release/tool` does what it looks like it does.
    pub fn is_ignored(&self, rel: &str, is_dir: bool) -> bool {
        self.explain(rel, is_dir).is_some()
    }

    /// As [`Self::is_ignored`], but returns the pattern responsible, so the user
    /// can be told *why* a file they expected to sync did not.
    pub fn explain(&self, rel: &str, is_dir: bool) -> Option<&str> {
        let components: Vec<&str> = rel.split('/').filter(|c| !c.is_empty()).collect();
        if components.is_empty() {
            return None;
        }
        // The forced prefix is evaluated on its own and settles the matter. Were
        // it folded in with the rest, a configured `!.bisync/` would re-include
        // the control directory under last-match-wins — and two machines syncing
        // each other's record of what they had agreed is a fine way to lose data.
        if let Some(rule) = last_match(&self.rules[..self.forced], &components, is_dir) {
            return Some(&rule.source);
        }
        match last_match(&self.rules[self.forced..], &components, is_dir) {
            Some(rule) if !rule.negated => Some(&rule.source),
            _ => None,
        }
    }

    /// Whether an ignored directory can be skipped outright during a walk.
    ///
    /// False once any `!` rule exists: something under an excluded directory
    /// might be re-included, and the only way to find out is to look.
    pub fn can_prune(&self) -> bool {
        !self.has_negations
    }

    /// The configurable rules as lines, in application order, for sending to a
    /// peer. The forced prefix is left out: every constructor adds it, so
    /// including it would give the far side two copies of it — and a digest that
    /// differed from ours over nothing.
    pub fn to_lines(&self) -> Vec<String> {
        self.rules[self.forced..]
            .iter()
            .map(|r| r.source.clone())
            .collect()
    }

    /// Digest of the compiled rules, for the two ends to compare cheaply.
    ///
    /// Taken over exactly what [`Self::to_lines`] sends, so that a set built
    /// from another set's lines digests identically. That equality is the whole
    /// purpose: it is how each end tells "your config differs from mine" from
    /// "your config is mine".
    pub fn digest(&self) -> Digest {
        let mut buf = String::new();
        for line in self.to_lines() {
            let _ = writeln!(buf, "{line}");
        }
        file_digest(buf.as_bytes())
    }

    /// The number of rules the user configured, not counting the forced prefix.
    pub fn len(&self) -> usize {
        self.rules.len() - self.forced
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The last rule in `rules` that applies to `components` or to any directory
/// above it, or `None`.
///
/// Ancestors are tested first so that excluding `target/` excludes everything
/// beneath it without needing `target/**`, and a deeper rule still wins — which
/// is what makes `target/` plus `!target/release/tool` do what it looks like.
fn last_match<'r>(rules: &'r [Rule], components: &[&str], is_dir: bool) -> Option<&'r Rule> {
    let mut verdict = None;
    for depth in 1..=components.len() {
        let prefix = &components[..depth];
        // Everything but the final component is necessarily a directory.
        let prefix_is_dir = depth < components.len() || is_dir;
        for rule in rules {
            if rule.dir_only && !prefix_is_dir {
                continue;
            }
            if matches_segments(&rule.segments, prefix) {
                verdict = Some(rule);
            }
        }
    }
    verdict
}

/// Match pattern segments against path components, `**` matching any run.
fn matches_segments(segments: &[Segment], components: &[&str]) -> bool {
    match segments.split_first() {
        None => components.is_empty(),
        Some((Segment::AnyDepth, rest)) => {
            // Try consuming 0, 1, 2 ... components before the remainder.
            (0..=components.len()).any(|skip| matches_segments(rest, &components[skip..]))
        }
        Some((Segment::Glob(pat), rest)) => match components.split_first() {
            Some((head, tail)) => {
                glob_component(pat, head.as_bytes()) && matches_segments(rest, tail)
            }
            None => false,
        },
    }
}

/// Glob one path component. `*` and `?` never match `/`, which cannot appear in
/// a component anyway, so this is a plain glob with backtracking on `*`.
fn glob_component(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    // Where to resume if the current `*` turns out to have matched too little.
    let mut star: Option<(usize, usize)> = None;

    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                p += 1;
                star = Some((p, t));
                continue;
            }
            Some(b'?') => {
                p += 1;
                t += 1;
                continue;
            }
            Some(b'[') => match class_match(pattern, p, text[t]) {
                Some((matched, next)) if matched => {
                    p = next;
                    t += 1;
                    continue;
                }
                Some(_) => {}
                // Unterminated `[`: treat it as a literal bracket, which is what
                // a user who wrote it by accident meant.
                None => {
                    if text[t] == b'[' {
                        p += 1;
                        t += 1;
                        continue;
                    }
                }
            },
            Some(&c) if c == text[t] => {
                p += 1;
                t += 1;
                continue;
            }
            _ => {}
        }
        // Mismatch: give the last `*` one more character and retry.
        match star {
            Some((pp, tt)) => {
                p = pp;
                t = tt + 1;
                star = Some((pp, t));
            }
            None => return false,
        }
    }
    // Trailing `*`s can still match the empty remainder.
    while pattern.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pattern.len()
}

/// Evaluate `[...]` at `start`. Returns whether `c` is in the class and where
/// the class ends, or `None` if the class is unterminated.
fn class_match(pattern: &[u8], start: usize, c: u8) -> Option<(bool, usize)> {
    let mut i = start + 1;
    let negated = matches!(pattern.get(i), Some(b'!') | Some(b'^'));
    if negated {
        i += 1;
    }
    let mut found = false;
    let mut first = true;
    while i < pattern.len() {
        // `]` as the first class member is a literal, per POSIX.
        if pattern[i] == b']' && !first {
            return Some((found != negated, i + 1));
        }
        first = false;
        if i + 2 < pattern.len() && pattern[i + 1] == b'-' && pattern[i + 2] != b']' {
            if pattern[i] <= c && c <= pattern[i + 2] {
                found = true;
            }
            i += 3;
        } else {
            if pattern[i] == c {
                found = true;
            }
            i += 1;
        }
    }
    None
}
