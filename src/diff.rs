//! A unified diff, for `--dry-run --diff`.
//!
//! Small and self-contained: lines are matched with a classic LCS after the
//! common prefix and suffix have been trimmed off, which for the edits people
//! actually make reduces the quadratic part to a handful of lines. Where it does
//! not — two files that share nothing — the region is reported as a count rather
//! than expanded, because an LCS table over ten thousand lines each way is a
//! gigabyte of memory to describe a diff nobody would read.
//!
//! Content that is not text is not diffed. A "diff" of two binaries is either
//! noise or a lie about what changed, so the sizes are reported instead.

use std::borrow::Cow;
use std::fmt::Write as _;

/// Longest run of differing lines that will be expanded into hunks.
///
/// The LCS table is `n * m` cells, so this bounds it at 4 million — a few tens of
/// megabytes for the duration of one file. Beyond it the region is summarised.
const MAX_REGION: usize = 2000;

/// What comparing two versions came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub kind: Kind,
    /// Lines only in the new version.
    pub added: usize,
    /// Lines only in the old version.
    pub removed: usize,
    /// The rendered hunks. Empty unless `kind` is [`Kind::Text`].
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Diffed line by line; `text` holds the hunks.
    Text,
    /// Not text, or not the same kind of text. Sizes are all that is on offer.
    Binary,
    /// Text, but too much of it differs to be worth expanding.
    TooLarge,
    /// The two versions are the same. Nothing to show.
    Same,
}

/// Colour one line of a rendered diff, or hand it back exactly as it came.
///
/// The scheme every other diff tool uses — red for what goes, green for what
/// arrives, cyan for the line numbers, bold for the two file headers. A diff is
/// skimmed rather than read, and at a prompt where the next thing to happen is a
/// keystroke, colour is most of what makes skimming it possible.
///
/// `on` is what the caller knows about its own output, and nothing here guesses
/// at it: false for a pipe, a log file or the far end of a link, where escape
/// codes are noise nobody asked for. The line then comes back borrowed, so the
/// uncoloured path allocates nothing.
pub fn paint(line: &str, on: bool) -> Cow<'_, str> {
    if !on {
        return Cow::Borrowed(line);
    }
    // The file headers are tested for first: they begin with the same character
    // as an ordinary removed or added line, and are neither.
    let code = if line.starts_with("---") || line.starts_with("+++") {
        BOLD
    } else {
        match line.as_bytes().first() {
            Some(b'-') => RED,
            Some(b'+') => GREEN,
            Some(b'@') => CYAN,
            // A context line, or a sentence of prose where a diff could not be
            // shown. Both are left alone.
            _ => return Cow::Borrowed(line),
        }
    };
    Cow::Owned(format!("\x1b[{code}m{line}\x1b[0m"))
}

const BOLD: &str = "1";
const RED: &str = "31";
const GREEN: &str = "32";
const CYAN: &str = "36";

/// Compare two versions of a file, with `context` lines around each hunk.
pub fn compare(old: &[u8], new: &[u8], context: usize) -> Change {
    if old == new {
        return Change {
            kind: Kind::Same,
            added: 0,
            removed: 0,
            text: String::new(),
        };
    }
    let (Some(old), Some(new)) = (as_text(old), as_text(new)) else {
        return Change {
            kind: Kind::Binary,
            added: 0,
            removed: 0,
            text: String::new(),
        };
    };

    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();

    // Identical head and tail are not part of the problem, and trimming them is
    // what keeps the LCS tractable for an ordinary edit. All but `context` lines
    // of each, though: a hunk needs its surrounding lines, and trimming those
    // away would leave every change at a file boundary with none.
    let head = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let tail = a[head..]
        .iter()
        .rev()
        .zip(b[head..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let head = head.saturating_sub(context);
    let tail = tail.saturating_sub(context);
    let (mid_a, mid_b) = (&a[head..a.len() - tail], &b[head..b.len() - tail]);

    if mid_a.len() > MAX_REGION || mid_b.len() > MAX_REGION {
        return Change {
            kind: Kind::TooLarge,
            added: mid_b.len(),
            removed: mid_a.len(),
            text: String::new(),
        };
    }

    let ops = edits(mid_a, mid_b);
    let added = ops.iter().filter(|(op, _)| *op == Op::Insert).count();
    let removed = ops.iter().filter(|(op, _)| *op == Op::Delete).count();
    // Line numbers are of the whole file, so the trimmed head counts.
    let text = render(&ops, context, head + 1);
    Change {
        kind: Kind::Text,
        added,
        removed,
        text,
    }
}

/// UTF-8 without NUL bytes. The NUL test is what a `file`-style heuristic does,
/// and it catches the binaries that happen to decode as valid UTF-8.
fn as_text(bytes: &[u8]) -> Option<&str> {
    if bytes.contains(&0) {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    Equal,
    Delete,
    Insert,
}

/// The edit script turning `a` into `b`, as a flat list of operations.
fn edits<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<(Op, &'a str)> {
    let (n, m) = (a.len(), b.len());
    // dp[i][j] = length of the longest common subsequence of a[i..] and b[j..].
    let mut dp = vec![0u32; (n + 1) * (m + 1)];
    let at = |i: usize, j: usize| i * (m + 1) + j;
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[at(i, j)] = if a[i] == b[j] {
                dp[at(i + 1, j + 1)] + 1
            } else {
                dp[at(i + 1, j)].max(dp[at(i, j + 1)])
            };
        }
    }

    let mut ops = Vec::with_capacity(n + m);
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            ops.push((Op::Equal, a[i]));
            i += 1;
            j += 1;
        } else if dp[at(i + 1, j)] >= dp[at(i, j + 1)] {
            ops.push((Op::Delete, a[i]));
            i += 1;
        } else {
            ops.push((Op::Insert, b[j]));
            j += 1;
        }
    }
    ops.extend(a[i..].iter().map(|line| (Op::Delete, *line)));
    ops.extend(b[j..].iter().map(|line| (Op::Insert, *line)));
    ops
}

/// Render an edit script as unified-diff hunks.
fn render(ops: &[(Op, &str)], context: usize, first_line: usize) -> String {
    // Which operations are near enough a change to be worth printing.
    let mut wanted = vec![false; ops.len()];
    for (i, (op, _)) in ops.iter().enumerate() {
        if *op != Op::Equal {
            let from = i.saturating_sub(context);
            let to = (i + context + 1).min(ops.len());
            wanted[from..to].iter_mut().for_each(|w| *w = true);
        }
    }

    let mut out = String::new();
    let (mut old_line, mut new_line) = (first_line, first_line);
    let mut i = 0;
    while i < ops.len() {
        if !wanted[i] {
            match ops[i].0 {
                Op::Equal => {
                    old_line += 1;
                    new_line += 1;
                }
                Op::Delete => old_line += 1,
                Op::Insert => new_line += 1,
            }
            i += 1;
            continue;
        }
        // One hunk: the run of wanted operations starting here.
        let start = i;
        while i < ops.len() && wanted[i] {
            i += 1;
        }
        let hunk = &ops[start..i];
        let old_count = hunk.iter().filter(|(op, _)| *op != Op::Insert).count();
        let new_count = hunk.iter().filter(|(op, _)| *op != Op::Delete).count();
        let _ = writeln!(out, "@@ -{old_line},{old_count} +{new_line},{new_count} @@");
        for (op, line) in hunk {
            let mark = match op {
                Op::Equal => ' ',
                Op::Delete => '-',
                Op::Insert => '+',
            };
            let _ = writeln!(out, "{mark}{line}");
        }
        old_line += old_count;
        new_line += new_count;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{compare, paint};

    #[test]
    fn a_line_is_coloured_by_what_it_says_about_the_file() {
        let coloured = |line: &str| paint(line, true).into_owned();
        assert_eq!(coloured("+added"), "\x1b[32m+added\x1b[0m");
        assert_eq!(coloured("-removed"), "\x1b[31m-removed\x1b[0m");
        assert_eq!(
            coloured("@@ -1,2 +1,3 @@"),
            "\x1b[36m@@ -1,2 +1,3 @@\x1b[0m"
        );
        // The headers start with the same characters as a changed line and are
        // not one.
        assert_eq!(
            coloured("--- here now (12B)"),
            "\x1b[1m--- here now (12B)\x1b[0m"
        );
        assert_eq!(
            coloured("+++ the peer (23B)"),
            "\x1b[1m+++ the peer (23B)\x1b[0m"
        );
        // Context, and prose where a diff could not be shown.
        assert_eq!(coloured(" unchanged"), " unchanged");
        assert_eq!(coloured("not text"), "not text");
        assert_eq!(coloured(""), "");
    }

    #[test]
    fn nothing_is_coloured_when_the_output_is_not_a_terminal() {
        let change = compare(b"one\ntwo\n", b"one\nTWO\n", 1);
        for line in change.text.lines() {
            assert_eq!(paint(line, false), line);
            assert!(!paint(line, false).contains('\x1b'));
        }
    }
}
