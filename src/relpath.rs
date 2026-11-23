//! Paths as they travel on the wire: `/`-separated, relative to the sync root,
//! and validated on arrival.
//!
//! The far end of the link is not necessarily trustworthy — it is at minimum a
//! program that could be an older version with a different idea of encoding — so
//! every path a peer sends is checked before it is joined to anything. A missed
//! `..` here is a remote write anywhere on the filesystem, which makes this
//! small module the security boundary of the whole tool.

use std::path::{Component, Path, PathBuf};

use crate::wire::DecodeError;

/// Longest path bisync will accept, in bytes. Well past any filesystem's own
/// limit; it exists to bound work, not to be reached.
pub const MAX_PATH: usize = 4096;

/// Check a relative path received from a peer or read from a state file.
///
/// Accepts the empty string, which denotes the sync root itself. Rejects
/// anything absolute, any `.` or `..` component, empty components (`a//b`),
/// trailing slashes, NUL bytes, and — because a path is joined to a real root on
/// a real filesystem — a leading drive letter or UNC prefix on Windows.
pub fn validate(rel: &str) -> Result<(), DecodeError> {
    if rel.is_empty() {
        return Ok(());
    }
    let bad = |why: &str| Err(DecodeError::BadPath(format!("{rel}: {why}")));
    if rel.len() > MAX_PATH {
        return bad("too long");
    }
    if rel.starts_with('/') {
        return bad("absolute");
    }
    if rel.ends_with('/') {
        return bad("trailing slash");
    }
    if rel.contains('\0') {
        return bad("contains NUL");
    }
    for component in rel.split('/') {
        match component {
            "" => return bad("empty component"),
            "." | ".." => return bad("relative component"),
            _ => {}
        }
        // Windows treats a backslash as a separator and `:` as a drive marker.
        // Names containing either are legal on Unix but would change meaning in
        // transit, so they are refused rather than silently reinterpreted.
        if cfg!(windows) && (component.contains('\\') || component.contains(':')) {
            return bad("component would be a separator on this platform");
        }
    }
    Ok(())
}

/// Join a validated relative path to the sync root.
///
/// Panics in debug builds if `rel` was never validated; every path that reaches
/// here came from [`validate`] or from a local scan, and a panic in a test is
/// preferable to a write outside the root in production.
pub fn join(root: &Path, rel: &str) -> PathBuf {
    debug_assert!(validate(rel).is_ok(), "unvalidated path {rel:?}");
    if rel.is_empty() {
        return root.to_path_buf();
    }
    let mut out = root.to_path_buf();
    for component in rel.split('/') {
        out.push(component);
    }
    out
}

/// The directory containing `rel`, or `""` for a top-level entry.
pub fn parent(rel: &str) -> &str {
    match rel.rfind('/') {
        Some(i) => &rel[..i],
        None => "",
    }
}

/// The final component of `rel`.
pub fn basename(rel: &str) -> &str {
    match rel.rfind('/') {
        Some(i) => &rel[i + 1..],
        None => rel,
    }
}

/// `rel` and every directory above it, root first, excluding `rel` itself.
pub fn ancestors(rel: &str) -> Vec<&str> {
    let mut out = vec![""];
    let mut end = 0;
    while let Some(i) = rel[end..].find('/') {
        end += i;
        out.push(&rel[..end]);
        end += 1;
    }
    out
}

/// Is `rel` inside `dir` (at any depth)? `""` contains everything.
pub fn is_under(rel: &str, dir: &str) -> bool {
    if dir.is_empty() {
        return true;
    }
    rel.len() > dir.len() && rel.starts_with(dir) && rel.as_bytes()[dir.len()] == b'/'
}

/// Number of path components; the root is depth 0.
pub fn depth(rel: &str) -> usize {
    if rel.is_empty() {
        0
    } else {
        rel.split('/').count()
    }
}

/// Convert a filesystem path below `root` into the wire form.
///
/// Returns `None` when the path is not under `root`, or when a component is not
/// UTF-8. Non-UTF-8 names are a real thing on Unix, but they cannot be encoded
/// in a protocol both ends parse as text; such files are reported as skipped
/// rather than silently mangled.
pub fn from_path(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    let mut out = String::new();
    for component in rel.components() {
        let name = match component {
            Component::Normal(n) => n.to_str()?,
            // A scan never produces these; a caller passing a path with `..` in
            // it is a bug, not something to normalise away.
            _ => return None,
        };
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(name);
    }
    Some(out)
}
