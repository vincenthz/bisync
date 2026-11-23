//! Small pieces with nowhere better to live: time formatting, size parsing, and
//! byte counts for humans. All in-tree, so the dependency list stays at one.

use std::time::{Duration, SystemTime};

use crate::tree::Stamp;

pub fn now() -> Stamp {
    Stamp::from_system(SystemTime::now())
}

/// `2026-08-21T14:03:11Z`, for log lines and conflict reports.
pub fn format_utc(stamp: Stamp) -> String {
    let (y, m, d, hh, mm, ss) = civil(stamp.secs);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// `20260821T140311Z`: the same instant, usable as a directory name.
pub fn format_compact(stamp: Stamp) -> String {
    let (y, m, d, hh, mm, ss) = civil(stamp.secs);
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

/// Read back what [`format_compact`] wrote: `20260821T140311Z`.
///
/// The name of a preserved version is the authority on when it was preserved,
/// not the copy's own mtime — `fs::copy` does not carry the source's timestamp
/// across on every platform, and the point of putting the time in the name was
/// to have somewhere it cannot drift.
pub fn parse_compact(s: &str) -> Option<Stamp> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let field = |from: usize, to: usize| -> Option<i64> {
        let part = s.get(from..to)?;
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (year, month, day) = (field(0, 4)?, field(4, 6)?, field(6, 8)?);
    let (hour, minute, second) = (field(9, 11)?, field(11, 13)?, field(13, 15)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = days_from_civil(year, month as u32, day as u32);
    Some(Stamp {
        secs: days * 86_400 + hour * 3600 + minute * 60 + second,
        nanos: 0,
    })
}

/// Days since the Unix epoch for a UTC calendar date: the inverse of [`civil`].
///
/// Hinnant's `days_from_civil`, and the same trick — treat March as the start of
/// the year so February's varying length falls at the end, after which the
/// 400-year cycle divides evenly and there are no special cases.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Break a Unix timestamp into UTC calendar fields.
///
/// Hinnant's `civil_from_days`: shift the epoch to 0000-03-01 so that February —
/// the month whose length varies — lands at the end of the year, after which the
/// 400-year leap cycle divides evenly and there are no special cases left.
fn civil(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (
        y,
        m,
        d,
        (rem / 3600) as u32,
        (rem % 3600 / 60) as u32,
        (rem % 60) as u32,
    )
}

/// Parse a size with an optional binary suffix: `1M`, `512k`, `2GiB`, `4096`.
///
/// Suffixes are powers of 1024 throughout. A tool that says it will not send
/// files over 1M and then sends a 1,048,000-byte one because the user meant
/// megabytes-of-1000 would be irritating in a way that is not worth the
/// pedantry, so there is one interpretation and it is the binary one.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let digits = s.trim_end_matches(|c: char| !c.is_ascii_digit());
    let suffix = s[digits.len()..].trim().to_ascii_lowercase();
    let value: u64 = digits.parse().ok()?;
    let shift = match suffix.trim_end_matches("ib").trim_end_matches('b') {
        "" => 0,
        "k" => 10,
        "m" => 20,
        "g" => 30,
        "t" => 40,
        _ => return None,
    };
    value.checked_mul(1u64 << shift)
}

/// Round-trip partner of [`parse_size`] for exact powers of 1024, and a readable
/// approximation otherwise.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("T", 1 << 40),
        ("G", 1 << 30),
        ("M", 1 << 20),
        ("K", 1 << 10),
    ];
    for (unit, scale) in UNITS {
        if bytes >= scale {
            if bytes % scale == 0 {
                return format!("{}{unit}", bytes / scale);
            }
            return format!("{:.1}{unit}", bytes as f64 / scale as f64);
        }
    }
    format!("{bytes}B")
}

/// Parse a span of time: `90s`, `30m`, `12h`, `7d`, `4w`, or bare seconds.
///
/// `m` is minutes. Months would be the other reading and are deliberately not
/// offered — a unit whose length depends on which one it is has no place in a
/// retention setting.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let digits = s.trim_end_matches(|c: char| !c.is_ascii_digit());
    let suffix = s[digits.len()..].trim();
    let value: u64 = digits.parse().ok()?;
    let seconds = match suffix {
        "" | "s" | "sec" | "secs" => 1,
        "m" | "min" | "mins" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3600,
        "d" | "day" | "days" => 86_400,
        "w" | "week" | "weeks" => 604_800,
        _ => return None,
    };
    value.checked_mul(seconds).map(Duration::from_secs)
}

/// A span of time, in the largest unit that divides it exactly: `7d`, `36h`.
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    for (unit, scale) in [("w", 604_800u64), ("d", 86_400), ("h", 3600), ("m", 60)] {
        if secs >= scale && secs % scale == 0 {
            return format!("{}{unit}", secs / scale);
        }
    }
    format!("{secs}s")
}

/// Pluralise a count where adding `s` is right: `1 file`, `2 files`.
pub fn plural(n: usize, singular: &str) -> String {
    if n == 1 {
        format!("{n} {singular}")
    } else {
        format!("{n} {singular}s")
    }
}

/// Pluralise a count where it is not: `1 entry`, `2 entries`.
pub fn count(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("{n} {singular}")
    } else {
        format!("{n} {plural}")
    }
}
