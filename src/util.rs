//! Formatting helpers shared by the collector, UI and evidence writer.

use std::time::SystemTime;

use chrono::{DateTime, SecondsFormat, Utc};

pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// Compact UTC timestamp that is safe in file names: `20261006T121314Z`.
pub fn now_compact() -> String {
    Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

pub fn system_time_rfc3339(t: SystemTime) -> String {
    DateTime::<Utc>::from(t).to_rfc3339_opts(SecondsFormat::Nanos, true)
}

pub fn unix_rfc3339(secs: i64, nanos: u32) -> String {
    DateTime::<Utc>::from_timestamp(secs, nanos)
        .map(|t| t.to_rfc3339_opts(SecondsFormat::Nanos, true))
        .unwrap_or_else(|| secs.to_string())
}

pub fn unix_short(secs: i64) -> String {
    DateTime::<Utc>::from_timestamp(secs, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| secs.to_string())
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Truncates on a character boundary, appending an ellipsis when shortened.
pub fn truncate_in_place(s: &mut String, max_chars: usize) {
    if s.chars().count() > max_chars {
        let cut = s
            .char_indices()
            .nth(max_chars.saturating_sub(1))
            .map_or(s.len(), |(i, _)| i);
        s.truncate(cut);
        s.push('…');
    }
}

pub fn truncate(s: &str, max_chars: usize) -> String {
    let mut out = s.to_string();
    truncate_in_place(&mut out, max_chars);
    out
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn human_kb(kb: u64) -> String {
    human_bytes(kb.saturating_mul(1024))
}

pub fn human_duration(secs: f64) -> String {
    let s = secs.max(0.0) as u64;
    let (d, h, m, sec) = (s / 86_400, s / 3600 % 24, s / 60 % 60, s % 60);
    if d > 0 {
        format!("{d}d {h:02}h {m:02}m")
    } else if h > 0 {
        format!("{h}h {m:02}m {sec:02}s")
    } else if m > 0 {
        format!("{m}m {sec:02}s")
    } else {
        format!("{sec}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_duration(3725.0), "1h 02m 05s");
        assert_eq!(human_duration(90061.0), "1d 01h 01m");
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("åäö", 5), "åäö");
        assert_eq!(hex(&[0, 255, 16]), "00ff10");
    }
}
