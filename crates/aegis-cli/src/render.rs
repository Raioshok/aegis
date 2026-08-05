//! Terminal rendering helpers (colour, tables, timestamps).

use aegis_core::{ScanStats, Severity};

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const CYAN: &str = "\x1b[36m";
pub const GREEN: &str = "\x1b[32m";
pub const RED: &str = "\x1b[31m";
pub const YELLOW: &str = "\x1b[33m";

/// Whether stdout is a TTY (colours off when piped).
pub fn color_enabled() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

pub fn paint(color: &str, text: &str) -> String {
    if color_enabled() {
        format!("{color}{text}{RESET}")
    } else {
        text.to_string()
    }
}

pub fn sev_paint(sev: Severity, text: &str) -> String {
    if color_enabled() {
        format!("{}{text}{RESET}", sev.ansi())
    } else {
        text.to_string()
    }
}

/// Format a unix epoch as `YYYY-MM-DD HH:MM` UTC.
pub fn fmt_epoch(secs: i64) -> String {
    use time::OffsetDateTime;
    match OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute()
        ),
        Err(_) => secs.to_string(),
    }
}

/// Human-readable byte size.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut val = bytes as f64;
    let mut unit = 0;
    while val >= 1024.0 && unit < UNITS.len() - 1 {
        val /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{val:.1} {}", UNITS[unit])
    }
}

/// Print the summary line for a completed scan.
pub fn print_summary(stats: &ScanStats) {
    let secs = stats.duration_ms as f64 / 1000.0;
    if stats.threats == 0 {
        println!(
            "\n{} {} files scanned · {} · {:.2}s · {} threats",
            paint(GREEN, "✓ CLEAN"),
            stats.scanned,
            human_bytes(stats.bytes_scanned),
            secs,
            stats.threats
        );
    } else {
        println!(
            "\n{} {} threat(s) in {} files · {} · {:.2}s ({} errors)",
            paint(RED, "⚠ THREATS"),
            stats.threats,
            stats.scanned,
            human_bytes(stats.bytes_scanned),
            secs,
            stats.errors
        );
    }
}
