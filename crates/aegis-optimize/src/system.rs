//! Arch Linux system optimization analysis (read-only scan).
//!
//! Detects reclaimable disk space and health issues the way a commercial
//! "PC cleaner" would, but tuned for Arch: pacman package cache, orphaned
//! packages, the systemd journal, per-user caches, failed units and boot time.
//! Parsing helpers are pure and unit-tested; the scan wires them to real tools.

use crate::model::{human_bytes, Finding, Impact, OptimizeReport};
use std::path::Path;
use std::process::Command;

/// Directory size in bytes (recursive), best-effort.
pub fn dir_size(path: &Path) -> u64 {
    fn walk(p: &Path) -> u64 {
        let mut total = 0;
        if let Ok(entries) = std::fs::read_dir(p) {
            for e in entries.flatten() {
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_symlink() {
                    continue;
                }
                if ft.is_dir() {
                    total += walk(&e.path());
                } else if let Ok(md) = e.metadata() {
                    total += md.len();
                }
            }
        }
        total
    }
    if path.is_dir() {
        walk(path)
    } else {
        0
    }
}

/// Parse `pacman -Qtdq` (orphans) output into a package list.
pub fn parse_orphans(output: &str) -> Vec<String> {
    output
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

/// Parse `journalctl --disk-usage` output → bytes.
/// e.g. "Archived and active journals take up 2.3G in the file system."
pub fn parse_journal_usage(output: &str) -> Option<u64> {
    let tok = output.split_whitespace().find(|t| {
        let last = t.chars().last().unwrap_or(' ');
        matches!(last, 'B' | 'K' | 'M' | 'G' | 'T')
            && t.chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
    })?;
    parse_size(tok)
}

/// Parse a size like `2.3G`, `512M`, `11GiB`, `1466` (bytes) into bytes.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim().trim_end_matches("iB").trim_end_matches('B');
    let (num, mult) = match s.chars().last() {
        Some('K') => (&s[..s.len() - 1], 1024u64),
        Some('M') => (&s[..s.len() - 1], 1024u64.pow(2)),
        Some('G') => (&s[..s.len() - 1], 1024u64.pow(3)),
        Some('T') => (&s[..s.len() - 1], 1024u64.pow(4)),
        _ => (s, 1),
    };
    num.trim()
        .parse::<f64>()
        .ok()
        .map(|v| (v * mult as f64) as u64)
}

#[allow(dead_code)]
fn cmd_stdout(prog: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(prog).args(args).output().ok()?;
    if out.status.success() || !out.stdout.is_empty() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

/// Run the full system optimization scan.
pub fn scan() -> OptimizeReport {
    let mut r = OptimizeReport::default();
    #[cfg(target_os = "linux")]
    {
        scan_pacman_cache(&mut r);
        scan_orphans(&mut r);
        scan_journal(&mut r);
        scan_user_cache(&mut r);
        scan_tmp(&mut r);
        scan_failed_units(&mut r);
    }
    #[cfg(windows)]
    {
        scan_windows_junk(&mut r);
    }
    r
}

#[cfg(windows)]
fn scan_windows_junk(r: &mut OptimizeReport) {
    use std::path::PathBuf;
    let local_appdata = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let win_dir = std::env::var_os("WINDIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));

    // 1. User Temp Directory
    if let Some(ref local) = local_appdata {
        let temp_dir = local.join("Temp");
        let size = dir_size(&temp_dir);
        if size > 50 * 1024 * 1024 {
            r.push(Finding::action(
                "Disk Cleanup",
                "User Temporary Files",
                format!("%LOCALAPPDATA%\\Temp holds {} of cached logs and setup scratch files.", human_bytes(size)),
                if size > 2 * 1024u64.pow(3) { Impact::High } else { Impact::Medium },
                size * 4 / 5,
                "del /q /f /s %TEMP%\\*",
                false,
            ));
        } else {
            r.push(Finding::ok("Disk Cleanup", "User Temp folder is lean", format!("{} in use.", human_bytes(size))));
        }
    }

    // 2. Windows Update Download Cache
    let soft_dist = win_dir.join("SoftwareDistribution").join("Download");
    if soft_dist.is_dir() {
        let size = dir_size(&soft_dist);
        if size > 100 * 1024 * 1024 {
            r.push(Finding::action(
                "System Storage",
                "Windows Update Download Cache",
                format!("Downloaded Windows Update packages take up {}.", human_bytes(size)),
                Impact::Medium,
                size,
                "net stop wuauserv && rmdir /s /q C:\\Windows\\SoftwareDistribution\\Download",
                true,
            ));
        } else {
            r.push(Finding::ok("System Storage", "Windows Update cache is clean", format!("{} in use.", human_bytes(size))));
        }
    }

    // 3. Crash Dumps
    if let Some(ref local) = local_appdata {
        let crash_dumps = local.join("CrashDumps");
        let size = dir_size(&crash_dumps);
        if size > 20 * 1024 * 1024 {
            r.push(Finding::action(
                "Diagnostic Logs",
                "Application Crash Dumps",
                format!("Application crash dumps take up {}.", human_bytes(size)),
                Impact::Low,
                size,
                "del /q /f %LOCALAPPDATA%\\CrashDumps\\*.dmp",
                false,
            ));
        }
    }
}

#[allow(dead_code)]
fn scan_pacman_cache(r: &mut OptimizeReport) {
    let dir = Path::new("/var/cache/pacman/pkg");
    if !dir.is_dir() {
        return;
    }
    let size = dir_size(dir);
    // `paccache -dv` in dry-run reports candidates; if unavailable, estimate that
    // keeping the 2 most-recent versions of each package reclaims the rest.
    let reclaim = cmd_stdout("paccache", &["-d", "-k", "1"])
        .and_then(|o| {
            // "finished: N packages removed (disk space saved: X)"
            o.lines()
                .find(|l| l.contains("disk space saved"))
                .and_then(|l| l.rsplit(':').next())
                .and_then(|s| parse_size(s.trim().trim_end_matches(')')))
        })
        .unwrap_or(size * 3 / 4); // conservative estimate if paccache absent

    if reclaim > 50 * 1024 * 1024 {
        r.push(Finding::action(
            "Package cache",
            "Old cached packages",
            format!(
                "/var/cache/pacman/pkg holds {} of downloaded packages; keeping the \
                 latest version of each reclaims about {}.",
                human_bytes(size),
                human_bytes(reclaim)
            ),
            if reclaim > 5 * 1024u64.pow(3) {
                Impact::High
            } else {
                Impact::Medium
            },
            reclaim,
            "paccache -rk1   # keep 1 latest version per package",
            true,
        ));
    } else {
        r.push(Finding::ok(
            "Package cache",
            "Pacman cache is lean",
            format!("{} cached, little to reclaim.", human_bytes(size)),
        ));
    }
}

#[allow(dead_code)]
fn scan_orphans(r: &mut OptimizeReport) {
    let Some(out) = cmd_stdout("pacman", &["-Qtdq"]) else {
        return;
    };
    let orphans = parse_orphans(&out);
    if orphans.is_empty() {
        r.push(Finding::ok(
            "Packages",
            "No orphaned packages",
            "Nothing to prune.",
        ));
    } else {
        r.push(Finding::action(
            "Packages",
            "Orphaned packages",
            format!(
                "{} package(s) were installed as dependencies but nothing needs \
                 them any more: {}{}",
                orphans.len(),
                orphans
                    .iter()
                    .take(8)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                if orphans.len() > 8 { ", …" } else { "" }
            ),
            Impact::Low,
            0,
            "pacman -Rns $(pacman -Qtdq)",
            true,
        ));
    }
}

#[allow(dead_code)]
fn scan_journal(r: &mut OptimizeReport) {
    let Some(out) = cmd_stdout("journalctl", &["--disk-usage"]) else {
        return;
    };
    let Some(bytes) = parse_journal_usage(&out) else {
        return;
    };
    if bytes > 500 * 1024 * 1024 {
        let target = 200 * 1024 * 1024;
        r.push(Finding::action(
            "Logs",
            "Large systemd journal",
            format!(
                "The journal uses {}. Capping it at 200 MB reclaims {}.",
                human_bytes(bytes),
                human_bytes(bytes.saturating_sub(target))
            ),
            Impact::Medium,
            bytes.saturating_sub(target),
            "journalctl --vacuum-size=200M",
            true,
        ));
    } else {
        r.push(Finding::ok(
            "Logs",
            "Journal size is reasonable",
            format!("{} in use.", human_bytes(bytes)),
        ));
    }
}

#[allow(dead_code)]
fn scan_user_cache(r: &mut OptimizeReport) {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let Some(cache) = home.map(|h| h.join(".cache")) else {
        return;
    };
    let size = dir_size(&cache);
    if size > 1024u64.pow(3) {
        r.push(Finding::action(
            "User cache",
            "Large ~/.cache",
            format!(
                "~/.cache holds {}. Much of it (thumbnails, browser & build caches) \
                 is safe to clear, but do it with apps closed.",
                human_bytes(size)
            ),
            if size > 8 * 1024u64.pow(3) {
                Impact::High
            } else {
                Impact::Medium
            },
            size * 3 / 4,
            "aegis optimize clean --user-cache   # or: rm -rf ~/.cache/*",
            false,
        ));
    } else {
        r.push(Finding::ok(
            "User cache",
            "~/.cache is small",
            format!("{} in use.", human_bytes(size)),
        ));
    }
}

#[allow(dead_code)]
fn scan_tmp(r: &mut OptimizeReport) {
    let size = dir_size(Path::new("/tmp"));
    if size > 512 * 1024 * 1024 {
        r.push(Finding::action(
            "Temp files",
            "Large /tmp",
            format!(
                "/tmp holds {} (cleared on reboot anyway).",
                human_bytes(size)
            ),
            Impact::Low,
            size / 2,
            "find /tmp -mtime +3 -delete   # remove items older than 3 days",
            false,
        ));
    }
}

#[allow(dead_code)]
fn scan_failed_units(r: &mut OptimizeReport) {
    let Some(out) = cmd_stdout("systemctl", &["--failed", "--no-legend", "--plain"]) else {
        return;
    };
    let failed: Vec<&str> = out
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|s| !s.is_empty())
        .collect();
    if failed.is_empty() {
        r.push(Finding::ok(
            "Services",
            "No failed units",
            "All systemd units are healthy.",
        ));
    } else {
        r.push(Finding::action(
            "Services",
            "Failed systemd units",
            format!("{} unit(s) failed: {}", failed.len(), failed.join(", ")),
            Impact::Medium,
            0,
            "systemctl --failed   # then investigate/restart each",
            false,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_parsing() {
        assert_eq!(parse_size("2G"), Some(2 * 1024u64.pow(3)));
        assert_eq!(parse_size("512M"), Some(512 * 1024 * 1024));
        assert_eq!(parse_size("2.3G"), Some((2.3 * 1024f64.powi(3)) as u64));
        assert_eq!(parse_size("1466"), Some(1466));
        assert_eq!(parse_size("11GiB"), Some(11 * 1024u64.pow(3)));
    }

    #[test]
    fn journal_usage_parse() {
        let out = "Archived and active journals take up 2.3G in the file system.";
        assert_eq!(
            parse_journal_usage(out),
            Some((2.3 * 1024f64.powi(3)) as u64)
        );
    }

    #[test]
    fn orphan_parse() {
        assert_eq!(parse_orphans("foo\nbar\n\n  baz  \n").len(), 3);
        assert!(parse_orphans("").is_empty());
    }

    #[test]
    fn live_scan_runs() {
        // Should not panic on the real system.
        let r = scan();
        assert!(!r.findings.is_empty());
    }
}
