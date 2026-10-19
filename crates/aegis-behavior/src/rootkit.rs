//! Rootkit & system-integrity scanner.
//!
//! Uses cross-view detection: the same fact is observed two ways and any
//! disagreement is a red flag, because a rootkit that hides from one interface
//! rarely hides from all of them. All checks are read-only.
//!
//! Milestone-3 checks:
//! * **Hidden processes** — a PID that answers a direct `/proc/<pid>` stat but
//!   is missing from the `/proc` directory listing (readdir-hooking rootkit).
//! * **Hidden kernel modules** — modules present in `/sys/module` but absent
//!   from `/proc/modules` (or vice-versa).
//! * **`/etc/ld.so.preload`** — the classic userland-rootkit persistence file.
//! * **Kernel taint** — `/proc/sys/kernel/tainted` flags (informational).
//!
//! The parsing/diff logic is factored into pure functions so it is unit-tested
//! with synthetic inputs; the live scan wires them to the real filesystem.

#![allow(dead_code)]

use aegis_core::{Detection, Severity, ThreatClass};
use std::collections::BTreeSet;
use std::path::Path;

/// Run every rootkit / integrity check against the live system.
pub fn scan() -> Vec<Detection> {
    #[cfg(target_os = "linux")]
    {
        let mut out = Vec::new();
        out.extend(check_hidden_processes());
        out.extend(check_hidden_modules());
        out.extend(check_ld_preload());
        out.extend(check_kernel_taint());
        out
    }
    #[cfg(windows)]
    {
        aegis_platform::default_integrity_checks().scan()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Vec::new()
    }
}

// --- hidden processes -------------------------------------------------

/// All task IDs visible through the `/proc` listing — the union of every
/// process's `task/` directory. This is the correct "listed" set: `/proc/<tid>`
/// is directly statable for thread IDs even though threads do not appear in the
/// top-level `/proc` readdir, so a naive process-only listing would flag every
/// thread as hidden.
#[allow(dead_code)]
fn listed_tasks() -> BTreeSet<u32> {
    let mut ids = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let name = e.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            ids.insert(pid);
            // Include every thread of this process.
            if let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) {
                for t in tasks.flatten() {
                    if let Some(tid) = t.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                        ids.insert(tid);
                    }
                }
            }
        }
    }
    ids
}

/// PIDs that answer a direct stat of `/proc/<pid>` across the plausible range.
fn probed_pids(max_pid: u32) -> BTreeSet<u32> {
    let mut pids = BTreeSet::new();
    for pid in 1..=max_pid {
        if Path::new(&format!("/proc/{pid}")).exists() {
            pids.insert(pid);
        }
    }
    pids
}

/// PIDs reachable by direct stat but hidden from the directory listing.
pub fn hidden_pids(listed: &BTreeSet<u32>, probed: &BTreeSet<u32>) -> Vec<u32> {
    probed.difference(listed).copied().collect()
}

fn read_max_pid() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(32768)
        .min(4_194_304)
}

fn check_hidden_processes() -> Vec<Detection> {
    let listed = listed_tasks();
    // Probing the whole pid_max range is expensive; cap the probe window to
    // the range actually in use plus headroom, which is where hiding happens.
    let cap = (listed.iter().copied().max().unwrap_or(0) + 5000).min(read_max_pid());
    let probed = probed_pids(cap);
    let mut candidates = hidden_pids(&listed, &probed);
    if candidates.is_empty() {
        return Vec::new();
    }
    // Second pass to absorb races: a process that started between the listing
    // and the probe would look "hidden". Re-read the listing and keep only
    // candidates that are still statable yet still absent from a fresh view.
    let listed2 = listed_tasks();
    candidates.retain(|pid| !listed2.contains(pid) && Path::new(&format!("/proc/{pid}")).exists());
    candidates
        .into_iter()
        .map(|pid| {
            Detection::new(
                "Rootkit",
                format!("Hidden.Process:{pid}"),
                Severity::Critical,
                ThreatClass::Rootkit,
                format!("PID {pid} answers /proc/{pid} but is hidden from the /proc listing"),
            )
        })
        .collect()
}

// --- hidden kernel modules -------------------------------------------

/// Parse module names from `/proc/modules` content (first column per line).
pub fn parse_proc_modules(content: &str) -> BTreeSet<String> {
    content
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(|s| s.to_string())
        .collect()
}

fn sys_module_names() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir("/sys/module") {
        for e in entries.flatten() {
            if e.path().is_dir() {
                if let Some(n) = e.file_name().to_str() {
                    names.insert(n.replace('-', "_"));
                }
            }
        }
    }
    names
}

/// Modules that a loaded-modules view (`/proc/modules`) lists but the sysfs
/// view (`/sys/module`) does not — a hidden dynamically-loaded module.
pub fn modules_missing_from_sysfs(
    proc_modules: &BTreeSet<String>,
    sys_modules: &BTreeSet<String>,
) -> Vec<String> {
    proc_modules
        .iter()
        .filter(|m| !sys_modules.contains(*m))
        .cloned()
        .collect()
}

fn check_hidden_modules() -> Vec<Detection> {
    let proc = std::fs::read_to_string("/proc/modules").unwrap_or_default();
    let proc_mods = parse_proc_modules(&proc);
    let sys_mods = sys_module_names();
    if proc_mods.is_empty() || sys_mods.is_empty() {
        return Vec::new(); // can't cross-check
    }
    modules_missing_from_sysfs(&proc_mods, &sys_mods)
        .into_iter()
        .map(|m| {
            Detection::new(
                "Rootkit",
                format!("Hidden.Module:{m}"),
                Severity::High,
                ThreatClass::Rootkit,
                format!("Module `{m}` is loaded (/proc/modules) but absent from /sys/module"),
            )
        })
        .collect()
}

// --- ld.so.preload ----------------------------------------------------

fn check_ld_preload() -> Vec<Detection> {
    let path = "/etc/ld.so.preload";
    match std::fs::read_to_string(path) {
        Ok(content) if !content.trim().is_empty() => vec![Detection::new(
            "Rootkit",
            "Persistence.LdSoPreload",
            Severity::High,
            ThreatClass::Rootkit,
            format!(
                "/etc/ld.so.preload is present and non-empty (userland-rootkit \
                 persistence): {}",
                content.trim().replace('\n', ", ")
            ),
        )],
        _ => Vec::new(),
    }
}

// --- kernel taint -----------------------------------------------------

/// Decode the taint bitmask into human-readable flags relevant to rootkits.
pub fn decode_taint(value: u64) -> Vec<&'static str> {
    const FLAGS: &[(u64, &str)] = &[
        (1 << 0, "proprietary module loaded (P)"),
        (1 << 1, "module force-loaded (F)"),
        (1 << 5, "bad page encountered (B)"),
        (1 << 12, "out-of-tree module loaded (O)"),
        (1 << 13, "unsigned module loaded (E)"),
    ];
    FLAGS
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

fn check_kernel_taint() -> Vec<Detection> {
    let taint = std::fs::read_to_string("/proc/sys/kernel/tainted")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let flags = decode_taint(taint);
    if flags.is_empty() {
        return Vec::new();
    }
    vec![Detection::new(
        "Rootkit",
        "Kernel.Tainted",
        Severity::Low,
        ThreatClass::Rootkit,
        format!("Kernel taint {taint}: {}", flags.join("; ")),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_modules() {
        let content = "nvidia 12345 40 - Live 0x0000\nbtrfs 100 1 - Live 0x0\n";
        let mods = parse_proc_modules(content);
        assert!(mods.contains("nvidia"));
        assert!(mods.contains("btrfs"));
        assert_eq!(mods.len(), 2);
    }

    #[test]
    fn detects_module_hidden_from_sysfs() {
        let proc: BTreeSet<String> = ["evil_rk", "btrfs"].iter().map(|s| s.to_string()).collect();
        let sys: BTreeSet<String> = ["btrfs", "nvidia"].iter().map(|s| s.to_string()).collect();
        let missing = modules_missing_from_sysfs(&proc, &sys);
        assert_eq!(missing, vec!["evil_rk".to_string()]);
    }

    #[test]
    fn hidden_pid_diff() {
        let listed: BTreeSet<u32> = [1, 2, 100].into_iter().collect();
        let probed: BTreeSet<u32> = [1, 2, 100, 31337].into_iter().collect();
        assert_eq!(hidden_pids(&listed, &probed), vec![31337]);
    }

    #[test]
    fn taint_decoding() {
        assert!(decode_taint(0).is_empty());
        let flags = decode_taint(1 << 5);
        assert_eq!(flags.len(), 1);
    }

    #[test]
    fn live_scan_runs_without_panicking() {
        // On a clean dev box this should be empty or only low-severity taint.
        let findings = scan();
        for d in &findings {
            assert_eq!(d.engine, "Rootkit");
        }
    }
}
