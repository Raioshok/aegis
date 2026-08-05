//! Memory scanner — inspects process address spaces via `/proc/<pid>/maps`.
//!
//! Detects the memory-layout fingerprints of code injection and fileless
//! malware:
//! * **W+X regions** — pages that are simultaneously writable and executable
//!   (`rwx`); legitimate JIT engines exist, so this is medium severity.
//! * **Anonymous executable regions** — executable memory with no backing file
//!   (classic shellcode/injected code).
//! * **Deleted-backing executables** — an executable mapping whose file was
//!   deleted (`(deleted)`), a hallmark of processes that unlinked their own
//!   binary to hide.
//!
//! The maps parser is pure and unit-tested; the live scan reads real processes
//! (those the caller is permitted to inspect).

use aegis_core::{Detection, Severity, ThreatClass};

/// A single parsed line of `/proc/<pid>/maps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapRegion {
    pub start: u64,
    pub end: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub private: bool,
    pub path: Option<String>,
    pub deleted: bool,
}

impl MapRegion {
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
    pub fn is_wx(&self) -> bool {
        self.writable && self.executable
    }
    pub fn is_anonymous(&self) -> bool {
        self.path.as_deref().map(|p| p.is_empty()).unwrap_or(true)
    }
}

/// Parse one maps line, e.g.
/// `7f..-7f.. r-xp 00000000 08:01 1234 /usr/lib/libc.so.6`
pub fn parse_maps_line(line: &str) -> Option<MapRegion> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let perms = parts.next()?;
    let _offset = parts.next()?;
    let _dev = parts.next()?;
    let _inode = parts.next()?;
    // Remainder (may contain spaces) is the pathname.
    let rest: String = {
        let idx = line.find(perms)? + perms.len();
        let after = &line[idx..];
        // skip offset/dev/inode columns to reach the path
        let mut it = after.split_whitespace();
        it.next();
        it.next();
        it.next();
        it.collect::<Vec<_>>().join(" ")
    };

    let (start_s, end_s) = range.split_once('-')?;
    let start = u64::from_str_radix(start_s, 16).ok()?;
    let end = u64::from_str_radix(end_s, 16).ok()?;

    let b = perms.as_bytes();
    let readable = b.first() == Some(&b'r');
    let writable = b.get(1) == Some(&b'w');
    let executable = b.get(2) == Some(&b'x');
    let private = b.get(3) == Some(&b'p');

    let path = rest.trim();
    let deleted = path.ends_with("(deleted)");
    let clean_path = path.trim_end_matches("(deleted)").trim();
    let path = if clean_path.is_empty() {
        None
    } else {
        Some(clean_path.to_string())
    };

    Some(MapRegion {
        start,
        end,
        readable,
        writable,
        executable,
        private,
        path,
        deleted,
    })
}

/// Parse a whole maps file.
pub fn parse_maps(content: &str) -> Vec<MapRegion> {
    content.lines().filter_map(parse_maps_line).collect()
}

/// Classify regions of a process into detections.
pub fn classify(pid: u32, regions: &[MapRegion]) -> Vec<Detection> {
    let mut out = Vec::new();
    for r in regions {
        if r.is_wx() {
            out.push(Detection::new(
                "Memory",
                format!("Suspicious.WX:{pid}"),
                Severity::Medium,
                ThreatClass::Behavioral,
                format!(
                    "PID {pid}: writable+executable region {:#x}-{:#x} ({} KiB){}",
                    r.start,
                    r.end,
                    r.size() / 1024,
                    r.path
                        .as_deref()
                        .map(|p| format!(" [{p}]"))
                        .unwrap_or_default()
                ),
            ));
        }
        if r.executable && r.deleted {
            out.push(Detection::new(
                "Memory",
                format!("Injected.DeletedBacking:{pid}"),
                Severity::High,
                ThreatClass::Behavioral,
                format!(
                    "PID {pid}: executing code from a deleted file {:#x}-{:#x} [{}]",
                    r.start,
                    r.end,
                    r.path.as_deref().unwrap_or("?")
                ),
            ));
        } else if r.executable && r.is_anonymous() && !r.is_wx() {
            // Anonymous executable (not already reported as W+X).
            out.push(Detection::new(
                "Memory",
                format!("Injected.AnonExec:{pid}"),
                Severity::Medium,
                ThreatClass::Behavioral,
                format!(
                    "PID {pid}: anonymous executable region {:#x}-{:#x} ({} KiB) with no backing file",
                    r.start,
                    r.end,
                    r.size() / 1024
                ),
            ));
        }
    }
    out
}

/// Scan a single process by PID.
pub fn scan_pid(pid: u32) -> Vec<Detection> {
    match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
        Ok(content) => classify(pid, &parse_maps(&content)),
        Err(_) => Vec::new(),
    }
}

/// Scan every process the caller can read.
pub fn scan_all() -> Vec<Detection> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            if let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                out.extend(scan_pid(pid));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_file_backed_region() {
        let line = "7f8c00000000-7f8c00021000 r-xp 00000000 08:01 1234 /usr/lib/libc.so.6";
        let r = parse_maps_line(line).unwrap();
        assert!(r.readable && r.executable && !r.writable);
        assert_eq!(r.path.as_deref(), Some("/usr/lib/libc.so.6"));
        assert!(!r.deleted);
        assert_eq!(r.size(), 0x21000);
    }

    #[test]
    fn parses_anonymous_wx_region() {
        let line = "0055aa000000-0055aa001000 rwxp 00000000 00:00 0 ";
        let r = parse_maps_line(line).unwrap();
        assert!(r.is_wx());
        assert!(r.is_anonymous());
    }

    #[test]
    fn parses_deleted_backing() {
        let line = "400000-401000 r-xp 00000000 08:01 99 /tmp/dropper (deleted)";
        let r = parse_maps_line(line).unwrap();
        assert!(r.deleted);
        assert!(r.executable);
        assert_eq!(r.path.as_deref(), Some("/tmp/dropper"));
    }

    #[test]
    fn classify_flags_injection_patterns() {
        let maps = "\
0055aa000000-0055aa001000 rwxp 00000000 00:00 0
400000-401000 r-xp 00000000 08:01 99 /tmp/x (deleted)
7f0000000000-7f0000001000 r-xp 00000000 08:01 1 /usr/lib/libc.so.6
0066bb000000-0066bb001000 r-xp 00000000 00:00 0 ";
        let regions = parse_maps(maps);
        let d = classify(4242, &regions);
        assert!(d.iter().any(|x| x.threat.starts_with("Suspicious.WX")));
        assert!(d
            .iter()
            .any(|x| x.threat.starts_with("Injected.DeletedBacking")));
        assert!(d.iter().any(|x| x.threat.starts_with("Injected.AnonExec")));
        // libc r-x file-backed region must NOT be flagged.
        assert_eq!(
            d.iter().filter(|x| x.threat.contains("AnonExec")).count(),
            1
        );
    }

    #[test]
    fn scanning_self_is_safe() {
        let pid = std::process::id();
        // Just ensure it runs and returns without error.
        let _ = scan_pid(pid);
    }
}
