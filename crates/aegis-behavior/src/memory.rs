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
use std::path::Path;

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
    pub fn is_unbacked(&self) -> bool {
        self.is_anonymous() || self.private
    }
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

impl From<&aegis_core::MapRegion> for MapRegion {
    fn from(r: &aegis_core::MapRegion) -> Self {
        let readable = r.permissions.starts_with('r');
        MapRegion {
            start: r.start as u64,
            end: r.end as u64,
            readable,
            writable: r.is_writable,
            executable: r.is_executable,
            private: r.is_private,
            path: r.pathname.clone(),
            deleted: false,
        }
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

/// Check whether a function prologue exhibits known evasion patches (AMSI/ETW bypass).
pub fn is_known_bypass_patch(prologue: &[u8]) -> bool {
    if prologue.is_empty() {
        return false;
    }
    // ret (0xC3) directly at entrypoint
    if prologue[0] == 0xC3 {
        return true;
    }
    // ret imm16 (0xC2, 0x18, 0x00 or 0xC2, 0x14, 0x00)
    if prologue[0] == 0xC2 {
        return true;
    }
    // xor eax, eax; ret (31 C0 C3 or 33 C0 C3)
    if prologue.len() >= 3 && (prologue[0..3] == [0x31, 0xC0, 0xC3] || prologue[0..3] == [0x33, 0xC0, 0xC3]) {
        return true;
    }
    // mov eax, 0x80070057; ret (B8 57 00 07 80 C3 - common AMSI E_INVALIDARG bypass)
    if prologue.len() >= 6 && prologue[0..6] == [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3] {
        return true;
    }
    // mov eax, 0; ret (B8 00 00 00 00 C3)
    if prologue.len() >= 6 && prologue[0..6] == [0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3] {
        return true;
    }
    false
}

/// Known JIT runtimes that legitimately allocate W+X memory.
pub fn is_known_jit_process(exe: &Path) -> bool {
    let name = exe
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "chrome.exe"
            | "msedge.exe"
            | "firefox.exe"
            | "node.exe"
            | "node"
            | "java.exe"
            | "java"
            | "javaw.exe"
            | "dotnet.exe"
            | "dotnet"
            | "code.exe"
    )
}

/// Scan a single process by PID.
pub fn scan_pid(pid: u32) -> Vec<Detection> {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
            Ok(content) => {
                let mut res = classify(pid, &parse_maps(&content));
                if content.contains("memfd:") {
                    res.push(Detection::new(
                        "Memory",
                        format!("Injected.MemfdExecution:{pid}"),
                        Severity::High,
                        ThreatClass::Behavioral,
                        format!("PID {pid} executing fileless payload mapped via memfd_create"),
                    ));
                }
                res
            }
            Err(_) => Vec::new(),
        }
    }
    #[cfg(windows)]
    {
        let inspector = aegis_platform::default_memory_inspector();
        let proc_ctrl = aegis_platform::default_process_control();
        let mut out = Vec::new();

        let img_path = proc_ctrl.image_path(pid);
        let is_jit = img_path
            .as_deref()
            .map(is_known_jit_process)
            .unwrap_or(false);

        if let Ok(regions) = inspector.regions(pid) {
            for r in &regions {
                if r.is_executable && r.is_writable {
                    // Suppress or downgrade W+X alerts for legitimate JIT engines (browsers, JVM, node)
                    if !is_jit {
                        out.push(Detection::new(
                            "Memory",
                            format!("Suspicious.WX:0x{:x}", r.start),
                            Severity::Medium,
                            ThreatClass::Behavioral,
                            format!("PID {pid} has W+X page at 0x{:x}-0x{:x}", r.start, r.end),
                        ));
                    }
                }
                if r.is_executable && r.is_private {
                    out.push(Detection::new(
                        "Memory",
                        format!("Injected.AnonExec:0x{:x}", r.start),
                        Severity::High,
                        ThreatClass::Behavioral,
                        format!("PID {pid} has private executable page (shellcode / injection) at 0x{:x}", r.start),
                    ));

                    // Inspect content of private executable page for reflective PEs and direct syscall stubs
                    if let Ok(mem_head) = inspector.read(pid, r) {
                        if mem_head.starts_with(b"MZ") && mem_head.len() >= 0x40 {
                            let pe_off = u32::from_le_bytes(mem_head[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
                            if pe_off + 4 <= mem_head.len() && &mem_head[pe_off..pe_off + 4] == b"PE\0\0" {
                                out.push(Detection::new(
                                    "Memory",
                                    format!("Injected.ReflectivePE:0x{:x}", r.start),
                                    Severity::Critical,
                                    ThreatClass::Behavioral,
                                    format!("PID {pid} has unbacked in-memory PE image (Reflective DLL injection) at 0x{:x}", r.start),
                                ));
                            }
                        }

                        if find_direct_syscall_stub(&mem_head) {
                            out.push(Detection::new(
                                "Memory",
                                format!("Injected.DirectSyscall:0x{:x}", r.start),
                                Severity::Critical,
                                ThreatClass::Rootkit,
                                format!("PID {pid} has direct syscall stubs in unbacked memory at 0x{:x} (Hell's Gate / SysWhispers EDR bypass)", r.start),
                            ));
                        }
                    }
                }

                // Check for ntdll unhooking / text tampering
                if let Some(ref path_str) = r.pathname {
                    if path_str.to_ascii_lowercase().ends_with("ntdll.dll") && r.is_writable && r.is_executable {
                        out.push(Detection::new(
                            "Memory",
                            format!("Tampering.Ntdll.RWX:{pid}"),
                            Severity::Critical,
                            ThreatClass::Rootkit,
                            format!("PID {pid} modified ntdll.dll .text section to W+X (API unhooking / hook tampering)"),
                        ));
                    }
                }
            }

            // Check for process hollowing
            if let Some(exe_path) = img_path {
                if let Ok(disk_bytes) = std::fs::read(&exe_path) {
                    if disk_bytes.starts_with(b"MZ") && disk_bytes.len() >= 0x40 {
                        // Find matching base header region in memory
                        for r in &regions {
                            if r.start < 0x7FFF_FFFF_0000 && r.permissions.starts_with('r') {
                                if let Ok(mem_bytes) = inspector.read(pid, r) {
                                    if mem_bytes.starts_with(b"MZ") && mem_bytes.len() >= 0x40 {
                                        // e_lfanew pointer to PE signature at offset 0x3c
                                        let pe_off_disk = u32::from_le_bytes(disk_bytes[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
                                        let pe_off_mem = u32::from_le_bytes(mem_bytes[0x3c..0x40].try_into().unwrap_or([0; 4])) as usize;
                                        if pe_off_disk != pe_off_mem || (pe_off_disk + 4 <= disk_bytes.len() && pe_off_mem + 4 <= mem_bytes.len() && &disk_bytes[pe_off_disk..pe_off_disk + 4] != &mem_bytes[pe_off_mem..pe_off_mem + 4]) {
                                            out.push(Detection::new(
                                                "Memory",
                                                format!("Injected.ProcessHollowing:{pid}"),
                                                Severity::Critical,
                                                ThreatClass::Behavioral,
                                                format!("Process image at {} was hollowed in memory", exe_path.display()),
                                            ));
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check for unbacked thread execution, thread hijacking, and FunctionPeekaboo
            if let Ok(anomalies) = inspector.inspect_threads(pid) {
                for a in anomalies {
                    if !is_jit {
                        if a.is_function_peekaboo {
                            out.push(Detection::new(
                                "Memory",
                                format!("Evasion.FunctionPeekaboo:{pid}:{}", a.tid),
                                Severity::Critical,
                                ThreatClass::Rootkit,
                                format!("PID {pid} thread {} exhibits FunctionPeekaboo LLVM on-demand function masking in TEB.UserReserved", a.tid),
                            ));
                        } else if a.is_rip_unbacked {
                            out.push(Detection::new(
                                "Memory",
                                format!("Injected.ThreadHijack:{pid}:{}", a.tid),
                                Severity::Critical,
                                ThreatClass::Behavioral,
                                format!("PID {pid} thread {} instruction pointer (RIP=0x{:x}) in unbacked memory (Thread Hijacking / PoolParty)", a.tid, a.rip),
                            ));
                        } else if a.is_start_unbacked {
                            out.push(Detection::new(
                                "Memory",
                                format!("Injected.UnbackedThread:{pid}:{}", a.tid),
                                Severity::Critical,
                                ThreatClass::Behavioral,
                                format!("PID {pid} thread {} start address 0x{:x} in unbacked memory (CreateRemoteThread / Shellcode)", a.tid, a.start_address),
                            ));
                        }
                    }
                }
            }

            // Check for Module Stomping & Section Overwriting in signed DLLs
            if let Ok(stomps) = inspector.detect_module_stomping(pid) {
                for s in stomps {
                    out.push(Detection::new(
                        "Memory",
                        format!("Injected.ModuleStomping:{pid}:{}", s.module_name),
                        Severity::Critical,
                        ThreatClass::Rootkit,
                        format!("PID {pid} module {} (.text section at 0x{:x}) code was stomped in memory (disk: {}, mem: {})",
                            s.module_name, s.base_address + s.text_rva, &s.disk_sha256[..12], &s.mem_sha256[..12]
                        ),
                    ));
                }
            }
        }
        out
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = pid;
        Vec::new()
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

/// Checks if a memory page contains raw x86_64 direct syscall stubs (Hell's Gate / SysWhispers).
fn find_direct_syscall_stub(bytes: &[u8]) -> bool {
    if bytes.len() < 12 {
        return false;
    }
    for w in bytes.windows(12) {
        // Pattern 1: 4c 8b d1 b8 ?? ?? 00 00 0f 05 c3 (mov r10, rcx; mov eax, <ssn>; syscall; ret)
        if w[0] == 0x4c && w[1] == 0x8b && w[2] == 0xd1 && w[3] == 0xb8 && w[8] == 0x0f && w[9] == 0x05 {
            return true;
        }
        // Pattern 2: 49 89 ca b8 ?? ?? 00 00 0f 05 c3 (mov r10, rcx; mov eax, <ssn>; syscall; ret)
        if w[0] == 0x49 && w[1] == 0x89 && w[2] == 0xca && w[3] == 0xb8 && w[8] == 0x0f && w[9] == 0x05 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_syscall_stub_detection() {
        // mov r10, rcx; mov eax, 0x18; syscall; ret
        let stub = [0x4c, 0x8b, 0xd1, 0xb8, 0x18, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3, 0x90];
        assert!(find_direct_syscall_stub(&stub));
        let innocent = [0x90; 12];
        assert!(!find_direct_syscall_stub(&innocent));
    }

    #[test]
    fn test_amsi_etw_bypass_patch_detection() {
        assert!(is_known_bypass_patch(&[0xC3])); // ret
        assert!(is_known_bypass_patch(&[0x31, 0xC0, 0xC3])); // xor eax, eax; ret
        assert!(is_known_bypass_patch(&[0x33, 0xC0, 0xC3])); // xor eax, eax; ret
        assert!(is_known_bypass_patch(&[0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3])); // AMSI invalid arg
        assert!(is_known_bypass_patch(&[0xC2, 0x18, 0x00])); // ret 0x18
        assert!(!is_known_bypass_patch(&[0x48, 0x89, 0x5C, 0x24, 0x08])); // standard prologue
    }

    #[test]
    fn test_jit_process_allowlist() {
        assert!(is_known_jit_process(Path::new("chrome.exe")));
        assert!(is_known_jit_process(Path::new("node.exe")));
        assert!(!is_known_jit_process(Path::new("mimikatz.exe")));
    }

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
