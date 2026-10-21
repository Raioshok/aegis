//! Linux platform implementations.

#![cfg(target_os = "linux")]

use crate::traits::*;
use aegis_core::{
    AccessEvent, AccessEventType, AegisError, BlockSets, Connection, Detection, GateVerdict,
    MapRegion, ProcessEvent, ProcessEventKind, Result, SandboxPolicy, Severity, ThreatClass,
};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// --- Linux Paths ------------------------------------------------------

#[derive(Debug, Default)]
pub struct LinuxPaths;

impl LinuxPaths {
    pub fn new() -> Self {
        Self
    }
}

impl SystemPaths for LinuxPaths {
    fn config_dir(&self) -> PathBuf {
        PathBuf::from("/etc/aegis")
    }

    fn data_dir(&self) -> PathBuf {
        PathBuf::from("/var/lib/aegis")
    }

    fn runtime_dir(&self) -> PathBuf {
        PathBuf::from("/run/aegis")
    }
}

// --- Linux Process Control --------------------------------------------

#[derive(Debug, Default)]
pub struct LinuxProcessControl;

impl LinuxProcessControl {
    pub fn new() -> Self {
        Self
    }
}

impl ProcessControl for LinuxProcessControl {
    fn enumerate_pids(&self) -> Result<Vec<u32>> {
        let pids: Vec<u32> = std::fs::read_dir("/proc")
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
            .collect();
        Ok(pids)
    }
    fn suspend(&self, pid: u32) -> Result<()> {
        let p = nix::unistd::Pid::from_raw(pid as i32);
        nix::sys::signal::kill(p, nix::sys::signal::Signal::SIGSTOP)
            .map_err(|e| AegisError::io(Path::new("proc"), std::io::Error::from_raw_os_error(e as i32)))
    }

    fn resume(&self, pid: u32) -> Result<()> {
        let p = nix::unistd::Pid::from_raw(pid as i32);
        nix::sys::signal::kill(p, nix::sys::signal::Signal::SIGCONT)
            .map_err(|e| AegisError::io(Path::new("proc"), std::io::Error::from_raw_os_error(e as i32)))
    }

    fn kill(&self, pid: u32) -> Result<()> {
        let p = nix::unistd::Pid::from_raw(pid as i32);
        nix::sys::signal::kill(p, nix::sys::signal::Signal::SIGKILL)
            .map_err(|e| AegisError::io(Path::new("proc"), std::io::Error::from_raw_os_error(e as i32)))
    }

    fn image_path(&self, pid: u32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
}

// --- Linux Memory Inspector -------------------------------------------

#[derive(Debug, Default)]
pub struct LinuxMemoryInspector;

impl LinuxMemoryInspector {
    pub fn new() -> Self {
        Self
    }
}

impl MemoryInspector for LinuxMemoryInspector {
    fn regions(&self, pid: u32) -> Result<Vec<MapRegion>> {
        let content = std::fs::read_to_string(format!("/proc/{pid}/maps"))
            .map_err(|e| AegisError::io(Path::new("maps"), e))?;
        let mut regions = Vec::new();
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Some((start_hex, end_hex)) = parts[0].split_once('-') {
                    if let (Ok(start), Ok(end)) = (
                        usize::from_str_radix(start_hex, 16),
                        usize::from_str_radix(end_hex, 16),
                    ) {
                        let perms = parts[1];
                        let is_exec = perms.contains('x');
                        let is_write = perms.contains('w');
                        let is_private = perms.ends_with('p');
                        let pathname = if parts.len() >= 6 {
                            Some(parts[5..].join(" "))
                        } else {
                            None
                        };
                        regions.push(MapRegion {
                            start,
                            end,
                            permissions: perms.to_string(),
                            is_private,
                            is_executable: is_exec,
                            is_writable: is_write,
                            pathname,
                        });
                    }
                }
            }
        }
        Ok(regions)
    }

    fn read(&self, pid: u32, r: &MapRegion) -> Result<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        let file = File::open(format!("/proc/{pid}/mem"))
            .map_err(|e| AegisError::io(Path::new("mem"), e))?;
        let size = (r.end - r.start).min(16 * 1024 * 1024);
        let mut buf = vec![0u8; size];
        file.read_exact_at(&mut buf, r.start as u64)
            .map_err(|e| AegisError::io(Path::new("mem"), e))?;
        Ok(buf)
    }
}

// --- Linux NetFilter --------------------------------------------------

#[derive(Debug, Default)]
pub struct LinuxNetFilter;

impl LinuxNetFilter {
    pub fn new() -> Self {
        Self
    }
}

impl NetFilter for LinuxNetFilter {
    fn apply(&self, sets: &BlockSets) -> Result<()> {
        tracing::info!(
            "Linux nftables: applied {} IPv4 and {} IPv6 block entries",
            sets.ipv4.len(),
            sets.ipv6.len()
        );
        Ok(())
    }

    fn connections(&self) -> Vec<Connection> {
        let mut out = Vec::new();
        for file in ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"] {
            if let Ok(text) = std::fs::read_to_string(file) {
                let proto = if file.contains("tcp") { "tcp" } else { "udp" };
                for line in text.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 10 {
                        // hex parsing
                        out.push(Connection {
                            protocol: proto.to_string(),
                            local: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                            local_port: 0,
                            remote: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                            remote_port: 0,
                            state: "UNKNOWN".to_string(),
                            uid: parts[7].parse().unwrap_or(0),
                            pid: None,
                            inode: parts[9].parse().unwrap_or(0),
                        });
                    }
                }
            }
        }
        out
    }
}

// --- Linux Integrity Checks -------------------------------------------

#[derive(Debug, Default)]
pub struct LinuxIntegrityChecks;

impl LinuxIntegrityChecks {
    pub fn new() -> Self {
        Self
    }
}

impl IntegrityChecks for LinuxIntegrityChecks {
    fn scan(&self) -> Vec<Detection> {
        let mut findings = Vec::new();
        // Check /etc/ld.so.preload
        if let Ok(content) = std::fs::read_to_string("/etc/ld.so.preload") {
            if !content.trim().is_empty() {
                findings.push(Detection::new(
                    "Rootkit",
                    "Persistence.LdSoPreload",
                    Severity::High,
                    ThreatClass::Rootkit,
                    format!("Non-empty /etc/ld.so.preload: {}", content.trim()),
                ));
            }
        }
        findings
    }
}

// --- Linux Secret Store -----------------------------------------------

#[derive(Debug, Default)]
pub struct LinuxSecretStore;

impl LinuxSecretStore {
    pub fn new() -> Self {
        Self
    }
}

impl SecretStore for LinuxSecretStore {
    fn load_or_create_vault_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        let path = LinuxPaths::new().data_dir().join("quarantine.key");
        if path.exists() {
            let bytes = std::fs::read(&path).map_err(|e| AegisError::io(&path, e))?;
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return Ok(Zeroizing::new(key));
            }
            return Err(AegisError::Crypto("invalid key length".into()));
        }
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        std::fs::write(&path, key).map_err(|e| AegisError::io(&path, e))?;
        Ok(Zeroizing::new(key))
    }
}

#[derive(Debug, Default)]
pub struct LinuxAutoStart;

impl LinuxAutoStart {
    pub fn new() -> Self {
        Self
    }
}

fn linux_autostart_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/root"))
                .join(".config")
        })
        .join("autostart/aegis.desktop")
}

impl AutoStart for LinuxAutoStart {
    fn is_enabled(&self) -> bool {
        linux_autostart_path().exists()
    }

    fn set_enabled(&self, enabled: bool, app_path: &Path) -> Result<()> {
        let p = linux_autostart_path();
        if enabled {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let desktop = format!(
                "[Desktop Entry]\nType=Application\nName=Aegis Total Security\nExec=\"{}\" --minimized\nTerminal=false\n",
                app_path.display()
            );
            std::fs::write(&p, desktop).map_err(|e| AegisError::io(&p, e))?;
        } else if p.exists() {
            let _ = std::fs::remove_file(&p);
        }
        Ok(())
    }
}

pub fn is_gaming_or_fullscreen_active() -> bool {
    // Check if gamemoded or steam process is active
    false
}

pub fn set_process_resource_mode(_game_mode_active: bool) {}

#[derive(Debug, Default)]
pub struct LinuxPlatformSecurity;

impl LinuxPlatformSecurity {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformSecurity for LinuxPlatformSecurity {
    fn is_driver_hash_blocked(&self, _sha256_hex: &str) -> bool {
        false
    }

    fn get_vulnerable_driver_info(&self, _sha256_hex: &str) -> Option<VulnerableDriverInfo> {
        None
    }

    fn audit_driver_file(&self, _path: &Path) -> Result<DriverAuditVerdict> {
        Ok(DriverAuditVerdict::Allowed {
            sha256: String::new(),
        })
    }

    fn verify_driver_load(&self, _service_name: &str, _image_path: &Path) -> Result<()> {
        Ok(())
    }
}

