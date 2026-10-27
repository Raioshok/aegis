//! # aegis-platform
//!
//! OS-abstraction platform layer providing traits and OS-specific implementations
//! for Linux and Windows.

pub mod hardening;
pub mod traits;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(windows)]
pub mod windows;

pub use traits::*;

#[cfg(windows)]
pub use windows::*;

#[cfg(target_os = "linux")]
pub use linux::*;

pub fn default_paths() -> Box<dyn SystemPaths> {
    #[cfg(windows)]
    {
        Box::new(WindowsPaths::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxPaths::new())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        panic!("unsupported platform");
    }
}

pub fn default_process_control() -> Box<dyn ProcessControl> {
    #[cfg(windows)]
    {
        Box::new(WindowsProcessControl::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxProcessControl::new())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        panic!("unsupported platform");
    }
}

pub fn default_memory_inspector() -> Box<dyn MemoryInspector> {
    #[cfg(windows)]
    {
        Box::new(WindowsMemoryInspector::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxMemoryInspector::new())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        panic!("unsupported platform");
    }
}

pub fn default_netfilter() -> Box<dyn NetFilter> {
    #[cfg(windows)]
    {
        Box::new(WindowsNetFilter::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxNetFilter::new())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        panic!("unsupported platform");
    }
}

pub fn default_integrity_checks() -> Box<dyn IntegrityChecks> {
    #[cfg(windows)]
    {
        Box::new(WindowsIntegrityChecks::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxIntegrityChecks::new())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        panic!("unsupported platform");
    }
}

pub fn default_autostart() -> Box<dyn AutoStart> {
    #[cfg(windows)]
    {
        Box::new(WindowsAutoStart::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxAutoStart::new())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        panic!("unsupported platform");
    }
}

pub fn default_platform_security() -> Box<dyn PlatformSecurity> {
    #[cfg(windows)]
    {
        Box::new(WindowsPlatformSecurity::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxPlatformSecurity::new())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        panic!("unsupported platform");
    }
}

pub fn default_secret_store() -> Box<dyn SecretStore> {
    #[cfg(windows)]
    {
        Box::new(WindowsSecretStore::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxSecretStore::new())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        panic!("unsupported platform");
    }
}

pub fn is_gaming_active() -> bool {
    #[cfg(windows)]
    {
        windows::is_gaming_or_fullscreen_active()
    }
    #[cfg(target_os = "linux")]
    {
        linux::is_gaming_or_fullscreen_active()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

pub fn set_process_resource_mode(game_mode_active: bool) {
    #[cfg(windows)]
    {
        windows::set_process_resource_mode(game_mode_active);
    }
    #[cfg(target_os = "linux")]
    {
        linux::set_process_resource_mode(game_mode_active);
    }
}

/// Poll the process table every `interval` and send an `Exec` event (with real
/// parent pid, image path and command line) for each process not seen before,
/// and an `Exit` event for each one that disappeared.
/// The thread exits when the receiver is dropped.
/// Whether `path` is a trusted binary: a valid Authenticode signature on Windows;
/// on Linux (no code signing) a root-owned file that only root can modify.
pub fn is_trusted_binary(path: &std::path::Path) -> bool {
    #[cfg(windows)]
    {
        windows::verify_authenticode(path)
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = path;
        false
    }
}

pub fn start_process_poller(
    interval: std::time::Duration,
) -> std::sync::mpsc::Receiver<aegis_core::ProcessEvent> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("aegis-proc-poller".into())
        .spawn(move || {
            let ctrl = default_process_control();
            let mut known = std::collections::HashSet::new();
            loop {
                let Ok(snapshot) = ctrl.enumerate_processes_snapshot() else {
                    std::thread::sleep(interval);
                    continue;
                };
                let alive: std::collections::HashSet<u32> = snapshot.iter().map(|p| p.0).collect();
                for (pid, ppid, name) in snapshot {
                    if !known.insert(pid) {
                        continue;
                    }
                    let exe = ctrl.image_path(pid).unwrap_or_else(|| std::path::PathBuf::from(&name));
                    let ev = aegis_core::ProcessEvent {
                        pid,
                        ppid,
                        cmdline: ctrl.command_line(pid).unwrap_or_else(|| vec![name]),
                        exe,
                        kind: aegis_core::ProcessEventKind::Exec,
                        timestamp_ms: aegis_core::now_epoch() as u64 * 1000,
                    };
                    if tx.send(ev).is_err() {
                        return;
                    }
                }
                // Report exits and forget them, so a reused pid counts as a new process.
                for pid in known.iter().filter(|p| !alive.contains(p)) {
                    let ev = aegis_core::ProcessEvent {
                        pid: *pid,
                        ppid: 0,
                        exe: std::path::PathBuf::new(),
                        cmdline: Vec::new(),
                        kind: aegis_core::ProcessEventKind::Exit,
                        timestamp_ms: aegis_core::now_epoch() as u64 * 1000,
                    };
                    if tx.send(ev).is_err() {
                        return;
                    }
                }
                known.retain(|pid| alive.contains(pid));
                std::thread::sleep(interval);
            }
        })
        .expect("spawn process poller");
    rx
}
