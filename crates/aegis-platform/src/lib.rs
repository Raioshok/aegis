//! # aegis-platform
//!
//! OS-abstraction platform layer providing traits and OS-specific implementations
//! for Linux and Windows.

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
