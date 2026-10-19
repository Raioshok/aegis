//! Persistent, JSON-backed application configuration.

use crate::error::{AegisError, Result};
use crate::paths;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Which engines participate in a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineToggles {
    pub hash: bool,
    pub yara: bool,
    pub heuristic: bool,
}

impl Default for EngineToggles {
    fn default() -> Self {
        Self {
            hash: true,
            yara: true,
            heuristic: true,
        }
    }
}

/// Top-level configuration document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub engines: EngineToggles,
    /// Shields & modular feature toggles.
    pub shields: ShieldsConfig,
    /// Kaspersky-style Game Mode (resource throttling & quiet mode).
    pub game_mode: GameModeConfig,
    /// Skip files larger than this (bytes). Protects against huge-file DoS.
    pub max_file_size: u64,
    /// Shannon-entropy threshold above which a binary is flagged as packed.
    pub entropy_threshold: f64,
    /// Scan dot-files and dot-directories.
    pub scan_hidden: bool,
    /// Follow symbolic links while walking (off by default — loop/escape safe).
    pub follow_symlinks: bool,
    /// Glob-free path prefixes excluded from scanning.
    pub exclusions: Vec<PathBuf>,
    /// Worker threads for parallel scanning (0 = auto/all cores).
    pub threads: usize,
    /// Real-time protection settings (daemon).
    pub realtime: RealtimeConfig,
    /// Scheduled-scan settings (daemon).
    pub schedule: ScheduleConfig,
    /// Ransomware behavioural-guard settings (daemon).
    pub ransomware: RansomwareSettings,
}

/// Shields & protection component toggles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldsConfig {
    pub realtime_filesystem: bool,
    pub memory_defense: bool,
    pub network_firewall: bool,
    pub ransomware_guard: bool,
    pub cloud_threat_feeds: bool,
}

impl Default for ShieldsConfig {
    fn default() -> Self {
        Self {
            realtime_filesystem: true,
            memory_defense: true,
            network_firewall: true,
            ransomware_guard: true,
            cloud_threat_feeds: true,
        }
    }
}

/// Kaspersky-style Gaming Mode (resource throttling & quiet mode during full-screen games).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameModeConfig {
    pub enabled: bool,
    pub auto_detect: bool,
    pub lower_priority: bool,
    pub suppress_notifications: bool,
    pub pause_background_scans: bool,
}

impl Default for GameModeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_detect: true,
            lower_priority: true,
            suppress_notifications: true,
            pause_background_scans: true,
        }
    }
}

/// Behavioural ransomware-guard configuration (plain data; mapped to the
/// behaviour engine's config in the daemon).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareSettings {
    pub enabled: bool,
    /// Sliding detection window in milliseconds.
    pub window_ms: u64,
    /// Writes within the window to consider a burst.
    pub max_writes: usize,
    /// Entropy at/above which written content looks encrypted.
    pub entropy_threshold: f64,
    /// High-entropy writes within the window required to alert.
    pub min_high_entropy: usize,
    /// Renames to the same extension required to flag a rename storm.
    pub rename_storm: usize,
    /// Kill the offending process on detection (needs the fanotify backend for
    /// process attribution).
    pub auto_kill: bool,
}

impl Default for RansomwareSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            window_ms: 5_000,
            max_writes: 20,
            entropy_threshold: 7.5,
            min_high_entropy: 12,
            rename_storm: 12,
            auto_kill: false,
        }
    }
}

/// Real-time on-access protection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeConfig {
    /// Master switch for the real-time monitor.
    pub enabled: bool,
    /// Directories watched for new/changed files.
    pub paths: Vec<PathBuf>,
    /// Watch backend: `"inotify"` (unprivileged, per-directory) or
    /// `"fanotify"` (mount-wide, requires CAP_SYS_ADMIN).
    pub backend: String,
    /// Automatically quarantine files detected in real time (no prompt).
    pub auto_quarantine: bool,
}

impl Default for RealtimeConfig {
    fn default() -> Self {
        let downloads = std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Downloads"))
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        Self {
            enabled: false,
            paths: vec![downloads],
            backend: "inotify".to_string(),
            auto_quarantine: false,
        }
    }
}

/// Scheduled full/quick scan configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// Run a periodic scan while the daemon is up.
    pub enabled: bool,
    /// Interval between scheduled scans, in minutes.
    pub interval_minutes: u64,
    /// Target directory for the scheduled scan.
    pub target: PathBuf,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        Self {
            enabled: false,
            interval_minutes: 720, // twice a day
            target: home,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            engines: EngineToggles::default(),
            shields: ShieldsConfig::default(),
            game_mode: GameModeConfig::default(),
            max_file_size: 200 * 1024 * 1024,
            entropy_threshold: 7.2,
            scan_hidden: true,
            follow_symlinks: false,
            exclusions: vec![
                PathBuf::from("/proc"),
                PathBuf::from("/sys"),
                PathBuf::from("/dev"),
                PathBuf::from("/run"),
            ],
            threads: 0,
            realtime: RealtimeConfig::default(),
            schedule: ScheduleConfig::default(),
            ransomware: RansomwareSettings::default(),
        }
    }
}

impl Config {
    /// Load configuration, falling back to defaults on missing/corrupt files.
    pub fn load() -> Self {
        let path = paths::config_file();
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
                tracing::warn!(?path, error = %e, "invalid config, using defaults");
                Config::default()
            }),
            Err(_) => Config::default(),
        }
    }

    /// Persist configuration to disk.
    pub fn save(&self) -> Result<()> {
        paths::ensure_dirs().map_err(|e| AegisError::io(paths::config_dir(), e))?;
        let path = paths::config_file();
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, text).map_err(|e| AegisError::io(&path, e))
    }

    /// Whether `path` is under any configured exclusion prefix.
    pub fn is_excluded(&self, path: &std::path::Path) -> bool {
        self.exclusions.iter().any(|ex| path.starts_with(ex))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert!(c.engines.yara);
        assert!(c.max_file_size > 0);
        assert!(c.is_excluded(std::path::Path::new("/proc/1/maps")));
        assert!(!c.is_excluded(std::path::Path::new("/home/user/file")));
    }

    #[test]
    fn roundtrip_json() {
        let c = Config::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.entropy_threshold, c.entropy_threshold);
    }
}
