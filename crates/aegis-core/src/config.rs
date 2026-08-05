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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            engines: EngineToggles::default(),
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
