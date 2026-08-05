//! XDG-compliant filesystem locations.
//!
//! Aegis runs both as an unprivileged CLI (per-user data under `$XDG_*`) and,
//! later, as a system daemon (data under `/var/lib/aegis`). This module resolves
//! the right base directories for the current context.

use std::path::PathBuf;

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

fn home() -> PathBuf {
    env_path("HOME").unwrap_or_else(|| PathBuf::from("/root"))
}

/// `$XDG_CONFIG_HOME/aegis` (default `~/.config/aegis`).
pub fn config_dir() -> PathBuf {
    env_path("XDG_CONFIG_HOME")
        .unwrap_or_else(|| home().join(".config"))
        .join("aegis")
}

/// `$XDG_DATA_HOME/aegis` (default `~/.local/share/aegis`).
pub fn data_dir() -> PathBuf {
    env_path("XDG_DATA_HOME")
        .unwrap_or_else(|| home().join(".local/share"))
        .join("aegis")
}

pub fn config_file() -> PathBuf {
    config_dir().join("config.json")
}

pub fn whitelist_file() -> PathBuf {
    config_dir().join("whitelist.json")
}

pub fn database_file() -> PathBuf {
    data_dir().join("aegis.db")
}

pub fn quarantine_dir() -> PathBuf {
    data_dir().join("quarantine")
}

/// Directory holding the encryption key for the quarantine vault.
pub fn keyring_file() -> PathBuf {
    data_dir().join("quarantine.key")
}

/// User-supplied YARA rules directory.
pub fn user_rules_dir() -> PathBuf {
    config_dir().join("yara-rules")
}

/// Ensure all runtime directories exist with restrictive permissions.
pub fn ensure_dirs() -> std::io::Result<()> {
    use std::fs;
    for dir in [config_dir(), data_dir(), quarantine_dir(), user_rules_dir()] {
        fs::create_dir_all(&dir)?;
    }
    // Quarantine may hold live malware — lock it down to the owner.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let q = quarantine_dir();
        if let Ok(meta) = fs::metadata(&q) {
            let mut perm = meta.permissions();
            perm.set_mode(0o700);
            let _ = fs::set_permissions(&q, perm);
        }
    }
    Ok(())
}
