//! Plugin manifest and permission model.

use serde::{Deserialize, Serialize};

/// Capabilities a plugin may request. Aegis enforces least privilege: a plugin
/// only receives the permissions its manifest declares *and* the host grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Read files under paths the host passes it.
    ReadFiles,
    /// Contribute detections to a scan.
    Scan,
    /// Read quarantine metadata.
    ReadQuarantine,
    /// Make outbound network requests (e.g. threat-intel lookups).
    Network,
    /// Read scan/threat history.
    ReadHistory,
}

/// A plugin's declared identity and requirements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    pub author: String,
    /// Executable/script the host runs (relative to the plugin dir).
    pub entrypoint: String,
    /// Host SDK API version this plugin targets.
    pub api_version: u32,
    /// Permissions the plugin requests.
    #[serde(default)]
    pub permissions: Vec<Permission>,
}

/// The SDK API version this build of Aegis implements.
pub const API_VERSION: u32 = 1;

impl PluginManifest {
    /// Canonical bytes that are signed/verified — a stable JSON serialization.
    pub fn signing_bytes(&self) -> Vec<u8> {
        // serde_json with sorted keys would be ideal; the struct field order is
        // stable, so to_vec is deterministic for a given serde_json version.
        serde_json::to_vec(self).expect("manifest serializes")
    }

    pub fn grants(&self, perm: Permission) -> bool {
        self.permissions.contains(&perm)
    }

    pub fn api_compatible(&self) -> bool {
        self.api_version == API_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PluginManifest {
        PluginManifest {
            name: "yara-extra".into(),
            version: "1.0.0".into(),
            description: "extra rules".into(),
            author: "me".into(),
            entrypoint: "run.sh".into(),
            api_version: API_VERSION,
            permissions: vec![Permission::Scan, Permission::ReadFiles],
        }
    }

    #[test]
    fn permissions_and_api() {
        let m = sample();
        assert!(m.grants(Permission::Scan));
        assert!(!m.grants(Permission::Network));
        assert!(m.api_compatible());
    }

    #[test]
    fn signing_bytes_are_stable() {
        let m = sample();
        assert_eq!(m.signing_bytes(), m.clone().signing_bytes());
    }
}
