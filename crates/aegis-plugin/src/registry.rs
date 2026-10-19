//! Plugin registry — discover, verify and gate plugins.
//!
//! A plugin lives in its own directory containing `plugin.json` (the manifest)
//! and `plugin.sig` (hex ed25519 signature). A plugin is **enabled only if** its
//! signature verifies against a public key in the host trust store *and* its API
//! version matches. Everything else is quarantined-off.

use crate::manifest::{Permission, PluginManifest};
use crate::signature::verify;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub enum PluginStatus {
    /// Signature valid + API compatible.
    Trusted,
    /// Signature did not verify against any trusted key.
    Untrusted,
    /// API version mismatch.
    Incompatible,
    /// Manifest/signature missing or malformed.
    Invalid(String),
}

#[derive(Debug, Clone)]
pub struct DiscoveredPlugin {
    pub dir: PathBuf,
    pub manifest: Option<PluginManifest>,
    pub status: PluginStatus,
}

impl DiscoveredPlugin {
    pub fn is_enabled(&self) -> bool {
        self.status == PluginStatus::Trusted
    }

    /// Effective permissions (empty unless trusted).
    pub fn permissions(&self) -> Vec<Permission> {
        match (&self.status, &self.manifest) {
            (PluginStatus::Trusted, Some(m)) => m.permissions.clone(),
            _ => Vec::new(),
        }
    }
}

/// The host's set of trusted publisher public keys (hex).
#[derive(Debug, Default, Clone)]
pub struct TrustStore {
    keys: Vec<String>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_keys<I: IntoIterator<Item = String>>(keys: I) -> Self {
        Self {
            keys: keys.into_iter().collect(),
        }
    }
    pub fn add(&mut self, public_key_hex: impl Into<String>) {
        self.keys.push(public_key_hex.into());
    }
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::with_keys(
                text.lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty() && !l.starts_with('#')),
            ),
            Err(_) => Self::default(),
        }
    }

    /// Verify a manifest against every trusted key; trusted if any match.
    fn verifies(&self, manifest: &PluginManifest, sig_hex: &str) -> bool {
        self.keys
            .iter()
            .any(|k| verify(manifest, sig_hex, k).is_ok())
    }
}

/// Evaluate a single plugin directory.
pub fn evaluate(dir: &Path, trust: &TrustStore) -> DiscoveredPlugin {
    let manifest_path = dir.join("plugin.json");
    let sig_path = dir.join("plugin.sig");

    let manifest: PluginManifest = match std::fs::read_to_string(&manifest_path) {
        Ok(text) => match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                return DiscoveredPlugin {
                    dir: dir.to_path_buf(),
                    manifest: None,
                    status: PluginStatus::Invalid(format!("bad manifest: {e}")),
                }
            }
        },
        Err(e) => {
            return DiscoveredPlugin {
                dir: dir.to_path_buf(),
                manifest: None,
                status: PluginStatus::Invalid(format!("no manifest: {e}")),
            }
        }
    };

    if !manifest.api_compatible() {
        return DiscoveredPlugin {
            dir: dir.to_path_buf(),
            manifest: Some(manifest),
            status: PluginStatus::Incompatible,
        };
    }

    if let Err(e) = manifest.validate_entrypoint() {
        return DiscoveredPlugin {
            dir: dir.to_path_buf(),
            manifest: Some(manifest),
            status: PluginStatus::Invalid(format!("invalid entrypoint: {e}")),
        };
    }

    let sig = std::fs::read_to_string(&sig_path).unwrap_or_default();
    let mut status = if !sig.trim().is_empty() && trust.verifies(&manifest, sig.trim()) {
        PluginStatus::Trusted
    } else {
        PluginStatus::Untrusted
    };

    // If trusted, verify all target hashes (TUF-style integrity check)
    if status == PluginStatus::Trusted && !manifest.targets.is_empty() {
        use sha2::{Digest, Sha256};
        for (rel, target) in &manifest.targets {
            let target_path = dir.join(rel);
            let meta = match std::fs::symlink_metadata(&target_path) {
                Ok(m) => m,
                Err(e) => {
                    status = PluginStatus::Invalid(format!("missing target file {rel}: {e}"));
                    break;
                }
            };
            if meta.file_type().is_symlink() {
                status = PluginStatus::Invalid(format!("target file {rel} is a forbidden symlink"));
                break;
            }
            if meta.len() != target.size {
                status = PluginStatus::Invalid(format!(
                    "target file {rel} size mismatch (expected {}, got {})",
                    target.size,
                    meta.len()
                ));
                break;
            }
            let bytes = match std::fs::read(&target_path) {
                Ok(b) => b,
                Err(e) => {
                    status = PluginStatus::Invalid(format!("read target file {rel}: {e}"));
                    break;
                }
            };
            let digest = hex::encode(Sha256::digest(&bytes));
            if !digest.eq_ignore_ascii_case(&target.sha256) {
                status = PluginStatus::Invalid(format!(
                    "target file {rel} hash mismatch (expected {}, got {})",
                    target.sha256, digest
                ));
                break;
            }
        }
    }

    DiscoveredPlugin {
        dir: dir.to_path_buf(),
        manifest: Some(manifest),
        status,
    }
}

/// Discover and evaluate every plugin under `plugins_dir`.
pub fn discover(plugins_dir: &Path, trust: &TrustStore) -> Vec<DiscoveredPlugin> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(plugins_dir) {
        for e in entries.flatten() {
            if e.path().is_dir() {
                out.push(evaluate(&e.path(), trust));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::API_VERSION;
    use crate::signature::KeyPair;

    fn write_plugin(dir: &Path, manifest: &PluginManifest, sig: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("plugin.json"),
            serde_json::to_vec(manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("plugin.sig"), sig).unwrap();
    }

    fn manifest() -> PluginManifest {
        PluginManifest {
            name: "p".into(),
            version: "1.0".into(),
            description: String::new(),
            author: "a".into(),
            entrypoint: "run".into(),
            api_version: API_VERSION,
            permissions: vec![Permission::Scan],
            targets: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn trusted_plugin_is_enabled() {
        let tmp = tempfile::tempdir().unwrap();
        let kp = KeyPair::generate();
        let m = manifest();
        let sig = kp.sign(&m);
        let pdir = tmp.path().join("good");
        write_plugin(&pdir, &m, &sig);

        let trust = TrustStore::with_keys([kp.public_hex()]);
        let p = evaluate(&pdir, &trust);
        assert!(p.is_enabled());
        assert_eq!(p.permissions(), vec![Permission::Scan]);
    }

    #[test]
    fn untrusted_signature_is_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let kp = KeyPair::generate();
        let attacker = KeyPair::generate();
        let m = manifest();
        let sig = kp.sign(&m);
        let pdir = tmp.path().join("bad");
        write_plugin(&pdir, &m, &sig);

        // trust store only knows the attacker's key, not the signer's
        let trust = TrustStore::with_keys([attacker.public_hex()]);
        let p = evaluate(&pdir, &trust);
        assert_eq!(p.status, PluginStatus::Untrusted);
        assert!(!p.is_enabled());
        assert!(p.permissions().is_empty());
    }

    #[test]
    fn tampered_permissions_break_trust() {
        let tmp = tempfile::tempdir().unwrap();
        let kp = KeyPair::generate();
        let m = manifest();
        let sig = kp.sign(&m); // signed with only Scan
        let mut tampered = m.clone();
        tampered.permissions.push(Permission::Network); // attacker adds Network
        let pdir = tmp.path().join("tampered");
        write_plugin(&pdir, &tampered, &sig);

        let trust = TrustStore::with_keys([kp.public_hex()]);
        let p = evaluate(&pdir, &trust);
        assert_eq!(p.status, PluginStatus::Untrusted);
    }
}
