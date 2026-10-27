//! Plugin execution — run a trusted plugin out-of-process over a JSON protocol.
//!
//! The host writes a [`PluginRequest`] as JSON to the plugin's stdin and reads a
//! [`PluginResponse`] as JSON from its stdout. Running a plugin in a separate
//! process (rather than loading a shared library) means a plugin never shares
//! the host's address space and can be further confined with the Landlock
//! sandbox before exec. Execution is refused unless the plugin is **trusted**
//! (valid signature) and **declares the permission** the request needs.

use crate::manifest::Permission;
use crate::registry::DiscoveredPlugin;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A request handed to a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRequest {
    /// What the host wants (e.g. `"scan"`).
    pub action: String,
    /// Optional target path for scan-type actions.
    #[serde(default)]
    pub target: Option<String>,
    /// The permission this action requires.
    pub required_permission: Permission,
}

/// One finding returned by a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginDetection {
    pub threat: String,
    /// 0–4, matching the host severity scale.
    pub severity: u8,
    #[serde(default)]
    pub detail: String,
}

/// A plugin's response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginResponse {
    #[serde(default)]
    pub detections: Vec<PluginDetection>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("plugin is not trusted (signature invalid or unknown key)")]
    Untrusted,
    #[error("plugin does not declare the required permission {0:?}")]
    PermissionDenied(Permission),
    #[error("plugin has no manifest")]
    NoManifest,
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("plugin produced invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("plugin timed out")]
    Timeout,
}

/// Execute a plugin, enforcing trust and the requested permission.
pub fn run(
    plugin: &DiscoveredPlugin,
    request: &PluginRequest,
    timeout: Duration,
) -> Result<PluginResponse, RunError> {
    if !plugin.is_enabled() {
        return Err(RunError::Untrusted);
    }
    let manifest = plugin.manifest.as_ref().ok_or(RunError::NoManifest)?;
    if !manifest.grants(request.required_permission) {
        return Err(RunError::PermissionDenied(request.required_permission));
    }

    let entry = plugin.dir.join(&manifest.entrypoint);
    let mut cmd = if cfg!(windows) && manifest.entrypoint.ends_with(".sh") {
        let mut c = Command::new("sh");
        c.arg(&entry);
        c
    } else if cfg!(windows) && (manifest.entrypoint.ends_with(".bat") || manifest.entrypoint.ends_with(".cmd")) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(&entry);
        c
    } else {
        Command::new(&entry)
    };
    cmd.current_dir(&plugin.dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(unix)]
    cmd.env_clear().env("PATH", "/usr/bin:/bin");

    let mut child = cmd.spawn()?;

    // Send the request.
    let payload = serde_json::to_vec(request)?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&payload)?;
        // dropping stdin closes it, signalling EOF to the plugin
    }

    // Defense-in-depth timeout: kill the plugin if it overruns.
    let pid = child.id();
    let finished = Arc::new(AtomicBool::new(false));
    {
        let finished = finished.clone();
        std::thread::spawn(move || {
            std::thread::sleep(timeout);
            if !finished.load(Ordering::SeqCst) {
                let _ = aegis_platform::default_process_control().kill(pid);
            }
        });
    }

    let output = child.wait_with_output()?;
    finished.store(true, Ordering::SeqCst);

    if output.stdout.is_empty() && !output.status.success() {
        return Err(RunError::Timeout);
    }
    let resp: PluginResponse = serde_json::from_slice(&output.stdout)?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{PluginManifest, API_VERSION};
    use crate::registry::evaluate;
    use crate::signature::KeyPair;
    use crate::TrustStore;

    fn make_plugin(dir: &std::path::Path, script: &str, perms: Vec<Permission>) -> KeyPair {
        std::fs::create_dir_all(dir).unwrap();
        let entry = dir.join("run.sh");
        std::fs::write(&entry, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let manifest = PluginManifest {
            name: "test-plugin".into(),
            version: "1.0".into(),
            description: String::new(),
            author: "t".into(),
            entrypoint: "run.sh".into(),
            api_version: API_VERSION,
            permissions: perms,
            targets: [("run.sh".to_string(), crate::manifest::TargetFile::of(&entry).unwrap())].into(),
        };
        let kp = KeyPair::generate();
        let sig = kp.sign(&manifest);
        std::fs::write(
            dir.join("plugin.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("plugin.sig"), sig).unwrap();
        kp
    }

    #[test]
    fn trusted_plugin_runs_and_returns_detections() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("p");
        // A plugin that ignores stdin and prints a detection.
        let script = "#!/bin/sh\ncat >/dev/null\n\
            printf '{\"detections\":[{\"threat\":\"Plugin.Test\",\"severity\":3,\"detail\":\"hi\"}]}'\n";
        let kp = make_plugin(&dir, script, vec![Permission::Scan]);

        let trust = TrustStore::with_keys([kp.public_hex()]);
        let plugin = evaluate(&dir, &trust);
        assert!(plugin.is_enabled());

        let req = PluginRequest {
            action: "scan".into(),
            target: Some("/tmp".into()),
            required_permission: Permission::Scan,
        };
        let resp = run(&plugin, &req, Duration::from_secs(5)).unwrap();
        assert_eq!(resp.detections.len(), 1);
        assert_eq!(resp.detections[0].threat, "Plugin.Test");
    }

    #[test]
    fn untrusted_plugin_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("p");
        let _signer = make_plugin(&dir, "#!/bin/sh\necho '{}'\n", vec![Permission::Scan]);
        // Trust store does not contain the signer's key.
        let trust = TrustStore::with_keys([KeyPair::generate().public_hex()]);
        let plugin = evaluate(&dir, &trust);
        let req = PluginRequest {
            action: "scan".into(),
            target: None,
            required_permission: Permission::Scan,
        };
        assert!(matches!(
            run(&plugin, &req, Duration::from_secs(5)),
            Err(RunError::Untrusted)
        ));
    }

    #[test]
    fn missing_permission_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("p");
        // Plugin only declares Scan, but the request needs Network.
        let kp = make_plugin(&dir, "#!/bin/sh\necho '{}'\n", vec![Permission::Scan]);
        let trust = TrustStore::with_keys([kp.public_hex()]);
        let plugin = evaluate(&dir, &trust);
        let req = PluginRequest {
            action: "lookup".into(),
            target: None,
            required_permission: Permission::Network,
        };
        assert!(matches!(
            run(&plugin, &req, Duration::from_secs(5)),
            Err(RunError::PermissionDenied(Permission::Network))
        ));
    }
}
