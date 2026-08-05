//! Applying rulesets to the kernel via the `nft` binary (privileged).
//!
//! Kept separate from the pure rule model so everything except the final
//! `nft -f -` invocation is unit-testable without root.

use crate::model::{Ruleset, TABLE};
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Debug, thiserror::Error)]
pub enum FirewallError {
    #[error("`nft` binary not found on PATH")]
    NftMissing,
    #[error("nft failed: {0}")]
    Nft(String),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

fn nft_path() -> Option<&'static str> {
    ["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
}

/// Apply a ruleset atomically via `nft -f -`. Requires CAP_NET_ADMIN (root).
pub fn apply(ruleset: &Ruleset) -> Result<(), FirewallError> {
    run_script(&ruleset.to_nft_script())
}

/// Remove the entire Aegis table.
pub fn flush() -> Result<(), FirewallError> {
    // `delete table` errors if absent, so create-then-delete for idempotency.
    run_script(&format!(
        "add table inet {TABLE}\ndelete table inet {TABLE}\n"
    ))
}

/// Dump the current Aegis table (`nft list table inet aegis`).
pub fn list() -> Result<String, FirewallError> {
    let nft = nft_path().ok_or(FirewallError::NftMissing)?;
    let out = Command::new(nft)
        .args(["list", "table", "inet", TABLE])
        .output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(FirewallError::Nft(
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }
}

fn run_script(script: &str) -> Result<(), FirewallError> {
    let nft = nft_path().ok_or(FirewallError::NftMissing)?;
    let mut child = Command::new(nft)
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| FirewallError::Nft("no stdin".into()))?
        .write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(FirewallError::Nft(
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }
}
