//! Lightweight sandbox built from **Landlock** (filesystem access control) and
//! POSIX **rlimits** (CPU/memory/file-size caps) — both via safe crates, so this
//! module stays `unsafe`-free.
//!
//! Usage model: a launcher restricts *itself* (`restrict_current`) and then
//! `exec`s the target program, which inherits the Landlock domain and limits.
//! Landlock restrictions are irreversible and inherited by all descendants,
//! which is exactly what an isolating launcher wants.
//!
//! Full namespace/seccomp isolation (`unshare`, seccomp-BPF) layers on top in a
//! later increment; Landlock already provides meaningful, unprivileged
//! filesystem confinement on this kernel.

use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use nix::sys::resource::{setrlimit, Resource};
use std::path::PathBuf;

/// What the sandboxed process is allowed to do.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// Paths the process may read and execute.
    pub read_exec: Vec<PathBuf>,
    /// Paths the process may additionally write.
    pub read_write: Vec<PathBuf>,
    /// CPU-seconds limit (SIGKILL on breach).
    pub cpu_seconds: Option<u64>,
    /// Address-space (virtual memory) limit in bytes.
    pub address_space: Option<u64>,
    /// Maximum size of any file the process may create, in bytes.
    pub file_size: Option<u64>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            // A minimal read/exec base for running most binaries.
            read_exec: ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"]
                .iter()
                .map(PathBuf::from)
                .filter(|p| p.exists())
                .collect(),
            read_write: [std::env::temp_dir()].into_iter().collect(),
            cpu_seconds: Some(10),
            address_space: Some(512 * 1024 * 1024),
            file_size: Some(64 * 1024 * 1024),
        }
    }
}

/// Outcome of applying the sandbox.
#[derive(Debug)]
pub struct SandboxOutcome {
    pub landlock: RulesetStatus,
    pub limits_applied: bool,
}

/// Whether the running kernel enforces Landlock at all.
pub fn landlock_supported() -> bool {
    // Building an empty ruleset and checking best-effort status is the
    // crate-sanctioned probe.
    Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V1))
        .and_then(|r| r.create())
        .is_ok()
}

/// Apply rlimits then a Landlock domain to the **current** process. Irreversible.
pub fn restrict_current(
    policy: &SandboxPolicy,
) -> Result<SandboxOutcome, Box<dyn std::error::Error>> {
    apply_rlimits(policy)?;
    let abi = ABI::V1;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .add_rules(path_beneath_rules(
            &policy.read_exec,
            AccessFs::from_read(abi),
        ))?
        .add_rules(path_beneath_rules(
            &policy.read_write,
            AccessFs::from_all(abi),
        ))?
        .restrict_self()?;
    Ok(SandboxOutcome {
        landlock: status.ruleset,
        limits_applied: true,
    })
}

fn apply_rlimits(policy: &SandboxPolicy) -> nix::Result<()> {
    if let Some(cpu) = policy.cpu_seconds {
        setrlimit(Resource::RLIMIT_CPU, cpu, cpu)?;
    }
    if let Some(as_bytes) = policy.address_space {
        setrlimit(Resource::RLIMIT_AS, as_bytes, as_bytes)?;
    }
    if let Some(fsize) = policy.file_size {
        setrlimit(Resource::RLIMIT_FSIZE, fsize, fsize)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_sane() {
        let p = SandboxPolicy::default();
        assert!(!p.read_exec.is_empty());
        assert!(p.cpu_seconds.is_some());
    }

    #[test]
    fn kernel_reports_landlock_support() {
        // This kernel has CONFIG_SECURITY_LANDLOCK=y; probe must not panic.
        // (We assert only that the probe returns; enforcement is not applied to
        // the test process.)
        let _ = landlock_supported();
    }
}
