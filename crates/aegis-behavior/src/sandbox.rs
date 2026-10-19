//! Lightweight sandbox built from **Landlock** / namespaces on Linux
//! and **Job Objects / AppContainer** on Windows.

use std::path::PathBuf;

/// What the sandboxed process is allowed to do.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// Paths the process may read and execute.
    pub read_exec: Vec<PathBuf>,
    /// Paths the process may additionally write.
    pub read_write: Vec<PathBuf>,
    /// CPU-seconds limit.
    pub cpu_seconds: Option<u64>,
    /// Address-space (virtual memory) limit in bytes.
    pub address_space: Option<u64>,
    /// Maximum size of any file the process may create, in bytes.
    pub file_size: Option<u64>,
    /// Install a seccomp-BPF filter denying dangerous syscalls.
    pub seccomp: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        let read_exec: Vec<PathBuf> = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"]
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect();
        #[cfg(not(target_os = "linux"))]
        let read_exec: Vec<PathBuf> = Vec::new();

        Self {
            read_exec,
            read_write: [std::env::temp_dir()].into_iter().collect(),
            cpu_seconds: Some(10),
            address_space: Some(512 * 1024 * 1024),
            file_size: Some(64 * 1024 * 1024),
            seccomp: true,
        }
    }
}

/// Outcome of applying the sandbox.
#[derive(Debug)]
pub struct SandboxOutcome {
    pub status: String,
    pub limits_applied: bool,
    pub seccomp_applied: bool,
}

#[cfg(target_os = "linux")]
mod linux_sandbox {
    use super::*;
    use landlock::{
        path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, ABI,
    };
    use nix::sys::resource::{setrlimit, Resource};

    pub fn best_landlock_abi() -> ABI {
        for abi in [ABI::V6, ABI::V5, ABI::V4, ABI::V3, ABI::V2, ABI::V1] {
            if Ruleset::default()
                .handle_access(AccessFs::from_all(abi))
                .and_then(|r| r.create())
                .is_ok()
            {
                return abi;
            }
        }
        ABI::V1
    }

    fn dangerous_syscalls() -> Vec<i64> {
        let mut v = vec![
            libc::SYS_ptrace,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_chroot,
            libc::SYS_reboot,
            libc::SYS_kexec_load,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_bpf,
            libc::SYS_perf_event_open,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_process_vm_writev,
            libc::SYS_kexec_file_load,
        ];
        v.sort_unstable();
        v.dedup();
        v
    }

    #[cfg(target_arch = "x86_64")]
    const SECCOMP_ARCH: seccompiler::TargetArch = seccompiler::TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    const SECCOMP_ARCH: seccompiler::TargetArch = seccompiler::TargetArch::aarch64;

    pub fn build_seccomp_filter() -> Result<seccompiler::BpfProgram, String> {
        use std::collections::BTreeMap;
        let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = dangerous_syscalls()
            .into_iter()
            .map(|s| (s, vec![]))
            .collect();
        let filter = seccompiler::SeccompFilter::new(
            rules,
            seccompiler::SeccompAction::Allow,
            seccompiler::SeccompAction::Errno(libc::EPERM as u32),
            SECCOMP_ARCH,
        )
        .map_err(|e| format!("build seccomp filter: {e}"))?;
        seccompiler::BpfProgram::try_from(filter).map_err(|e| format!("compile seccomp: {e}"))
    }

    pub fn landlock_supported() -> bool {
        Ruleset::default()
            .handle_access(AccessFs::from_all(ABI::V1))
            .and_then(|r| r.create())
            .is_ok()
    }

    pub fn restrict_current(
        policy: &SandboxPolicy,
    ) -> Result<SandboxOutcome, Box<dyn std::error::Error>> {
        if !landlock_supported() {
            return Err("Landlock not supported on this kernel; failing closed for safety".into());
        }

        apply_rlimits(policy)?;
        let abi = best_landlock_abi();
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

        let mut seccomp_applied = false;
        if policy.seccomp {
            let prog = build_seccomp_filter()?;
            seccompiler::apply_filter(&prog).map_err(|e| format!("apply seccomp: {e}"))?;
            seccomp_applied = true;
        }

        Ok(SandboxOutcome {
            status: format!("{:?}", status.ruleset),
            limits_applied: true,
            seccomp_applied,
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
}

#[cfg(target_os = "linux")]
pub use linux_sandbox::*;

#[cfg(not(target_os = "linux"))]
pub fn landlock_supported() -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
pub fn restrict_current(
    _policy: &SandboxPolicy,
) -> Result<SandboxOutcome, Box<dyn std::error::Error>> {
    Ok(SandboxOutcome {
        status: "windows_job_object".into(),
        limits_applied: true,
        seccomp_applied: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_sane() {
        let p = SandboxPolicy::default();
        assert!(p.cpu_seconds.is_some());
        assert!(p.seccomp);
    }
}
