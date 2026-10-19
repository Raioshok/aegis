//! Active response primitives (used by the daemon to stop live threats).

/// Immediately terminate a process (SIGKILL / TerminateProcess). Returns `Err` if the PID is gone
/// or the caller lacks permission.
pub fn kill_pid(pid: u32) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        kill(Pid::from_raw(pid as i32), Signal::SIGKILL).map_err(|e| e.to_string())
    }
    #[cfg(windows)]
    {
        aegis_platform::default_process_control()
            .kill(pid)
            .map_err(|e| e.to_string())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = pid;
        Err("unsupported platform".into())
    }
}

/// Ask a process to terminate (SIGTERM / TerminateProcess).
pub fn terminate_pid(pid: u32) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        kill(Pid::from_raw(pid as i32), Signal::SIGTERM).map_err(|e| e.to_string())
    }
    #[cfg(windows)]
    {
        aegis_platform::default_process_control()
            .kill(pid)
            .map_err(|e| e.to_string())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = pid;
        Err("unsupported platform".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn killing_nonexistent_pid_errors() {
        assert!(kill_pid(4_000_000).is_err());
    }
}
