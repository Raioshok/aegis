//! Active response primitives (used by the daemon to stop live threats).

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

/// Immediately terminate a process (SIGKILL). Returns `Err` if the PID is gone
/// or the caller lacks permission.
pub fn kill_pid(pid: u32) -> Result<(), String> {
    kill(Pid::from_raw(pid as i32), Signal::SIGKILL).map_err(|e| e.to_string())
}

/// Ask a process to terminate (SIGTERM).
pub fn terminate_pid(pid: u32) -> Result<(), String> {
    kill(Pid::from_raw(pid as i32), Signal::SIGTERM).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn killing_nonexistent_pid_errors() {
        // PID 0 targets our own process group with kill(); use a very high PID
        // that will not exist to get a clean ESRCH instead.
        assert!(kill_pid(4_000_000).is_err());
    }
}
