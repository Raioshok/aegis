//! CLI subcommands for the behavioural engine (rootkit, memory, sandbox).
//!
//! These run in-process (they read `/proc` and `/sys` directly), so they work
//! whether or not the daemon is running.

use crate::render::{self, BOLD, DIM};
use aegis_core::{Detection, Severity};
use std::path::PathBuf;

fn print_detections(title: &str, detections: &[Detection]) -> i32 {
    println!("{BOLD}{title}{RESET}", RESET = render::RESET);
    if detections.is_empty() {
        println!(
            "  {}",
            render::paint(render::GREEN, "✓ nothing suspicious found")
        );
        return 0;
    }
    let mut worst = Severity::Clean;
    for d in detections {
        worst = worst.max(d.severity);
        println!(
            "  {}  {}",
            render::sev_paint(d.severity, &format!("[{}]", d.severity.label())),
            d.threat
        );
        println!(
            "        {DIM}{}{RESET}",
            d.detail,
            DIM = DIM,
            RESET = render::RESET
        );
    }
    if worst >= Severity::High {
        1
    } else {
        0
    }
}

/// `aegis rootkit` — cross-view rootkit/integrity scan.
pub fn rootkit(json: bool) -> i32 {
    let findings = aegis_behavior::rootkit::scan();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&findings).unwrap_or_default()
        );
        return if findings.iter().any(|d| d.severity >= Severity::High) {
            1
        } else {
            0
        };
    }
    print_detections("Rootkit / integrity scan", &findings)
}

/// `aegis memory [pid]` — scan process memory maps for injection patterns.
pub fn memory(pid: Option<u32>, json: bool) -> i32 {
    let findings = match pid {
        Some(p) => aegis_behavior::memory::scan_pid(p),
        None => aegis_behavior::memory::scan_all(),
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&findings).unwrap_or_default()
        );
        return if findings.iter().any(|d| d.severity >= Severity::High) {
            1
        } else {
            0
        };
    }
    let title = match pid {
        Some(p) => format!("Memory scan of PID {p}"),
        None => "Memory scan (all accessible processes)".to_string(),
    };
    print_detections(&title, &findings)
}

/// `aegis sandbox [--allow-read P]... [--allow-write P]... -- <cmd> [args...]`
///
/// Restricts *this* process with Landlock + rlimits, then execs the command so
/// it inherits the confinement.
pub fn sandbox(
    read: Vec<PathBuf>,
    write: Vec<PathBuf>,
    cpu_seconds: Option<u64>,
    command: Vec<String>,
) -> i32 {
    use aegis_behavior::sandbox::{restrict_current, SandboxPolicy};
    use std::os::unix::process::CommandExt;

    if command.is_empty() {
        eprintln!("sandbox: no command given (use `-- <cmd>`)");
        return 2;
    }
    if !aegis_behavior::sandbox::landlock_supported() {
        eprintln!("sandbox: this kernel does not support Landlock");
        return 2;
    }

    let mut policy = SandboxPolicy::default();
    if !read.is_empty() {
        policy.read_exec.extend(read);
    }
    if !write.is_empty() {
        policy.read_write.extend(write);
    }
    if let Some(cpu) = cpu_seconds {
        policy.cpu_seconds = Some(cpu);
    }

    match restrict_current(&policy) {
        Ok(outcome) => {
            eprintln!(
                "{} sandbox active (landlock: {:?}); executing: {}",
                render::paint(render::GREEN, "✓"),
                outcome.landlock,
                command.join(" ")
            );
        }
        Err(e) => {
            eprintln!("sandbox: failed to apply confinement: {e}");
            return 2;
        }
    }

    // exec replaces this (now-confined) process image with the target.
    let err = std::process::Command::new(&command[0])
        .args(&command[1..])
        .exec();
    eprintln!("sandbox: exec failed: {err}");
    126
}
