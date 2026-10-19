//! # aegis-daemon
//!
//! The Aegis background service. It provides:
//!
//! * **Real-time protection** — on-access scanning driven by `inotify`
//!   (unprivileged) or `fanotify` (privileged, `--features fanotify`).
//! * **IPC server** — a framed-JSON control socket ([`aegis_ipc`]) so the CLI
//!   and UI can query status, trigger scans, and manage the daemon.
//! * **Scheduler** — periodic scans on a configurable interval.
//!
//! Everything runs on a Tokio runtime; blocking scan work is offloaded via
//! `spawn_blocking` so the reactor stays responsive.

#![forbid(unsafe_code)]

mod daemon;
pub mod gateway;
pub mod realtime;
mod scheduler;
mod server;
mod state;

pub use daemon::run;
pub use gateway::{GatewayServer, GatewayState, TelemetryReport, TrainingStats};
pub use state::DaemonState;

/// Initialise tracing for the daemon (idempotent-ish; call once at startup).
pub fn init_logging() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "aegis=info".to_string());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
