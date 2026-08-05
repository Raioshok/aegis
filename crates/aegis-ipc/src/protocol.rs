//! Wire protocol shared by the daemon and its clients.
//!
//! Requests and responses are JSON documents, each preceded on the wire by a
//! 4-byte big-endian length prefix (see [`crate::codec`]). Keeping the protocol
//! as plain serde types means the future Tauri UI, the CLI, and tests all speak
//! the exact same language.

use aegis_core::{ScanStats, Severity};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Protocol version; bumped on breaking changes so a client can refuse to talk
/// to an incompatible daemon.
pub const PROTOCOL_VERSION: u32 = 1;

/// A request from a client to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness probe.
    Ping,
    /// Daemon status snapshot.
    Status,
    /// Run a scan of `path` synchronously and return the result.
    Scan { path: PathBuf, kind: String },
    /// Recent scan history.
    History { limit: i64 },
    /// Current quarantine contents.
    QuarantineList,
    /// Real-time protection status.
    RealtimeStatus,
    /// Re-read configuration and whitelist from disk.
    ReloadConfig,
    /// Ask the daemon to shut down gracefully.
    Shutdown,
}

/// A response from the daemon to a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Pong { version: u32 },
    Status(DaemonStatus),
    ScanResult(ScanSummary),
    History(Vec<HistoryEntry>),
    Quarantine(Vec<QuarantineEntry>),
    Realtime(RealtimeStatus),
    Ok { message: String },
    Error { message: String },
}

/// A compact snapshot of daemon health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub version: String,
    pub protocol: u32,
    pub pid: u32,
    pub uptime_secs: u64,
    pub engines: Vec<EngineInfo>,
    pub realtime: RealtimeStatus,
    pub scans_run: u64,
    pub threats_found: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineInfo {
    pub name: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeStatus {
    pub enabled: bool,
    pub backend: String,
    pub watched_paths: Vec<PathBuf>,
    pub events_seen: u64,
    pub threats_blocked: u64,
    /// Populated when the monitor could not start (e.g. missing privileges).
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub target: PathBuf,
    pub stats: ScanStats,
    pub threats: Vec<ThreatBrief>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatBrief {
    pub path: PathBuf,
    pub sha256: String,
    pub severity: Severity,
    pub names: String,
    pub engines: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub finished: i64,
    pub target: String,
    pub files_scanned: i64,
    pub threats: i64,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub sha256: String,
    pub original_path: String,
    pub threat: String,
    pub quarantined_at: i64,
    pub size: i64,
}
