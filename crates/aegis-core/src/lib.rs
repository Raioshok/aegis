//! # aegis-core
//!
//! The domain layer of the Aegis antivirus platform: pure data types, errors,
//! configuration, the whitelist, and the event bus. This crate has **no I/O
//! side effects beyond config/whitelist persistence** and no dependency on any
//! engine, storage backend or UI framework, keeping the domain testable and
//! stable (Clean Architecture / DDD).

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod config;
pub mod error;
pub mod event;
pub mod model;
pub mod paths;
pub mod whitelist;

pub use config::{Config, EngineToggles, RealtimeConfig, ScheduleConfig};
pub use error::{AegisError, Result};
pub use event::{Event, EventBus};
pub use model::{Detection, FileVerdict, ScanStats, Severity, ThreatClass};
pub use whitelist::{Whitelist, WhitelistRule};

/// Current epoch seconds, for timestamping rules and records.
pub fn now_epoch() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
