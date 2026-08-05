//! The [`Engine`] trait — the Strategy pattern for detection backends.
//!
//! Every detection technology (hash DB, YARA, heuristics, and — in later
//! milestones — behavioural/eBPF) implements this single interface, so the
//! orchestrator can run them uniformly and users can toggle them independently.

use aegis_core::Detection;

/// Pre-read context handed to engines so a file is read from disk only once.
#[derive(Debug)]
pub struct FileContext<'a> {
    pub path: &'a std::path::Path,
    /// File bytes (possibly truncated to a scan cap).
    pub data: &'a [u8],
    pub size: u64,
    /// Precomputed SHA-256 (lowercase hex).
    pub sha256: &'a str,
}

/// A detection strategy. Must be `Send + Sync` to run across the rayon pool.
pub trait Engine: Send + Sync {
    /// Stable engine name, e.g. `"YARA"`.
    fn name(&self) -> &str;

    /// Human-readable readiness string for the dashboard/CLI.
    fn status(&self) -> String;

    /// Inspect one file and return zero or more detections.
    fn scan(&self, ctx: &FileContext<'_>) -> Vec<Detection>;
}
