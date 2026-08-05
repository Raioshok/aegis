//! # aegis-optimize
//!
//! A Kaspersky-style system tune-up, but Arch-native and safe:
//!
//! * [`system`] — reclaimable disk space & health (pacman cache, orphans,
//!   journal, `~/.cache`, `/tmp`, failed units).
//! * [`network`] — TCP/network sysctl tuning analysis (BBR, qdisc, buffers, TFO,
//!   MTU probing), DNS latency, and connection activity.
//! * [`actions`] — applying fixes; **dry-run by default**, privileged steps shell
//!   out to the canonical Arch tools.
//!
//! Scanning is read-only and safe to run anywhere; nothing modifies the system
//! unless an [`actions`] function is called with `apply = true`.

#![forbid(unsafe_code)]

pub mod actions;
pub mod model;
pub mod network;
pub mod system;

pub use model::{human_bytes, Finding, Impact, OptimizeReport};

/// Run both the system and network optimization scans and merge the results.
pub fn full_scan() -> OptimizeReport {
    let mut report = system::scan();
    for f in network::scan().findings {
        report.push(f);
    }
    report
}
