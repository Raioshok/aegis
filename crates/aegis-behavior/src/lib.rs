//! # aegis-behavior
//!
//! The behavioural engine: signature-less, activity-based defence that
//! complements the file-scanning engines.
//!
//! * [`ransomware`] — sliding-window detection of mass-encryption / rename-storm
//!   activity, with optional process termination.
//! * [`rootkit`] — cross-view `/proc`⇄`/sys` integrity checks (hidden processes,
//!   hidden modules, `ld.so.preload`, kernel taint).
//! * [`memory`] — `/proc/<pid>/maps` analysis for injected / W^X / deleted-backing
//!   executable code.
//! * [`sandbox`] — Landlock + rlimit confinement for running suspicious files.
//! * [`response`] — active-response primitives (process kill).
//!
//! eBPF-based kernel syscall tracing is a planned deepening of this engine; the
//! detections here are delivered through `/proc`, `/sys` and the daemon's
//! file-event stream, which cover the same threat classes without requiring a
//! loaded BPF program.

#![forbid(unsafe_code)]

pub mod dag;
pub mod memory;
pub mod ransomware;
pub mod response;
pub mod rootkit;
pub mod rules;
pub mod sandbox;

pub use dag::{
    calculate_entropy, AgentType, LineageAlert, ProcessDagSnapshot, ProcessEdge, ProcessNode,
    ProcessTreeDag, ProcessTreeNodeDto,
};
pub use ransomware::{AlertReason, RansomwareAlert, RansomwareConfig, RansomwareGuard};
pub use rules::{BehaviorRule, BehaviorRuleEngine, MatchCondition};
