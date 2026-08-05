//! Core domain types shared by every engine, the daemon and the UI.
//!
//! These types are intentionally free of I/O and framework concerns (Domain
//! Driven Design: this is the *domain* layer). Engines produce [`Detection`]s,
//! the orchestrator aggregates them into a [`FileVerdict`].

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Severity of a detection, ordered from benign to critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// No threat.
    Clean = 0,
    /// Low-confidence heuristic suspicion.
    Low = 1,
    /// Strong heuristic / pattern match.
    Medium = 2,
    /// Signature or multi-engine agreement.
    High = 3,
    /// Known malware / high-consensus threat.
    Critical = 4,
}

impl Severity {
    /// Short human label.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Clean => "Clean",
            Severity::Low => "Suspicious (low)",
            Severity::Medium => "Suspicious",
            Severity::High => "Malware",
            Severity::Critical => "Critical",
        }
    }

    /// ANSI colour used by the CLI renderer.
    pub fn ansi(self) -> &'static str {
        match self {
            Severity::Clean => "\x1b[32m",    // green
            Severity::Low => "\x1b[33m",      // yellow
            Severity::Medium => "\x1b[33m",   // yellow
            Severity::High => "\x1b[31m",     // red
            Severity::Critical => "\x1b[91m", // bright red
        }
    }
}

/// Broad classification of a threat, used for reporting and telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatClass {
    Signature,
    Heuristic,
    Behavioral,
    PackedBinary,
    ReverseShell,
    CryptoMiner,
    Persistence,
    Rootkit,
    Ransomware,
    Unknown,
}

/// A single verdict from one engine about one file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Engine that produced this detection (e.g. `"YARA"`).
    pub engine: String,
    /// Threat name / signature / rule identifier.
    pub threat: String,
    pub severity: Severity,
    pub class: ThreatClass,
    /// Human-readable explanation.
    pub detail: String,
}

impl Detection {
    pub fn new(
        engine: impl Into<String>,
        threat: impl Into<String>,
        severity: Severity,
        class: ThreatClass,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            engine: engine.into(),
            threat: threat.into(),
            severity,
            class,
            detail: detail.into(),
        }
    }
}

/// Aggregated result for a single scanned file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileVerdict {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub detections: Vec<Detection>,
    /// True when a whitelist rule cleared this file.
    pub whitelisted: bool,
    /// Non-fatal error encountered while scanning (unreadable, too large, …).
    pub error: Option<String>,
}

impl FileVerdict {
    pub fn clean(path: PathBuf) -> Self {
        Self {
            path,
            sha256: String::new(),
            size: 0,
            detections: Vec::new(),
            whitelisted: false,
            error: None,
        }
    }

    /// Whether this file should be treated as a threat.
    pub fn is_threat(&self) -> bool {
        !self.whitelisted && !self.detections.is_empty()
    }

    /// The highest severity among all detections (or `Clean`).
    pub fn severity(&self) -> Severity {
        if self.whitelisted {
            return Severity::Clean;
        }
        self.detections
            .iter()
            .map(|d| d.severity)
            .max()
            .unwrap_or(Severity::Clean)
    }

    /// The most severe detection, if any.
    pub fn top_detection(&self) -> Option<&Detection> {
        self.detections.iter().max_by_key(|d| d.severity)
    }

    /// Comma-separated unique threat names.
    pub fn threat_names(&self) -> String {
        let mut names: Vec<&str> = self.detections.iter().map(|d| d.threat.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        names.join(", ")
    }
}

/// Statistics accumulated over a scan run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    pub total_files: u64,
    pub scanned: u64,
    pub skipped: u64,
    pub threats: u64,
    pub errors: u64,
    pub bytes_scanned: u64,
    pub duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Clean < Severity::Low);
    }

    #[test]
    fn verdict_severity_is_max() {
        let mut v = FileVerdict::clean(PathBuf::from("/tmp/x"));
        v.detections.push(Detection::new(
            "YARA",
            "A",
            Severity::Low,
            ThreatClass::Heuristic,
            "",
        ));
        v.detections.push(Detection::new(
            "ClamAV",
            "B",
            Severity::High,
            ThreatClass::Signature,
            "",
        ));
        assert_eq!(v.severity(), Severity::High);
        assert!(v.is_threat());
    }

    #[test]
    fn whitelisted_overrides_detections() {
        let mut v = FileVerdict::clean(PathBuf::from("/tmp/x"));
        v.detections.push(Detection::new(
            "YARA",
            "A",
            Severity::Critical,
            ThreatClass::Signature,
            "",
        ));
        v.whitelisted = true;
        assert!(!v.is_threat());
        assert_eq!(v.severity(), Severity::Clean);
    }
}
