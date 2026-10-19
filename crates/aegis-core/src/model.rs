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
    /// Reconstruct from the stored integer value (saturating).
    pub fn from_u8(v: u8) -> Severity {
        match v {
            0 => Severity::Clean,
            1 => Severity::Low,
            2 => Severity::Medium,
            3 => Severity::High,
            _ => Severity::Critical,
        }
    }

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

/// Standardized high-level verdict level (replacing binary threat / max severity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerdictLevel {
    Clean = 0,
    Suspicious = 1,
    Malware = 2,
}

impl VerdictLevel {
    pub fn label(self) -> &'static str {
        match self {
            VerdictLevel::Clean => "Clean",
            VerdictLevel::Suspicious => "PUA/Suspicious",
            VerdictLevel::Malware => "Malware",
        }
    }

    pub fn ansi(self) -> &'static str {
        match self {
            VerdictLevel::Clean => "\x1b[32m",
            VerdictLevel::Suspicious => "\x1b[33m",
            VerdictLevel::Malware => "\x1b[31m",
        }
    }
}

/// Action to take on an access event (fanotify or minifilter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GateVerdict {
    Allow,
    Deny,
    Audit,
}

/// Memory mapping region for memory inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapRegion {
    pub start: usize,
    pub end: usize,
    pub permissions: String,
    pub is_private: bool,
    pub is_executable: bool,
    pub is_writable: bool,
    pub pathname: Option<String>,
}

/// Connection record for network inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    pub protocol: String,
    pub local: std::net::IpAddr,
    pub local_port: u16,
    pub remote: std::net::IpAddr,
    pub remote_port: u16,
    pub state: String,
    pub uid: u32,
    pub pid: Option<u32>,
    pub inode: u64,
}

impl Connection {
    pub fn is_listening(&self) -> bool {
        self.state == "LISTEN"
    }
    pub fn is_established(&self) -> bool {
        self.state == "ESTABLISHED"
    }
}

/// Real-time file access event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessEventType {
    Open,
    OpenExec,
    CloseWrite,
    Modify,
    Rename,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEvent {
    pub path: PathBuf,
    pub pid: u32,
    pub event_type: AccessEventType,
    pub file_id: Option<u64>,
}

/// Firewall block sets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockSets {
    pub ipv4: Vec<std::net::Ipv4Addr>,
    pub ipv6: Vec<std::net::Ipv6Addr>,
    pub app_paths: Vec<PathBuf>,
}

/// Sandbox constraints.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub allow_network: bool,
    pub read_paths: Vec<PathBuf>,
    pub write_paths: Vec<PathBuf>,
    pub memory_limit_bytes: Option<u64>,
    pub cpu_limit_pct: Option<u32>,
}

/// Process creation/termination event for behaviour engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessEventKind {
    Exec,
    Fork,
    Exit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub exe: PathBuf,
    pub cmdline: Vec<String>,
    pub kind: ProcessEventKind,
    pub timestamp_ms: u64,
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
    /// Detection weight (importance of engine/rule, 0.0 - 1.0).
    #[serde(default = "default_one")]
    pub weight: f32,
    /// Detection confidence (0.0 - 1.0).
    #[serde(default = "default_one")]
    pub confidence: f32,
}

fn default_one() -> f32 {
    1.0
}

impl Detection {
    pub fn new(
        engine: impl Into<String>,
        threat: impl Into<String>,
        severity: Severity,
        class: ThreatClass,
        detail: impl Into<String>,
    ) -> Self {
        let (weight, confidence) = match severity {
            Severity::Critical => (1.0, 1.0),
            Severity::High => (0.85, 0.85),
            Severity::Medium => (0.65, 0.65),
            Severity::Low => (0.40, 0.40),
            Severity::Clean => (0.0, 0.0),
        };
        Self {
            engine: engine.into(),
            threat: threat.into(),
            severity,
            class,
            detail: detail.into(),
            weight,
            confidence,
        }
    }

    pub fn with_scores(
        engine: impl Into<String>,
        threat: impl Into<String>,
        severity: Severity,
        class: ThreatClass,
        detail: impl Into<String>,
        weight: f32,
        confidence: f32,
    ) -> Self {
        Self {
            engine: engine.into(),
            threat: threat.into(),
            severity,
            class,
            detail: detail.into(),
            weight,
            confidence,
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

    /// Whether this file should be treated as a threat (Malware or Suspicious).
    pub fn is_threat(&self) -> bool {
        !self.whitelisted && !self.detections.is_empty()
    }

    /// Combined confidence score (0.0 to 1.0) taking multi-engine consensus into account.
    pub fn confidence(&self) -> f32 {
        if self.whitelisted || self.detections.is_empty() {
            return 0.0;
        }
        let mut unreached = 1.0f32;
        let mut distinct_engines = std::collections::HashSet::new();
        for d in &self.detections {
            let score = (d.weight * d.confidence).clamp(0.0, 0.95);
            unreached *= 1.0 - score;
            distinct_engines.insert(d.engine.as_str());
        }
        let mut combined = 1.0 - unreached;
        // Agreement bonus: raise score when distinct engines agree
        if distinct_engines.len() > 1 {
            combined += 0.15 * (distinct_engines.len() - 1) as f32;
        }
        combined.clamp(0.0, 1.0)
    }

    /// The verdict level: Clean, PUA/Suspicious, or Malware.
    pub fn verdict_level(&self) -> VerdictLevel {
        if self.whitelisted || self.detections.is_empty() {
            return VerdictLevel::Clean;
        }
        let conf = self.confidence();
        if conf >= 0.70 {
            VerdictLevel::Malware
        } else if conf >= 0.30 {
            VerdictLevel::Suspicious
        } else {
            VerdictLevel::Clean
        }
    }

    /// Whether this verdict warrants automatic quarantine (Malware only).
    pub fn should_quarantine(&self) -> bool {
        !self.whitelisted && self.verdict_level() == VerdictLevel::Malware
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
