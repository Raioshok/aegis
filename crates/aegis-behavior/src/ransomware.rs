//! Ransomware guard — behavioural detection of mass-encryption activity.
//!
//! Ransomware has an unmistakable filesystem signature: a burst of writes that
//! replace file contents with **high-entropy** (encrypted) data, often followed
//! by renames to a common extension (`.locked`, `.crypt`, …). This guard keeps a
//! sliding time-window of recent write/rename events and raises an alert when
//! the burst + entropy pattern crosses configured thresholds.
//!
//! The detector is pure and time-injectable (`now_ms` is a parameter, not read
//! from a clock) so the entire decision logic is deterministically unit-tested.
//! The daemon feeds it real events and supplies content entropy; when a verdict
//! fires with a known PID (available from the fanotify backend) it can kill the
//! offending process.

use serde::Serialize;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

/// Tunable thresholds for the guard.
#[derive(Debug, Clone)]
pub struct RansomwareConfig {
    /// Sliding window length in milliseconds.
    pub window_ms: u64,
    /// Writes within the window required to consider a burst.
    pub max_writes: usize,
    /// A write whose content entropy is at/above this looks encrypted.
    pub entropy_threshold: f64,
    /// High-entropy writes within the window required to alert.
    pub min_high_entropy: usize,
    /// Renames to the same new extension required to flag a rename storm.
    pub rename_storm: usize,
}

impl Default for RansomwareConfig {
    fn default() -> Self {
        Self {
            window_ms: 5_000,
            max_writes: 20,
            entropy_threshold: 7.5,
            min_high_entropy: 12,
            rename_storm: 12,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EventType {
    Write,
    Rename,
}

#[derive(Debug, Clone)]
struct Record {
    at_ms: u64,
    path: PathBuf,
    entropy: f64,
    kind: EventType,
    ext: Option<String>,
    pid: Option<u32>,
}

/// The reason an alert fired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum AlertReason {
    /// Burst of high-entropy writes — encryption in progress.
    MassEncryption,
    /// Many files renamed to the same new extension.
    RenameStorm,
}

/// A ransomware alert.
#[derive(Debug, Clone, Serialize)]
pub struct RansomwareAlert {
    pub reason: AlertReason,
    /// Offending process, when attributable (fanotify backend).
    pub pid: Option<u32>,
    pub writes_in_window: usize,
    pub high_entropy_writes: usize,
    pub sample_paths: Vec<PathBuf>,
}

/// Stateful sliding-window ransomware detector.
#[derive(Debug)]
pub struct RansomwareGuard {
    cfg: RansomwareConfig,
    window: VecDeque<Record>,
    /// Debounce: suppress repeat alerts for the same pid within the window.
    last_alert_ms: Option<u64>,
}

impl RansomwareGuard {
    pub fn new(cfg: RansomwareConfig) -> Self {
        Self {
            cfg,
            window: VecDeque::new(),
            last_alert_ms: None,
        }
    }

    fn evict(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.cfg.window_ms);
        while let Some(front) = self.window.front() {
            if front.at_ms < cutoff {
                self.window.pop_front();
            } else {
                break;
            }
        }
    }

    /// Record one filesystem event and return an alert if the pattern trips.
    ///
    /// `entropy` is the Shannon entropy (0–8) of the file's current content for
    /// writes; ignored for renames.
    pub fn observe(
        &mut self,
        path: &Path,
        kind: EventType,
        entropy: f64,
        pid: Option<u32>,
        now_ms: u64,
    ) -> Option<RansomwareAlert> {
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase());
        self.window.push_back(Record {
            at_ms: now_ms,
            path: path.to_path_buf(),
            entropy,
            kind,
            ext,
            pid,
        });
        self.evict(now_ms);

        // Debounce repeated alerts within one window.
        if let Some(last) = self.last_alert_ms {
            if now_ms.saturating_sub(last) < self.cfg.window_ms {
                return None;
            }
        }

        let writes: Vec<&Record> = self
            .window
            .iter()
            .filter(|r| r.kind == EventType::Write)
            .collect();
        let high_entropy = writes
            .iter()
            .filter(|r| r.entropy >= self.cfg.entropy_threshold)
            .count();

        // 1. Mass-encryption: enough writes AND enough of them high-entropy.
        if writes.len() >= self.cfg.max_writes && high_entropy >= self.cfg.min_high_entropy {
            self.last_alert_ms = Some(now_ms);
            return Some(RansomwareAlert {
                reason: AlertReason::MassEncryption,
                pid: dominant_pid(&self.window),
                writes_in_window: writes.len(),
                high_entropy_writes: high_entropy,
                sample_paths: sample_paths(&writes),
            });
        }

        // 2. Rename storm: many renames to the same new extension.
        if let Some((_ext, count)) = dominant_rename_ext(&self.window) {
            if count >= self.cfg.rename_storm {
                self.last_alert_ms = Some(now_ms);
                let renames: Vec<&Record> = self
                    .window
                    .iter()
                    .filter(|r| r.kind == EventType::Rename)
                    .collect();
                return Some(RansomwareAlert {
                    reason: AlertReason::RenameStorm,
                    pid: dominant_pid(&self.window),
                    writes_in_window: writes.len(),
                    high_entropy_writes: high_entropy,
                    sample_paths: sample_paths(&renames),
                });
            }
        }

        None
    }
}

fn sample_paths(records: &[&Record]) -> Vec<PathBuf> {
    records.iter().take(5).map(|r| r.path.clone()).collect()
}

/// The most common PID among windowed events, if any are attributed.
fn dominant_pid(window: &VecDeque<Record>) -> Option<u32> {
    use std::collections::HashMap;
    let mut counts: HashMap<u32, usize> = HashMap::new();
    for r in window {
        if let Some(pid) = r.pid {
            *counts.entry(pid).or_default() += 1;
        }
    }
    counts.into_iter().max_by_key(|(_, c)| *c).map(|(p, _)| p)
}

/// The most common new extension among renames, and how many.
fn dominant_rename_ext(window: &VecDeque<Record>) -> Option<(String, usize)> {
    use std::collections::HashMap;
    let mut counts: HashMap<String, usize> = HashMap::new();
    for r in window {
        if r.kind == EventType::Rename {
            if let Some(ext) = &r.ext {
                *counts.entry(ext.clone()).or_default() += 1;
            }
        }
    }
    counts.into_iter().max_by_key(|(_, c)| *c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RansomwareConfig {
        RansomwareConfig {
            window_ms: 1000,
            max_writes: 10,
            entropy_threshold: 7.5,
            min_high_entropy: 6,
            rename_storm: 6,
        }
    }

    #[test]
    fn mass_encryption_trips() {
        let mut g = RansomwareGuard::new(cfg());
        let mut alert = None;
        for i in 0..12u64 {
            let p = PathBuf::from(format!("/home/u/doc{i}.txt"));
            // high-entropy writes (encrypted content); keep the first alert
            if let Some(a) = g.observe(&p, EventType::Write, 7.9, Some(1234), i * 50) {
                alert.get_or_insert(a);
            }
        }
        let a = alert.expect("should alert");
        assert_eq!(a.reason, AlertReason::MassEncryption);
        assert_eq!(a.pid, Some(1234));
        assert!(a.high_entropy_writes >= 6);
    }

    #[test]
    fn normal_activity_does_not_trip() {
        let mut g = RansomwareGuard::new(cfg());
        // A few low-entropy writes spread over time — ordinary editing.
        for i in 0..12u64 {
            let p = PathBuf::from(format!("/home/u/doc{i}.txt"));
            let a = g.observe(&p, EventType::Write, 4.0, None, i * 50);
            assert!(a.is_none(), "clean writes must not alert");
        }
    }

    #[test]
    fn slow_encryption_outside_window_does_not_trip() {
        let mut g = RansomwareGuard::new(cfg());
        // High-entropy writes but 500ms apart → never enough inside a 1s window.
        let mut tripped = false;
        for i in 0..20u64 {
            let p = PathBuf::from(format!("/home/u/doc{i}.txt"));
            if g.observe(&p, EventType::Write, 7.9, None, i * 500)
                .is_some()
            {
                tripped = true;
            }
        }
        assert!(!tripped, "writes spread beyond the window must not trip");
    }

    #[test]
    fn rename_storm_trips() {
        let mut g = RansomwareGuard::new(cfg());
        let mut alert = None;
        for i in 0..8u64 {
            let p = PathBuf::from(format!("/home/u/doc{i}.locked"));
            if let Some(a) = g.observe(&p, EventType::Rename, 0.0, Some(99), i * 50) {
                alert.get_or_insert(a);
            }
        }
        let a = alert.expect("rename storm should alert");
        assert_eq!(a.reason, AlertReason::RenameStorm);
    }
}
