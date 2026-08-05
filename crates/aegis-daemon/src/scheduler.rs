//! Periodic scheduled scans.
//!
//! While enabled, the scheduler runs a scan of the configured target every
//! `interval_minutes`, recording results to history exactly like a manual scan.

use crate::state::DaemonState;
use aegis_core::now_epoch;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// Run scheduled scans until `shutdown` fires.
pub async fn run(state: Arc<DaemonState>, shutdown: Arc<Notify>) {
    let cfg = state.config_snapshot();
    if !cfg.schedule.enabled {
        return;
    }
    let interval = Duration::from_secs(cfg.schedule.interval_minutes.max(1) * 60);
    let target = cfg.schedule.target.clone();
    tracing::info!(
        interval_min = cfg.schedule.interval_minutes,
        target = %target.display(),
        "scheduler enabled"
    );

    let mut ticker = tokio::time::interval(interval);
    // Skip the immediate first tick so we don't scan the instant we boot.
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                tracing::info!("scheduler shutting down");
                break;
            }
            _ = ticker.tick() => {
                run_once(&state, &target).await;
            }
        }
    }
}

async fn run_once(state: &Arc<DaemonState>, target: &std::path::Path) {
    tracing::info!(target = %target.display(), "scheduled scan starting");
    let state = state.clone();
    let target = target.to_path_buf();
    let res = tokio::task::spawn_blocking(move || {
        let scanner = state.scanner();
        let (stats, verdicts) = scanner.scan(&target);
        state.incr_scans(stats.threats);
        let repo = state.db.scans();
        if let Ok(scan_id) = repo.insert_scan(
            now_epoch(),
            now_epoch(),
            &target.to_string_lossy(),
            stats.scanned as i64,
            stats.threats as i64,
            "scheduled",
        ) {
            for v in verdicts.iter().filter(|v| v.is_threat()) {
                for d in &v.detections {
                    let _ = repo.insert_threat(
                        scan_id,
                        now_epoch(),
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
        stats
    })
    .await;
    match res {
        Ok(stats) => tracing::info!(
            files = stats.scanned,
            threats = stats.threats,
            "scheduled scan finished"
        ),
        Err(e) => tracing::error!(error = %e, "scheduled scan failed"),
    }
}
