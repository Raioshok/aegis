//! Daemon composition root and lifecycle.
//!
//! Wires the shared state, the IPC server, the real-time monitor and the
//! scheduler together, signals readiness to systemd (`Type=notify`), and shuts
//! everything down cleanly on SIGTERM/SIGINT or an IPC `Shutdown`.

use crate::realtime::{fanotify, inotify::InotifyWatcher, Monitor, Watcher};
use crate::state::DaemonState;
use crate::{scheduler, server};
use aegis_core::{paths, Config, Whitelist};
use aegis_storage::Database;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Notify;

/// Run the daemon until shutdown. Returns once every task has stopped.
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    paths::ensure_dirs()?;
    let config = Config::load();
    let whitelist = Whitelist::load();
    let db = Arc::new(Database::open(&paths::database_file())?);
    let state = DaemonState::new(config.clone(), whitelist, db);

    // IPC control socket.
    let socket = paths::socket_path();
    let listener = server::bind(&socket)?;
    tracing::info!(socket = %socket.display(), "listening on control socket");

    let shutdown = Arc::new(Notify::new());

    // --- IPC server task ---
    let server_task = {
        let state = state.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move { server::serve(listener, state, shutdown).await })
    };

    // --- Real-time monitor task ---
    let monitor_task = if config.realtime.enabled {
        match start_watcher(&config) {
            Ok(mut watcher) => {
                let backend = watcher.backend();
                let watched = watcher.watched();
                tracing::info!(backend, ?watched, "real-time protection enabled");
                match watcher.take_events() {
                    Some(rx) => {
                        let monitor = Monitor::new(state.clone(), config.realtime.auto_quarantine);
                        // The watcher's background thread owns the inotify/fanotify
                        // fd independently, so dropping `watcher` here is safe —
                        // events keep flowing until the receiver is dropped.
                        drop(watcher);
                        Some(tokio::spawn(async move { monitor.run(rx).await }))
                    }
                    None => None,
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "real-time protection failed to start; continuing without it");
                None
            }
        }
    } else {
        tracing::info!("real-time protection disabled in config");
        None
    };

    // --- Scheduler task ---
    let scheduler_task = {
        let state = state.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move { scheduler::run(state, shutdown).await })
    };

    // Tell systemd we are ready (no-op when not launched under systemd).
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
    tracing::info!(pid = std::process::id(), "aegis daemon ready");

    // --- Wait for a shutdown signal ---
    wait_for_signal(&shutdown).await;

    tracing::info!("shutdown requested; stopping tasks");
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Stopping]);
    shutdown.notify_waiters();

    // Give tasks a moment to observe the notify and exit.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let _ = server_task.await;
        let _ = scheduler_task.await;
    })
    .await;
    if let Some(m) = monitor_task {
        m.abort();
    }

    // Remove the socket file on the way out.
    let _ = std::fs::remove_file(&socket);
    tracing::info!("aegis daemon stopped");
    Ok(())
}

/// Select and start the configured real-time watcher.
fn start_watcher(config: &Config) -> Result<Box<dyn Watcher>, String> {
    let paths = config.realtime.paths.clone();
    match config.realtime.backend.as_str() {
        "fanotify" => {
            // Best-effort; falls back to inotify if unavailable/unprivileged.
            match fanotify::start(paths.clone()) {
                Ok(w) => Ok(Box::new(w)),
                Err(e) => {
                    tracing::warn!(error = %e, "fanotify unavailable; falling back to inotify");
                    InotifyWatcher::start(paths)
                        .map(|w| Box::new(w) as Box<dyn Watcher>)
                        .map_err(|e| e.to_string())
                }
            }
        }
        _ => InotifyWatcher::start(paths)
            .map(|w| Box::new(w) as Box<dyn Watcher>)
            .map_err(|e| e.to_string()),
    }
}

/// Resolve when SIGTERM/SIGINT arrives or an IPC `Shutdown` fires `shutdown`.
async fn wait_for_signal(shutdown: &Arc<Notify>) {
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "cannot install SIGTERM handler");
            shutdown.notified().await;
            return;
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => {
            shutdown.notified().await;
            return;
        }
    };
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("received SIGTERM"),
        _ = sigint.recv() => tracing::info!("received SIGINT"),
        _ = shutdown.notified() => tracing::info!("received IPC shutdown"),
    }
}
