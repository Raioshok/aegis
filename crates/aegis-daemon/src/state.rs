//! Shared daemon state.
//!
//! A single [`DaemonState`] is wrapped in an `Arc` and shared by the IPC server,
//! the real-time monitor, and the scheduler. Mutable pieces (config, whitelist,
//! counters) sit behind `RwLock`/atomics so those tasks can run concurrently.

use aegis_core::{Config, EventBus, Whitelist};
use aegis_engine::{shared_engines, Engine, Scanner};
use aegis_storage::Database;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// Long-lived services and counters shared across daemon tasks.
pub struct DaemonState {
    config: RwLock<Config>,
    whitelist: RwLock<Whitelist>,
    engines: RwLock<Arc<Vec<Box<dyn Engine>>>>,
    pub db: Arc<Database>,
    pub bus: EventBus,
    started: Instant,
    // live counters surfaced via IPC `Status`
    pub scans_run: AtomicU64,
    pub threats_found: AtomicU64,
    pub rt_events: AtomicU64,
    pub rt_blocked: AtomicU64,
}

impl DaemonState {
    pub fn new(config: Config, whitelist: Whitelist, db: Arc<Database>) -> Arc<Self> {
        let engines = shared_engines(&config, &aegis_core::paths::user_rules_dir());
        Arc::new(Self {
            config: RwLock::new(config),
            whitelist: RwLock::new(whitelist),
            engines: RwLock::new(engines),
            db,
            bus: EventBus::new(),
            started: Instant::now(),
            scans_run: AtomicU64::new(0),
            threats_found: AtomicU64::new(0),
            rt_events: AtomicU64::new(0),
            rt_blocked: AtomicU64::new(0),
        })
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn config_snapshot(&self) -> Config {
        self.config.read().expect("config lock").clone()
    }

    /// Build a scanner sharing the pre-compiled engine set (no YARA recompile).
    pub fn scanner(&self) -> Scanner {
        let config = self.config.read().expect("config lock").clone();
        let whitelist = self.whitelist.read().expect("whitelist lock").clone();
        let engines = self.engines.read().expect("engines lock").clone();
        Scanner::new_shared(config, whitelist, engines, self.bus.clone())
    }

    /// Human-readable status of each engine.
    pub fn engine_infos(&self) -> Vec<(String, String)> {
        let engines = self.engines.read().expect("engines lock");
        engines
            .iter()
            .map(|e| (e.name().to_string(), e.status()))
            .collect()
    }

    /// Reload config + whitelist from disk and rebuild engines.
    pub fn reload(&self) {
        let new_config = Config::load();
        let new_wl = Whitelist::load();
        let new_engines = shared_engines(&new_config, &aegis_core::paths::user_rules_dir());
        *self.engines.write().expect("engines lock") = new_engines;
        *self.config.write().expect("config lock") = new_config;
        *self.whitelist.write().expect("whitelist lock") = new_wl;
        tracing::info!("configuration reloaded");
    }

    /// Is a path currently whitelisted? (used by the real-time monitor)
    pub fn is_whitelisted(&self, path: &Path, sha256: &str) -> bool {
        self.whitelist
            .read()
            .expect("whitelist lock")
            .is_whitelisted(path, sha256)
    }

    pub fn incr_scans(&self, threats: u64) {
        self.scans_run.fetch_add(1, Ordering::Relaxed);
        self.threats_found.fetch_add(threats, Ordering::Relaxed);
    }
}
