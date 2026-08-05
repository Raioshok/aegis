//! Shared runtime context wiring together config, storage, engines and the
//! quarantine vault (a small composition root / dependency-injection seam).

use aegis_core::{paths, Config, EventBus, Whitelist};
use aegis_engine::{default_engines, Scanner};
use aegis_storage::Database;

/// Owns every long-lived service the CLI commands need.
pub struct App {
    pub config: Config,
    pub whitelist: Whitelist,
    pub db: Database,
    pub bus: EventBus,
}

impl App {
    /// Build the application context, ensuring directories exist.
    pub fn new() -> aegis_core::Result<Self> {
        paths::ensure_dirs().map_err(|e| aegis_core::AegisError::io(paths::data_dir(), e))?;
        let config = Config::load();
        let whitelist = Whitelist::load();
        let db = Database::open(&paths::database_file())?;
        Ok(Self {
            config,
            whitelist,
            db,
            bus: EventBus::new(),
        })
    }

    /// Construct a fresh scanner with the currently-enabled engines.
    pub fn scanner(&self) -> Scanner {
        let engines = default_engines(&self.config, &paths::user_rules_dir());
        Scanner::new(
            self.config.clone(),
            self.whitelist.clone(),
            engines,
            self.bus.clone(),
        )
    }
}
