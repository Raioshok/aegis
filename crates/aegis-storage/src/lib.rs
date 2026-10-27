//! # aegis-storage
//!
//! SQLite-backed persistence for scan history, detected threats and the
//! quarantine index. Exposes a [`Database`] handle plus repositories
//! (Repository pattern) so callers work with domain types, not SQL.

#![forbid(unsafe_code)]

use aegis_core::{AegisError, Result};
use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

mod quarantine_index;
mod scans;

pub use quarantine_index::{QuarantineIndex, QuarantineRecord};
pub use scans::{ScanRecord, ScanRepository, ThreatRecord};

/// Owns the SQLite connection behind a mutex (SQLite is single-writer).
#[derive(Debug)]
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Open (creating if needed) the database at `path` and run migrations.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AegisError::io(parent, e))?;
        }
        let conn = Connection::open(path).map_err(|e| AegisError::Storage(e.to_string()))?;
        let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    /// In-memory database (used by tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(|e| AegisError::Storage(e.to_string()))?;
        let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA wal_autocheckpoint = 1000;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS scans (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                started       INTEGER NOT NULL,
                finished      INTEGER NOT NULL,
                target        TEXT    NOT NULL,
                files_scanned INTEGER NOT NULL,
                threats       INTEGER NOT NULL,
                kind          TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS threats (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id  INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                ts       INTEGER NOT NULL,
                path     TEXT    NOT NULL,
                sha256   TEXT    NOT NULL,
                threat   TEXT    NOT NULL,
                engine   TEXT    NOT NULL,
                severity INTEGER NOT NULL,
                action   TEXT    NOT NULL DEFAULT 'detected'
            );

            CREATE TABLE IF NOT EXISTS quarantine (
                sha256         TEXT PRIMARY KEY,
                original_path  TEXT    NOT NULL,
                threat         TEXT    NOT NULL,
                engine         TEXT    NOT NULL,
                severity       INTEGER NOT NULL,
                size           INTEGER NOT NULL,
                quarantined_at INTEGER NOT NULL,
                stored_name    TEXT    NOT NULL,
                nonce          BLOB    NOT NULL,
                status         TEXT    NOT NULL DEFAULT 'quarantined'
            );

            CREATE INDEX IF NOT EXISTS idx_threats_scan ON threats(scan_id);
            CREATE INDEX IF NOT EXISTS idx_threats_ts   ON threats(ts);
            "#,
        )
        .map_err(|e| AegisError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Access the scan/threat repository.
    pub fn scans(&self) -> ScanRepository<'_> {
        ScanRepository::new(&self.conn)
    }

    /// Access the quarantine index repository.
    pub fn quarantine(&self) -> QuarantineIndex<'_> {
        QuarantineIndex::new(&self.conn)
    }

    /// Truncate and checkpoint the SQLite Write-Ahead Log (WAL) to prevent file bloat.
    pub fn checkpoint(&self) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| AegisError::Storage(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_and_migrates() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(db.scans().recent(10).unwrap().len(), 0);
        assert_eq!(db.quarantine().all().unwrap().len(), 0);
    }
}
