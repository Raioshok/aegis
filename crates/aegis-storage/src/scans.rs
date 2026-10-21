//! Scan-history and threat repository.

use aegis_core::{AegisError, Result};
use rusqlite::{params, Connection};
use std::sync::Mutex;

/// A row in the `scans` table.
#[derive(Debug, Clone)]
pub struct ScanRecord {
    pub id: i64,
    pub started: i64,
    pub finished: i64,
    pub target: String,
    pub files_scanned: i64,
    pub threats: i64,
    pub kind: String,
}

/// A row in the `threats` table.
#[derive(Debug, Clone)]
pub struct ThreatRecord {
    pub id: i64,
    pub ts: i64,
    pub path: String,
    pub sha256: String,
    pub threat: String,
    pub engine: String,
    pub severity: i64,
    pub action: String,
}

/// Repository over `scans` + `threats`.
pub struct ScanRepository<'a> {
    conn: &'a Mutex<Connection>,
}

impl<'a> ScanRepository<'a> {
    pub(crate) fn new(conn: &'a Mutex<Connection>) -> Self {
        Self { conn }
    }

    /// Insert a scan row and return its id.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_scan(
        &self,
        started: i64,
        finished: i64,
        target: &str,
        files_scanned: i64,
        threats: i64,
        kind: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().expect("db poisoned");
        conn.execute(
            "INSERT INTO scans(started,finished,target,files_scanned,threats,kind)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![started, finished, target, files_scanned, threats, kind],
        )
        .map_err(|e| AegisError::Storage(e.to_string()))?;
        Ok(conn.last_insert_rowid())
    }

    /// Insert a detected threat linked to a scan.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_threat(
        &self,
        scan_id: i64,
        ts: i64,
        path: &str,
        sha256: &str,
        threat: &str,
        engine: &str,
        severity: i64,
        action: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("db poisoned");
        conn.execute(
            "INSERT INTO threats(scan_id,ts,path,sha256,threat,engine,severity,action)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![scan_id, ts, path, sha256, threat, engine, severity, action],
        )
        .map_err(|e| AegisError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Most recent scans, newest first.
    pub fn recent(&self, limit: i64) -> Result<Vec<ScanRecord>> {
        let conn = self.conn.lock().expect("db poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT id,started,finished,target,files_scanned,threats,kind
                 FROM scans ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| AegisError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([limit], |r| {
                Ok(ScanRecord {
                    id: r.get(0)?,
                    started: r.get(1)?,
                    finished: r.get(2)?,
                    target: r.get(3)?,
                    files_scanned: r.get(4)?,
                    threats: r.get(5)?,
                    kind: r.get(6)?,
                })
            })
            .map_err(|e| AegisError::Storage(e.to_string()))?;
        collect(rows)
    }

    /// Most recent threats, newest first.
    pub fn recent_threats(&self, limit: i64) -> Result<Vec<ThreatRecord>> {
        let conn = self.conn.lock().expect("db poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT id,ts,path,sha256,threat,engine,severity,action
                 FROM threats ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| AegisError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([limit], |r| {
                Ok(ThreatRecord {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    path: r.get(2)?,
                    sha256: r.get(3)?,
                    threat: r.get(4)?,
                    engine: r.get(5)?,
                    severity: r.get(6)?,
                    action: r.get(7)?,
                })
            })
            .map_err(|e| AegisError::Storage(e.to_string()))?;
        collect(rows)
    }

    /// Aggregate counters for the dashboard: (scans, files, threats).
    pub fn totals(&self) -> Result<(i64, i64, i64)> {
        let conn = self.conn.lock().expect("db poisoned");
        let (scans, files): (i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(files_scanned),0) FROM scans",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| AegisError::Storage(e.to_string()))?;
        let threats: i64 = conn
            .query_row("SELECT COUNT(*) FROM threats", [], |r| r.get(0))
            .map_err(|e| AegisError::Storage(e.to_string()))?;
        Ok((scans, files, threats))
    }

    /// Delete a single threat event by its ID.
    pub fn delete_threat(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("db poisoned");
        conn.execute("DELETE FROM threats WHERE id = ?1", params![id])
            .map_err(|e| AegisError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Clear all historical threat events.
    pub fn clear_threats(&self) -> Result<()> {
        let conn = self.conn.lock().expect("db poisoned");
        conn.execute("DELETE FROM threats", [])
            .map_err(|e| AegisError::Storage(e.to_string()))?;
        Ok(())
    }
}

fn collect<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
) -> Result<Vec<T>> {
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| AegisError::Storage(e.to_string()))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use crate::Database;

    #[test]
    fn insert_and_read_back() {
        let db = Database::open_in_memory().unwrap();
        let repo = db.scans();
        let sid = repo.insert_scan(1, 2, "/tmp", 10, 1, "manual").unwrap();
        repo.insert_threat(sid, 3, "/tmp/x", "abc", "Evil", "YARA", 3, "detected")
            .unwrap();
        assert_eq!(repo.recent(5).unwrap().len(), 1);
        assert_eq!(repo.recent_threats(5).unwrap().len(), 1);
        let (scans, files, threats) = repo.totals().unwrap();
        assert_eq!((scans, files, threats), (1, 10, 1));
    }
}
