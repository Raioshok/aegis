//! Quarantine index repository — metadata for encrypted quarantined files.
//!
//! The encrypted blobs live on disk in the quarantine directory; this table is
//! the authoritative index describing what each blob is and how to restore it
//! (including the per-file AES-GCM nonce).

use aegis_core::{AegisError, Result};
use rusqlite::{params, Connection};
use std::sync::Mutex;

/// A quarantined item.
#[derive(Debug, Clone)]
pub struct QuarantineRecord {
    pub sha256: String,
    pub original_path: String,
    pub threat: String,
    pub engine: String,
    pub severity: i64,
    pub size: i64,
    pub quarantined_at: i64,
    pub stored_name: String,
    pub nonce: Vec<u8>,
    pub status: String,
}

pub struct QuarantineIndex<'a> {
    conn: &'a Mutex<Connection>,
}

impl<'a> QuarantineIndex<'a> {
    pub(crate) fn new(conn: &'a Mutex<Connection>) -> Self {
        Self { conn }
    }

    pub fn insert(&self, rec: &QuarantineRecord) -> Result<()> {
        let conn = self.conn.lock().expect("db poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO quarantine
             (sha256,original_path,threat,engine,severity,size,quarantined_at,stored_name,nonce,status)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                rec.sha256,
                rec.original_path,
                rec.threat,
                rec.engine,
                rec.severity,
                rec.size,
                rec.quarantined_at,
                rec.stored_name,
                rec.nonce,
                rec.status,
            ],
        )
        .map_err(|e| AegisError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn mark_status(&self, sha256: &str, status: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db poisoned");
        conn.execute(
            "UPDATE quarantine SET status=?2 WHERE sha256=?1",
            params![sha256, status],
        )
        .map_err(|e| AegisError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get(&self, sha256: &str) -> Result<Option<QuarantineRecord>> {
        let conn = self.conn.lock().expect("db poisoned");
        let mut stmt = conn
            .prepare("SELECT sha256,original_path,threat,engine,severity,size,quarantined_at,stored_name,nonce,status FROM quarantine WHERE sha256=?1")
            .map_err(|e| AegisError::Storage(e.to_string()))?;
        let mut rows = stmt
            .query_map([sha256], row_to_record)
            .map_err(|e| AegisError::Storage(e.to_string()))?;
        match rows.next() {
            Some(r) => Ok(Some(r.map_err(|e| AegisError::Storage(e.to_string()))?)),
            None => Ok(None),
        }
    }

    pub fn all(&self) -> Result<Vec<QuarantineRecord>> {
        let conn = self.conn.lock().expect("db poisoned");
        let mut stmt = conn
            .prepare("SELECT sha256,original_path,threat,engine,severity,size,quarantined_at,stored_name,nonce,status FROM quarantine ORDER BY quarantined_at DESC")
            .map_err(|e| AegisError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], row_to_record)
            .map_err(|e| AegisError::Storage(e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| AegisError::Storage(e.to_string()))?);
        }
        Ok(out)
    }

    pub fn remove(&self, sha256: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db poisoned");
        conn.execute("DELETE FROM quarantine WHERE sha256=?1", [sha256])
            .map_err(|e| AegisError::Storage(e.to_string()))?;
        Ok(())
    }
}

fn row_to_record(r: &rusqlite::Row<'_>) -> rusqlite::Result<QuarantineRecord> {
    Ok(QuarantineRecord {
        sha256: r.get(0)?,
        original_path: r.get(1)?,
        threat: r.get(2)?,
        engine: r.get(3)?,
        severity: r.get(4)?,
        size: r.get(5)?,
        quarantined_at: r.get(6)?,
        stored_name: r.get(7)?,
        nonce: r.get(8)?,
        status: r.get(9).unwrap_or_else(|_| "quarantined".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    #[test]
    fn insert_get_remove() {
        let db = Database::open_in_memory().unwrap();
        let idx = db.quarantine();
        let rec = QuarantineRecord {
            sha256: "abc".into(),
            original_path: "/tmp/x".into(),
            threat: "Evil".into(),
            engine: "YARA".into(),
            severity: 4,
            size: 123,
            quarantined_at: 999,
            stored_name: "abc.quar".into(),
            nonce: vec![1, 2, 3, 4],
            status: "quarantined".into(),
        };
        idx.insert(&rec).unwrap();
        assert!(idx.get("abc").unwrap().is_some());
        assert_eq!(idx.all().unwrap().len(), 1);
        idx.remove("abc").unwrap();
        assert!(idx.get("abc").unwrap().is_none());
    }
}
