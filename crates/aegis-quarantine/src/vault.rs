//! The encrypted vault implementation.

use aegis_core::paths;
use aegis_core::{AegisError, Result};
use aegis_storage::{Database, QuarantineRecord};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm};
use rand::RngCore;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Encrypted quarantine manager. Holds the vault directory and the AES key.
pub struct Quarantine<'a> {
    db: &'a Database,
    dir: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Quarantine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Quarantine")
            .field("dir", &self.dir)
            .finish()
    }
}

impl<'a> Quarantine<'a> {
    /// Open the vault, loading or generating the per-install encryption key.
    pub fn open(db: &'a Database) -> Result<Self> {
        paths::ensure_dirs().map_err(|e| AegisError::io(paths::data_dir(), e))?;
        let dir = paths::quarantine_dir();
        let key = load_or_create_key()?;
        Ok(Self { db, dir, key })
    }

    /// Open with an explicit directory + key (used by tests).
    pub fn with_parts(db: &'a Database, dir: PathBuf, key: [u8; 32]) -> Self {
        Self {
            db,
            dir,
            key: Zeroizing::new(key),
        }
    }

    fn cipher(&self) -> Aes256Gcm {
        // Key size (U32) is inferred from `Aes256Gcm::new`.
        let key = GenericArray::from_slice(&self.key[..]);
        Aes256Gcm::new(key)
    }

    /// Encrypt `path`'s contents into the vault, record metadata, and remove
    /// the original. Returns the stored record.
    pub fn quarantine(
        &self,
        path: &Path,
        sha256: &str,
        threat: &str,
        engine: &str,
        severity: i64,
        quarantined_at: i64,
    ) -> Result<QuarantineRecord> {
        let plaintext = std::fs::read(path).map_err(|e| AegisError::io(path, e))?;
        let size = plaintext.len() as u64;

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher()
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| AegisError::Crypto(format!("encrypt: {e}")))?;

        let stored_name = format!("{sha256}.aegis");
        let stored_path = self.dir.join(&stored_name);
        std::fs::write(&stored_path, &ciphertext).map_err(|e| AegisError::io(&stored_path, e))?;
        set_owner_only(&stored_path);

        // Only remove the original once the encrypted copy is safely on disk.
        std::fs::remove_file(path).map_err(|e| AegisError::io(path, e))?;

        let rec = QuarantineRecord {
            sha256: sha256.to_string(),
            original_path: path.to_string_lossy().into_owned(),
            threat: threat.to_string(),
            engine: engine.to_string(),
            severity,
            size: size as i64,
            quarantined_at,
            stored_name,
            nonce: nonce.to_vec(),
        };
        self.db.quarantine().insert(&rec)?;
        Ok(rec)
    }

    /// Decrypt and restore a quarantined item to its original path.
    pub fn restore(&self, sha256: &str) -> Result<PathBuf> {
        let rec = self
            .db
            .quarantine()
            .get(sha256)?
            .ok_or_else(|| AegisError::NotFound(format!("quarantine {sha256}")))?;
        let stored_path = self.dir.join(&rec.stored_name);
        let ciphertext =
            std::fs::read(&stored_path).map_err(|e| AegisError::io(&stored_path, e))?;

        if rec.nonce.len() != 12 {
            return Err(AegisError::Crypto("invalid nonce length".into()));
        }
        // Nonce size (U12) is inferred from `decrypt`.
        let nonce = GenericArray::from_slice(&rec.nonce);
        let plaintext = self
            .cipher()
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| AegisError::Crypto(format!("decrypt/verify: {e}")))?;

        let dest = PathBuf::from(&rec.original_path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AegisError::io(parent, e))?;
        }
        std::fs::write(&dest, &plaintext).map_err(|e| AegisError::io(&dest, e))?;

        std::fs::remove_file(&stored_path).ok();
        self.db.quarantine().remove(sha256)?;
        Ok(dest)
    }

    /// Permanently delete a quarantined item.
    pub fn delete(&self, sha256: &str) -> Result<()> {
        if let Some(rec) = self.db.quarantine().get(sha256)? {
            let stored_path = self.dir.join(&rec.stored_name);
            std::fs::remove_file(&stored_path).ok();
        }
        self.db.quarantine().remove(sha256)
    }

    pub fn list(&self) -> Result<Vec<QuarantineRecord>> {
        self.db.quarantine().all()
    }
}

/// Load the 32-byte vault key, generating (0600) it on first use.
fn load_or_create_key() -> Result<Zeroizing<[u8; 32]>> {
    let path = paths::keyring_file();
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(Zeroizing::new(key));
        }
        tracing::warn!("quarantine key file has wrong length; regenerating");
    }
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    std::fs::write(&path, key).map_err(|e| AegisError::io(&path, e))?;
    set_owner_only(&path);
    Ok(Zeroizing::new(key))
}

fn set_owner_only(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perm = meta.permissions();
            perm.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perm);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_restore_roundtrip_is_byte_identical() {
        let db = Database::open_in_memory().unwrap();
        let tmp = std::env::temp_dir().join(format!("aegis-vault-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let key = [7u8; 32];
        let q = Quarantine::with_parts(&db, tmp.clone(), key);

        let victim = tmp.join("malware.bin");
        let original = b"\x7fELF...simulated malicious payload...\x00\x01\x02";
        std::fs::write(&victim, original).unwrap();

        let rec = q
            .quarantine(&victim, "hash123", "Evil", "YARA", 4, 111)
            .unwrap();
        // original gone, encrypted blob exists and is NOT the plaintext
        assert!(!victim.exists());
        let blob = std::fs::read(tmp.join(&rec.stored_name)).unwrap();
        assert_ne!(blob.as_slice(), original.as_slice());

        // restore → byte-identical
        let restored = q.restore("hash123").unwrap();
        assert_eq!(restored, victim);
        assert_eq!(
            std::fs::read(&victim).unwrap().as_slice(),
            original.as_slice()
        );
        assert!(q.list().unwrap().is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn tampered_blob_fails_to_restore() {
        let db = Database::open_in_memory().unwrap();
        let tmp = std::env::temp_dir().join(format!("aegis-vault-tamper-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let q = Quarantine::with_parts(&db, tmp.clone(), [9u8; 32]);

        let victim = tmp.join("x.bin");
        std::fs::write(&victim, b"secret payload").unwrap();
        let rec = q.quarantine(&victim, "h", "E", "YARA", 3, 1).unwrap();

        // flip a byte in the ciphertext → GCM tag must reject it
        let blob_path = tmp.join(&rec.stored_name);
        let mut blob = std::fs::read(&blob_path).unwrap();
        blob[0] ^= 0xFF;
        std::fs::write(&blob_path, &blob).unwrap();

        assert!(q.restore("h").is_err());
        std::fs::remove_dir_all(&tmp).ok();
    }
}
