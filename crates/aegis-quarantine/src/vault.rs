//! The encrypted vault implementation (ChaCha20-Poly1305 with legacy AES-GCM fallback).

use aegis_core::paths;
use aegis_core::{AegisError, Result};
use aegis_storage::{Database, QuarantineRecord};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const BLOB_MAGIC: &[u8; 16] = b"AEGIS_CHACHA_V1\0";
const BLOB_MAGIC_LEGACY: &[u8; 16] = b"AEGIS_VAULT_V2\x00\x00";

/// Metadata serialized into self-describing vault blobs and authenticated via AAD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMetadata {
    pub original_path: String,
    pub sha256: String,
    pub size: u64,
    pub threat: String,
    pub engine: String,
    pub severity: i64,
    pub quarantined_at: i64,
    #[serde(default)]
    pub mode: Option<u32>,
}

/// Encrypted quarantine manager. Holds the vault directory and the 256-bit symmetric key.
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

    fn chacha_cipher(&self) -> ChaCha20Poly1305 {
        let key = Key::from_slice(&self.key[..]);
        ChaCha20Poly1305::new(key)
    }

    fn legacy_aes_cipher(&self) -> Aes256Gcm {
        let key = aes_gcm::aead::generic_array::GenericArray::from_slice(&self.key[..]);
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
        // Read file metadata before reading content
        let meta = std::fs::symlink_metadata(path).map_err(|e| AegisError::io(path, e))?;
        if meta.file_type().is_symlink() {
            return Err(AegisError::Quarantine(format!(
                "refusing to quarantine symlink: {}",
                path.display()
            )));
        }

        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::MetadataExt;
            Some(meta.mode())
        };
        #[cfg(not(unix))]
        let mode = None;

        let plaintext = std::fs::read(path).map_err(|e| AegisError::io(path, e))?;
        let size = plaintext.len() as u64;

        let blob_meta = BlobMetadata {
            original_path: path.to_string_lossy().into_owned(),
            sha256: sha256.to_string(),
            size,
            threat: threat.to_string(),
            engine: engine.to_string(),
            severity,
            quarantined_at,
            mode,
        };
        let meta_bytes = serde_json::to_vec(&blob_meta)
            .map_err(|e| AegisError::Crypto(format!("serialize blob metadata: {e}")))?;

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Encrypt with metadata as ChaCha20-Poly1305 Associated Data (AAD)
        let ciphertext = self
            .chacha_cipher()
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: &meta_bytes,
                },
            )
            .map_err(|e| AegisError::Crypto(format!("encrypt: {e}")))?;

        // Build self-describing blob:
        // [16 bytes magic][12 bytes nonce][4 bytes meta_len][meta_bytes][ciphertext]
        let mut blob = Vec::with_capacity(16 + 12 + 4 + meta_bytes.len() + ciphertext.len());
        blob.extend_from_slice(BLOB_MAGIC);
        blob.extend_from_slice(nonce.as_slice());
        blob.extend_from_slice(&(meta_bytes.len() as u32).to_le_bytes());
        blob.extend_from_slice(&meta_bytes);
        blob.extend_from_slice(&ciphertext);

        let stored_name = format!("{sha256}.aegis");
        let stored_path = self.dir.join(&stored_name);
        std::fs::write(&stored_path, &blob).map_err(|e| AegisError::io(&stored_path, e))?;
        set_owner_only(&stored_path);

        // Mark record pending BEFORE removing original (crash safety)
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
            status: "pending".to_string(),
        };
        self.db.quarantine().insert(&rec)?;

        // Now remove the original file
        match std::fs::remove_file(path) {
            Ok(_) => {
                let _ = self.db.quarantine().mark_status(sha256, "quarantined");
            }
            Err(e) => {
                tracing::warn!(
                    "failed to unlink original file {}: {e}; marked as pending in vault",
                    path.display()
                );
            }
        }

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
        let blob =
            std::fs::read(&stored_path).map_err(|e| AegisError::io(&stored_path, e))?;

        let is_chacha = blob.starts_with(BLOB_MAGIC);
        let is_legacy_aes = blob.starts_with(BLOB_MAGIC_LEGACY);

        let (nonce_bytes, meta_opt, ciphertext) = if (is_chacha || is_legacy_aes) && blob.len() >= 32 {
            let nonce = &blob[16..28];
            let meta_len = u32::from_le_bytes(
                blob[28..32]
                    .try_into()
                    .map_err(|_| AegisError::Crypto("invalid meta length in blob".into()))?,
            ) as usize;
            if blob.len() < 32 + meta_len {
                return Err(AegisError::Crypto("corrupt vault blob header".into()));
            }
            let meta_slice = &blob[32..32 + meta_len];
            let cipher_slice = &blob[32 + meta_len..];
            (nonce.to_vec(), Some(meta_slice.to_vec()), cipher_slice.to_vec())
        } else {
            // Legacy / raw ciphertext compatibility
            (rec.nonce.clone(), None, blob)
        };

        if nonce_bytes.len() != 12 {
            return Err(AegisError::Crypto("invalid nonce length".into()));
        }

        let plaintext = if is_legacy_aes {
            let aes_nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(&nonce_bytes);
            if let Some(meta_bytes) = &meta_opt {
                self.legacy_aes_cipher()
                    .decrypt(
                        aes_nonce,
                        Payload {
                            msg: &ciphertext,
                            aad: meta_bytes,
                        },
                    )
                    .map_err(|e| AegisError::Crypto(format!("decrypt/verify: {e}")))?
            } else {
                self.legacy_aes_cipher()
                    .decrypt(aes_nonce, ciphertext.as_ref())
                    .map_err(|e| AegisError::Crypto(format!("decrypt/verify: {e}")))?
            }
        } else {
            let chacha_nonce = Nonce::from_slice(&nonce_bytes);
            if let Some(meta_bytes) = &meta_opt {
                self.chacha_cipher()
                    .decrypt(
                        chacha_nonce,
                        Payload {
                            msg: &ciphertext,
                            aad: meta_bytes,
                        },
                    )
                    .map_err(|e| AegisError::Crypto(format!("decrypt/verify: {e}")))?
            } else {
                self.chacha_cipher()
                    .decrypt(chacha_nonce, ciphertext.as_ref())
                    .map_err(|e| AegisError::Crypto(format!("decrypt/verify: {e}")))?
            }
        };

        let dest = PathBuf::from(&rec.original_path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AegisError::io(parent, e))?;
        }

        // Restore using create_new(true) (O_CREAT | O_EXCL) to prevent symlink hijack attacks
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)
            .map_err(|e| AegisError::io(&dest, e))?;
        file.write_all(&plaintext).map_err(|e| AegisError::io(&dest, e))?;

        // Reapply permissions if recorded in metadata
        if let Some(meta_bytes) = &meta_opt {
            if let Ok(_meta) = serde_json::from_slice::<BlobMetadata>(meta_bytes) {
                #[cfg(unix)]
                if let Some(mode) = _meta.mode {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode));
                }
            }
        }

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
/// Never regenerates an existing key to prevent data loss.
fn load_or_create_key() -> Result<Zeroizing<[u8; 32]>> {
    let path = paths::keyring_file();
    if path.exists() {
        let bytes = std::fs::read(&path).map_err(|e| AegisError::io(&path, e))?;
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(Zeroizing::new(key));
        }
        return Err(AegisError::Crypto(format!(
            "quarantine keyring file at {} is corrupted (expected 32 bytes, got {}); refusing to regenerate to protect existing quarantined files",
            path.display(),
            bytes.len()
        )));
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
    #[cfg(not(unix))]
    {
        let _ = path;
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

        let sha256 = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
        let rec = q
            .quarantine(
                &victim,
                sha256,
                "EICAR.Test",
                "test",
                3,
                1_700_000_000,
            )
            .unwrap();

        // Victim was unlinked
        assert!(!victim.exists());
        // Ciphertext blob was written with AEGIS_CHACHA_V1
        let stored = tmp.join(&rec.stored_name);
        assert!(stored.exists());
        let blob_bytes = std::fs::read(&stored).unwrap();
        assert!(blob_bytes.starts_with(b"AEGIS_CHACHA_V1\0"));

        // Restore works and decrypts back to byte-identical content
        let restored_path = q.restore(sha256).unwrap();
        assert_eq!(restored_path, victim);
        let restored = std::fs::read(&restored_path).unwrap();
        assert_eq!(restored, original);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn tampered_blob_fails_to_restore() {
        let db = Database::open_in_memory().unwrap();
        let tmp = std::env::temp_dir().join(format!("aegis-vault-tamp-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let key = [9u8; 32];
        let q = Quarantine::with_parts(&db, tmp.clone(), key);

        let victim = tmp.join("tamper.bin");
        std::fs::write(&victim, b"plain payload").unwrap();
        let sha256 = "aabbccddeeff11223344556677889900aabbccddeeff11223344556677889900";
        let rec = q
            .quarantine(&victim, sha256, "Tamper.Test", "test", 2, 100)
            .unwrap();

        let stored = tmp.join(&rec.stored_name);
        let mut blob = std::fs::read(&stored).unwrap();
        // Corrupt one byte of ciphertext/MAC
        let last = blob.len() - 1;
        blob[last] ^= 0x42;
        std::fs::write(&stored, &blob).unwrap();

        assert!(q.restore(sha256).is_err());
        std::fs::remove_dir_all(&tmp).ok();
    }
}
