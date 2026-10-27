//! Hash-signature engine — matches a file's SHA-256 against a
//! database of known-bad hashes (sorted [u8; 32] binary search).
//!
//! Feeds from MalwareBazaar (abuse.ch) or local hash lists are stored in a
//! compact sorted vector of 32-byte arrays for cache-friendly binary search.

use crate::engine::{Engine, FileContext};
use aegis_core::{Detection, Severity, ThreatClass};
use std::path::Path;

#[derive(Debug, Default)]
pub struct HashEngine {
    /// Sorted array of SHA-256 digests.
    hashes: Vec<[u8; 32]>,
}

const BUNDLED_MALWARE_HASHES: &str = include_str!("../../../rules/malware_hashes.txt");
const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

fn builtin_lines<'a>() -> impl Iterator<Item = &'a str> {
    std::iter::once(EICAR_SHA256).chain(BUNDLED_MALWARE_HASHES.lines())
}

impl HashEngine {
    /// Build from an iterator of hex digests (exactly these, no built-ins).
    pub fn from_hashes<I, S>(iter: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut hashes = Vec::new();
        for item in iter {
            let s = item.as_ref().trim();
            if s.is_empty() || s.starts_with('#') {
                continue;
            }
            let hex_part = s.split_whitespace().next().unwrap_or("");
            if let Ok(bytes) = hex::decode(hex_part) {
                if let Ok(arr) = bytes.try_into() {
                    hashes.push(arr);
                }
            }
        }
        hashes.sort_unstable();
        hashes.dedup();
        Self { hashes }
    }

    /// Load newline-delimited hashes from a file on top of the built-in set,
    /// tolerating a missing file.
    pub fn from_file(path: &Path) -> Self {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        Self::from_hashes(builtin_lines().chain(text.lines()))
    }

    /// Seed with built-in verified threat hashes and the EICAR test signature.
    pub fn with_builtin() -> Self {
        Self::from_hashes(builtin_lines())
    }

    /// Add more digests (e.g. from synced feeds).
    pub fn extend(&mut self, more: impl IntoIterator<Item = [u8; 32]>) {
        self.hashes.extend(more);
        self.hashes.sort_unstable();
        self.hashes.dedup();
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    pub fn contains_hash(&self, sha256_bytes: &[u8; 32]) -> bool {
        self.hashes.binary_search(sha256_bytes).is_ok()
    }

    #[inline]
    pub fn contains_hex(&self, hex_str: &str) -> bool {
        let trimmed = hex_str.trim();
        if trimmed.len() != 64 {
            return false;
        }
        let mut arr = [0u8; 32];
        if hex::decode_to_slice(trimmed, &mut arr).is_ok() {
            self.contains_hash(&arr)
        } else {
            false
        }
    }
}

impl Engine for HashEngine {
    fn name(&self) -> &str {
        "Hash"
    }

    fn status(&self) -> String {
        format!("ready · {} known-bad hashes (binary search)", self.hashes.len())
    }

    fn scan(&self, ctx: &FileContext<'_>) -> Vec<Detection> {
        if self.contains_hex(ctx.sha256) {
            return vec![Detection::with_scores(
                "Hash",
                format!("Known-bad:{}", &ctx.sha256[..16.min(ctx.sha256.len())]),
                Severity::Critical,
                ThreatClass::Signature,
                "SHA-256 matched a known-malicious hash in the database",
                1.0,
                1.0,
            )];
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_hash() {
        let h = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        let eng = HashEngine::from_hashes([h]);
        let ctx = FileContext {
            path: Path::new("/x"),
            data: b"",
            size: 0,
            sha256: h,
        };
        assert_eq!(eng.scan(&ctx).len(), 1);
    }

    #[test]
    fn ignores_unknown_hash() {
        let eng = HashEngine::from_hashes(["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"]);
        let ctx = FileContext {
            path: Path::new("/x"),
            data: b"",
            size: 0,
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        };
        assert!(eng.scan(&ctx).is_empty());
    }

    #[test]
    fn feed_file_adds_to_builtin_set() {
        let feed = std::env::temp_dir().join(format!("aegis-feed-{}.txt", std::process::id()));
        let extra = "11".repeat(32);
        std::fs::write(&feed, &extra).unwrap();
        let eng = HashEngine::from_file(&feed);
        std::fs::remove_file(&feed).ok();
        assert!(eng.contains_hex(&extra));
        assert!(eng.contains_hex(EICAR_SHA256));
        assert_eq!(eng.len(), HashEngine::with_builtin().len() + 1);
    }
}
