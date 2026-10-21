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

impl HashEngine {
    /// Build from an iterator of hex digests.
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
            if let Ok(bytes) = hex::decode(s) {
                if let Ok(arr) = bytes.try_into() {
                    hashes.push(arr);
                }
            }
        }
        hashes.sort_unstable();
        hashes.dedup();
        Self { hashes }
    }

    /// Load newline-delimited hashes from a file, tolerating a missing file.
    pub fn from_file(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_hashes(text.lines()),
            Err(_) => Self::default(),
        }
    }

    /// Seed with a minimal built-in set so a fresh install still catches the
    /// industry-standard EICAR test file and high-profile verified threats by hash.
    pub fn with_builtin() -> Self {
        Self::from_hashes([
            // EICAR standard antivirus test file (68-byte canonical form)
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            // Trojan.MEMZ (Destructive payload)
            "a3d5715a81f2fbeb5f76c88c9c21eeee87142909716472f911ff6950c790c24d",
            // Spyware.HawkEye (Keylogger/Credential stealer)
            "1dacdc296fd6ef6ba817b184cce9901901c47c01d849adfa4222bfabfed61838",
            // Ransomware.Cerber5
            "b3e1e9d97d74c416c2a30dd11858789af5554cf2de62f577c13944a19623777d",
            // Ransomware.AnteFrigus
            "3cb061bd1c9326ec12d3b5f540d425730245472b72e5295f52b53b82ea03cb68",
            // Virus.Macro.Melissa
            "554701bc874da646285689df79e5002b3b1a1f76daf705bea9586640026697ca",
            // Virus.DOS.MadMan
            "17d81134a5957fb758b9d69a90b033477a991c8b0f107d9864dc790ca37e6a23",
            // Ransomware.CryptoWall
            "45317968759d3e37282ceb75149f627d648534c5b4685f6da3966d8f6fca662d",
        ])
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

    pub fn contains_hex(&self, hex_str: &str) -> bool {
        if let Ok(bytes) = hex::decode(hex_str.trim()) {
            if let Ok(arr) = bytes.try_into() {
                return self.contains_hash(&arr);
            }
        }
        false
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
}
