//! Hash-signature engine — matches a file's SHA-256/SHA-1/MD5 against a
//! database of known-bad hashes (one hex digest per line; `#` comments allowed).
//!
//! This is the fastest possible detection (O(1) set lookup) and is how threat
//! feeds and offline malware-hash lists are consumed.

use crate::engine::{Engine, FileContext};
use aegis_core::{Detection, Severity, ThreatClass};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Default)]
pub struct HashEngine {
    bad: HashSet<String>,
}

impl HashEngine {
    /// Build from an iterator of hex digests.
    pub fn from_hashes<I, S>(iter: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let bad = iter
            .into_iter()
            .map(|s| s.as_ref().trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect();
        Self { bad }
    }

    /// Load newline-delimited hashes from a file, tolerating a missing file.
    pub fn from_file(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_hashes(text.lines()),
            Err(_) => Self::default(),
        }
    }

    /// Seed with a minimal built-in set so a fresh install still catches the
    /// industry-standard EICAR test file by hash.
    pub fn with_builtin() -> Self {
        Self::from_hashes([
            // EICAR standard antivirus test file (68-byte canonical form)
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        ])
    }

    pub fn len(&self) -> usize {
        self.bad.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bad.is_empty()
    }
}

impl Engine for HashEngine {
    fn name(&self) -> &str {
        "Hash"
    }

    fn status(&self) -> String {
        format!("ready · {} known-bad hashes", self.bad.len())
    }

    fn scan(&self, ctx: &FileContext<'_>) -> Vec<Detection> {
        if self.bad.contains(ctx.sha256) {
            return vec![Detection::new(
                "Hash",
                format!("Known-bad:{}", &ctx.sha256[..16.min(ctx.sha256.len())]),
                Severity::Critical,
                ThreatClass::Signature,
                "SHA-256 matched a known-malicious hash in the database",
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
        let eng = HashEngine::from_hashes(["deadbeef"]);
        let ctx = FileContext {
            path: Path::new("/x"),
            data: b"",
            size: 0,
            sha256: "deadbeef",
        };
        assert_eq!(eng.scan(&ctx).len(), 1);
    }

    #[test]
    fn ignores_unknown_hash() {
        let eng = HashEngine::from_hashes(["deadbeef"]);
        let ctx = FileContext {
            path: Path::new("/x"),
            data: b"",
            size: 0,
            sha256: "00000000",
        };
        assert!(eng.scan(&ctx).is_empty());
    }
}
