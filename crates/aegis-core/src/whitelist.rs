//! The project whitelist — trust your own code so it never false-positives.
//!
//! Two rule kinds:
//! * **Path** rules trust a directory subtree (survives edits) or a single file.
//! * **Hash** rules trust an exact SHA-256 (a specific build of a binary).

use crate::error::{AegisError, Result};
use crate::paths;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    Path,
    Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistRule {
    pub kind: RuleKind,
    /// Absolute path (Path rules) or lowercase sha256 (Hash rules).
    pub value: String,
    #[serde(default)]
    pub label: String,
    /// For path rules: cover the entire subtree.
    #[serde(default = "default_true")]
    pub recursive: bool,
    /// Unix epoch seconds when added.
    #[serde(default)]
    pub added: i64,
}

fn default_true() -> bool {
    true
}

impl WhitelistRule {
    fn matches_path(&self, target: &Path) -> bool {
        if self.kind != RuleKind::Path {
            return false;
        }
        let rule_path = Path::new(&self.value);
        // Prefer canonical comparison; fall back to lexical if either path
        // cannot be canonicalized (e.g. the file was already deleted).
        let target_c = target.canonicalize();
        let rule_c = rule_path.canonicalize();
        match (&target_c, &rule_c) {
            (Ok(t), Ok(r)) => {
                if self.recursive {
                    t == r || t.starts_with(r)
                } else {
                    t == r
                }
            }
            _ => {
                if self.recursive {
                    target.starts_with(rule_path)
                } else {
                    target == rule_path
                }
            }
        }
    }

    fn matches_hash(&self, sha256: &str) -> bool {
        self.kind == RuleKind::Hash && self.value.eq_ignore_ascii_case(sha256)
    }
}

/// Container of whitelist rules, persisted as JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Whitelist {
    #[serde(default)]
    pub rules: Vec<WhitelistRule>,
}

impl Whitelist {
    pub fn load() -> Self {
        match std::fs::read_to_string(paths::whitelist_file()) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => Whitelist::default(),
        }
    }

    pub fn save(&self) -> Result<()> {
        paths::ensure_dirs().map_err(|e| AegisError::io(paths::config_dir(), e))?;
        let path = paths::whitelist_file();
        std::fs::write(&path, serde_json::to_string_pretty(self)?)
            .map_err(|e| AegisError::io(&path, e))
    }

    /// Returns the matching rule, if the file is whitelisted.
    pub fn matched<'a>(&'a self, path: &Path, sha256: &str) -> Option<&'a WhitelistRule> {
        self.rules.iter().find(|r| match r.kind {
            RuleKind::Path => r.matches_path(path),
            RuleKind::Hash => !sha256.is_empty() && r.matches_hash(sha256),
        })
    }

    pub fn is_whitelisted(&self, path: &Path, sha256: &str) -> bool {
        self.matched(path, sha256).is_some()
    }

    /// Trust a directory or file by path. De-duplicates on the resolved value.
    pub fn add_path(&mut self, path: &Path, label: impl Into<String>, recursive: bool, now: i64) {
        let value = path
            .canonicalize()
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .into_owned();
        if let Some(existing) = self
            .rules
            .iter_mut()
            .find(|r| r.kind == RuleKind::Path && r.value == value)
        {
            existing.recursive = recursive;
            return;
        }
        let label = label.into();
        let label = if label.is_empty() {
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| value.clone())
        } else {
            label
        };
        self.rules.push(WhitelistRule {
            kind: RuleKind::Path,
            value,
            label,
            recursive,
            added: now,
        });
    }

    /// Trust an exact file hash.
    pub fn add_hash(&mut self, sha256: &str, label: impl Into<String>, now: i64) {
        let value = sha256.to_ascii_lowercase();
        if self
            .rules
            .iter()
            .any(|r| r.kind == RuleKind::Hash && r.value == value)
        {
            return;
        }
        self.rules.push(WhitelistRule {
            kind: RuleKind::Hash,
            value,
            label: label.into(),
            recursive: false,
            added: now,
        });
    }

    /// Remove a rule by its value; returns true if something was removed.
    pub fn remove(&mut self, value: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.value != value);
        self.rules.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_rule_matches_case_insensitively() {
        let mut wl = Whitelist::default();
        wl.add_hash("ABCDEF", "test", 0);
        assert!(wl.is_whitelisted(Path::new("/nonexistent"), "abcdef"));
        assert!(!wl.is_whitelisted(Path::new("/nonexistent"), "000000"));
    }

    #[test]
    fn path_rule_recursive_subtree() {
        let dir = std::env::temp_dir();
        let mut wl = Whitelist::default();
        wl.add_path(&dir, "tmp", true, 0);
        let child = dir.join("aegis-wl-test-file");
        std::fs::write(&child, b"x").unwrap();
        assert!(wl.is_whitelisted(&child, ""));
        std::fs::remove_file(&child).ok();
    }
}
