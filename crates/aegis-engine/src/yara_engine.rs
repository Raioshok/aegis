//! YARA engine backed by [`yara-x`] (VirusTotal's pure-Rust YARA).
//!
//! Features:
//! * Per-file compile error isolation: failing user rule files are skipped and reported in `status()`.
//! * Versioned rule set: hash of rules to invalidate the verdict cache.
//! * Reusable `Scanner` per thread: minimizes allocation overhead.
//! * YARA Forge packages support.

use crate::engine::{Engine, FileContext};
use aegis_core::{Detection, Severity, ThreatClass};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::path::Path;
use std::sync::Arc;
use yara_x::{Rules, Scanner};

thread_local! {
    static THREAD_SCANNER: RefCell<Option<(*const Rules, Scanner<'static>)>> = const { RefCell::new(None) };
}

pub struct YaraEngine {
    rules: Arc<Rules>,
    rule_count: usize,
    sources: usize,
    failed_sources: Vec<(String, String)>,
    version: String,
}

impl std::fmt::Debug for YaraEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraEngine")
            .field("sources", &self.sources)
            .field("rule_count", &self.rule_count)
            .field("version", &self.version)
            .field("failed_sources", &self.failed_sources.len())
            .finish()
    }
}

impl YaraEngine {
    /// Compile rules from a collection of source strings.
    pub fn from_sources<I, S>(sources: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut compiler = yara_x::Compiler::new();
        let mut count = 0usize;
        let mut hasher = Sha256::new();
        for src in sources {
            let s = src.as_ref();
            compiler
                .add_source(s)
                .map_err(|e| format!("YARA compile error: {e}"))?;
            hasher.update(s.as_bytes());
            count += 1;
        }
        let rules = Arc::new(compiler.build());
        let rule_count = rules.iter().count();
        let version = hex::encode(&hasher.finalize()[..8]);
        Ok(Self {
            rules,
            rule_count,
            sources: count,
            failed_sources: Vec::new(),
            version,
        })
    }

    /// Compile every `*.yar`/`*.yara` file found under the given directories.
    /// Skips files that fail compilation individually so one bad file never breaks the engine.
    pub fn from_dirs(dirs: &[&Path]) -> Result<Self, String> {
        let mut compiler = yara_x::Compiler::new();
        let mut sources = 0usize;
        let mut failed_sources = Vec::new();
        let mut hasher = Sha256::new();

        for dir in dirs {
            if !dir.exists() {
                continue;
            }
            let walker = walkdir::WalkDir::new(dir)
                .into_iter()
                .filter_map(|e| e.ok());
            for entry in walker {
                let p = entry.path();
                let is_rule = p
                    .extension()
                    .map(|e| e == "yar" || e == "yara")
                    .unwrap_or(false);
                if !is_rule {
                    continue;
                }
                let text = match std::fs::read_to_string(p) {
                    Ok(t) => t,
                    Err(e) => {
                        failed_sources.push((p.display().to_string(), format!("read error: {e}")));
                        continue;
                    }
                };
                // Test-compile this rule file individually first to isolate errors
                let mut test_compiler = yara_x::Compiler::new();
                if let Err(e) = test_compiler.add_source(text.as_str()) {
                    failed_sources.push((p.display().to_string(), format!("compile error: {e}")));
                    continue;
                }
                // Add to main compiler
                if compiler.add_source(text.as_str()).is_ok() {
                    hasher.update(text.as_bytes());
                    sources += 1;
                }
            }
        }

        let rules = Arc::new(compiler.build());
        let rule_count = rules.iter().count();
        let version = hex::encode(&hasher.finalize()[..8]);
        Ok(Self {
            rules,
            rule_count,
            sources,
            failed_sources,
            version,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn failed_sources(&self) -> &[(String, String)] {
        &self.failed_sources
    }

    fn map_severity(meta: &[(&str, MetaVal)]) -> (Severity, String) {
        let mut sev = Severity::Medium;
        let mut desc = String::new();
        for (k, v) in meta {
            match (*k, v) {
                ("severity", MetaVal::Str(s)) => {
                    sev = match s.to_ascii_lowercase().as_str() {
                        "low" => Severity::Low,
                        "medium" => Severity::Medium,
                        "high" => Severity::High,
                        "critical" => Severity::Critical,
                        _ => Severity::Medium,
                    };
                }
                ("description", MetaVal::Str(s)) => desc = s.clone(),
                _ => {}
            }
        }
        (sev, desc)
    }
}

/// Simplified metadata value extracted from a yara-x match.
enum MetaVal {
    Str(String),
    Other,
}

impl Engine for YaraEngine {
    fn name(&self) -> &str {
        "YARA"
    }

    fn status(&self) -> String {
        if self.failed_sources.is_empty() {
            format!(
                "ready · {} rules ({} sources, version {})",
                self.rule_count, self.sources, self.version
            )
        } else {
            format!(
                "ready · {} rules ({} sources, {} skipped with errors, version {})",
                self.rule_count,
                self.sources,
                self.failed_sources.len(),
                self.version
            )
        }
    }

    fn scan(&self, ctx: &FileContext<'_>) -> Vec<Detection> {
        let rules_ptr = Arc::as_ptr(&self.rules);

        THREAD_SCANNER.with(|cell| {
            let mut borrow = cell.borrow_mut();
            let need_new = match *borrow {
                Some((ptr, _)) => ptr != rules_ptr,
                None => true,
            };
            if need_new {
                // Safety: `self.rules` is an Arc held by YaraEngine which outlives any scan turn.
                let static_rules: &'static Rules = unsafe { &*rules_ptr };
                let scanner = Scanner::new(static_rules);
                *borrow = Some((rules_ptr, scanner));
            }
            let (_, ref mut scanner) = borrow.as_mut().unwrap();
            let matches = match scanner.scan(ctx.data) {
                Ok(r) => r,
                Err(_) => return Vec::new(),
            };

            let mut out = Vec::new();
            for rule in matches.matching_rules() {
                let meta: Vec<(&str, MetaVal)> = rule
                    .metadata()
                    .map(|(k, v)| {
                        let mv = match v {
                            yara_x::MetaValue::String(s) => MetaVal::Str(s.to_string()),
                            yara_x::MetaValue::Bytes(b) => {
                                MetaVal::Str(String::from_utf8_lossy(b).into_owned())
                            }
                            _ => MetaVal::Other,
                        };
                        (k, mv)
                    })
                    .collect();
                let (sev, desc) = YaraEngine::map_severity(&meta);
                let detail = if desc.is_empty() {
                    format!("Matched YARA rule {}", rule.identifier())
                } else {
                    desc
                };
                let (weight, conf) = match sev {
                    Severity::Critical => (1.0, 0.95),
                    Severity::High => (0.9, 0.9),
                    Severity::Medium => (0.7, 0.7),
                    Severity::Low => (0.4, 0.4),
                    Severity::Clean => (0.0, 0.0),
                };
                out.push(Detection::with_scores(
                    "YARA",
                    rule.identifier().to_string(),
                    sev,
                    ThreatClass::Signature,
                    detail,
                    weight,
                    conf,
                ));
            }
            out
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_and_matches() {
        let src = r#"
            rule contains_evil {
                meta:
                    severity = "high"
                    description = "test rule"
                strings:
                    $a = "EVILMARKER"
                condition:
                    $a
            }
        "#;
        let eng = YaraEngine::from_sources([src]).unwrap();
        assert_eq!(eng.rule_count(), 1);
        let data = b"harmless ... EVILMARKER ... tail";
        let ctx = FileContext {
            path: Path::new("/x"),
            data,
            size: data.len() as u64,
            sha256: "",
        };
        let d = eng.scan(&ctx);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].severity, Severity::High);
    }

    #[test]
    fn bad_rule_file_does_not_disable_engine() {
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp = std::env::temp_dir().join(format!("aegis-badrule-{}-{}", std::process::id(), unique_id));
        std::fs::create_dir_all(&tmp).unwrap();
        let good_rule = tmp.join("good.yar");
        std::fs::write(&good_rule, "rule good { condition: true }").unwrap();

        let bad_rule = tmp.join("bad.yar");
        std::fs::write(&bad_rule, "this is not a valid yara rule syntax error").unwrap();

        let eng = YaraEngine::from_dirs(&[&tmp]).unwrap();
        assert_eq!(eng.rule_count(), 1);
        assert_eq!(eng.failed_sources().len(), 1);
        assert!(eng.status().contains("skipped with errors"));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_all_bundled_rules_compile_cleanly() {
        use crate::{BUNDLED_YARA, BUNDLED_YARA_DROPPERS, BUNDLED_YARA_RANSOM};
        let eng = YaraEngine::from_sources([BUNDLED_YARA, BUNDLED_YARA_DROPPERS, BUNDLED_YARA_RANSOM]).unwrap();
        assert!(eng.failed_sources().is_empty(), "Bundled rules had compilation errors: {:?}", eng.failed_sources());
        assert!(eng.rule_count() >= 20);
    }
}
