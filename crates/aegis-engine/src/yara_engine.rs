//! YARA engine backed by [`yara-x`] (VirusTotal's pure-Rust YARA), so there is
//! no libyara C dependency to link or version-match.
//!
//! Rules may carry metadata controlling how a match is ranked:
//! * `severity = "low" | "medium" | "high" | "critical"`
//! * `description = "..."`

use crate::engine::{Engine, FileContext};
use aegis_core::{Detection, Severity, ThreatClass};
use std::path::Path;
use yara_x::{Rules, Scanner};

pub struct YaraEngine {
    rules: Rules,
    rule_count: usize,
    sources: usize,
}

impl std::fmt::Debug for YaraEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraEngine")
            .field("sources", &self.sources)
            .field("rule_count", &self.rule_count)
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
        for src in sources {
            compiler
                .add_source(src.as_ref())
                .map_err(|e| format!("YARA compile error: {e}"))?;
            count += 1;
        }
        let rules = compiler.build();
        let rule_count = rules.iter().count();
        Ok(Self {
            rules,
            rule_count,
            sources: count,
        })
    }

    /// Compile every `*.yar`/`*.yara` file found under the given directories.
    pub fn from_dirs(dirs: &[&Path]) -> Result<Self, String> {
        let mut compiler = yara_x::Compiler::new();
        let mut sources = 0usize;
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
                let text =
                    std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()))?;
                compiler
                    .add_source(text.as_str())
                    .map_err(|e| format!("compile {}: {e}", p.display()))?;
                sources += 1;
            }
        }
        let rules = compiler.build();
        let rule_count = rules.iter().count();
        Ok(Self {
            rules,
            rule_count,
            sources,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
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
        format!(
            "ready · {} rules ({} sources)",
            self.rule_count, self.sources
        )
    }

    fn scan(&self, ctx: &FileContext<'_>) -> Vec<Detection> {
        // A Scanner is cheap to create and is not Sync; build one per call so
        // the engine itself stays Sync for the rayon pool.
        let mut scanner = Scanner::new(&self.rules);
        let results = match scanner.scan(ctx.data) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for rule in results.matching_rules() {
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
            out.push(Detection::new(
                "YARA",
                rule.identifier().to_string(),
                sev,
                ThreatClass::Signature,
                detail,
            ));
        }
        out
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
}
