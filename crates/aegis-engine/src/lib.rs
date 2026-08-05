//! # aegis-engine
//!
//! Detection engines (Strategy pattern behind the [`Engine`] trait) and the
//! parallel [`Scanner`] orchestrator. Depends only on `aegis-core`, keeping
//! detection logic independent of storage, IPC and UI concerns.
//!
//! Engines shipped in Milestone 1:
//! * [`HashEngine`] — known-bad SHA-256/SHA-1/MD5 database.
//! * [`YaraEngine`] — YARA rules via pure-Rust `yara-x`.
//! * [`HeuristicEngine`] — entropy + behavioural byte-patterns.

#![forbid(unsafe_code)]

pub mod engine;
pub mod hash_engine;
pub mod hashing;
pub mod heuristic_engine;
pub mod orchestrator;
pub mod yara_engine;

pub use engine::{Engine, FileContext};
pub use hash_engine::HashEngine;
pub use hashing::{digest_file, sha256_hex, Digests};
pub use heuristic_engine::{shannon_entropy, HeuristicEngine};
pub use orchestrator::Scanner;
pub use yara_engine::YaraEngine;

/// The baseline YARA rules bundled into the binary (see `rules/aegis_base.yar`).
pub const BUNDLED_YARA: &str = include_str!("../../../rules/aegis_base.yar");

/// Build the default engine set from configuration, loading bundled + user
/// YARA rules and the built-in hash seeds.
pub fn default_engines(
    config: &aegis_core::Config,
    user_rules_dir: &std::path::Path,
) -> Vec<Box<dyn Engine>> {
    let mut engines: Vec<Box<dyn Engine>> = Vec::new();

    if config.engines.hash {
        engines.push(Box::new(HashEngine::with_builtin()));
    }
    if config.engines.yara {
        // Compile bundled rules first, then any user rules directory.
        let mut sources: Vec<String> = vec![BUNDLED_YARA.to_string()];
        if user_rules_dir.exists() {
            for entry in walkdir::WalkDir::new(user_rules_dir)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let p = entry.path();
                let is_rule = p
                    .extension()
                    .map(|e| e == "yar" || e == "yara")
                    .unwrap_or(false);
                if is_rule {
                    if let Ok(text) = std::fs::read_to_string(p) {
                        sources.push(text);
                    }
                }
            }
        }
        match YaraEngine::from_sources(sources) {
            Ok(y) => engines.push(Box::new(y)),
            Err(e) => tracing::error!(error = %e, "YARA compilation failed; engine disabled"),
        }
    }
    if config.engines.heuristic {
        engines.push(Box::new(HeuristicEngine::new(config.entropy_threshold)));
    }
    engines
}
