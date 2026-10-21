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

pub mod clamd_engine;
pub mod engine;
pub mod hash_engine;
pub mod hashing;
pub mod heuristic_engine;
pub mod ml_engine;
pub mod orchestrator;
pub mod updater;
pub mod yara_engine;

pub use clamd_engine::ClamdEngine;
pub use engine::{Engine, FileContext};
pub use hash_engine::HashEngine;
pub use hashing::{digest_file, sha256_hex, Digests};
pub use heuristic_engine::{shannon_entropy, HeuristicEngine};
pub use ml_engine::{
    ByteEntropyHistogram, ByteHistogram, GbdtModel, ImportFeatures, MlEngine, PeFeatures,
    SectionCharacteristics,
};
pub use orchestrator::Scanner;
pub use updater::{FeedData, FeedManager};
pub use yara_engine::YaraEngine;

/// The baseline YARA rules bundled into the binary (see `rules/aegis_base.yar`).
pub const BUNDLED_YARA: &str = include_str!("../../../rules/aegis_base.yar");
pub const BUNDLED_YARA_DROPPERS: &str = include_str!("../../../rules/droppers_and_cradles.yar");
pub const BUNDLED_YARA_RANSOM: &str = include_str!("../../../rules/ransomware_and_rats.yar");

/// Scan an in-memory script/macro buffer received from the Windows AMSI provider
/// or an in-memory script evaluator. Returns the most severe detection if a threat is matched.
pub fn scan_amsi_buffer(
    content_name: &str,
    buffer: &[u8],
    engines: &[Box<dyn Engine>],
) -> Option<aegis_core::Detection> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(buffer);
    let sha256 = hex::encode(hasher.finalize());

    let ctx = FileContext {
        path: std::path::Path::new(content_name),
        data: buffer,
        size: buffer.len() as u64,
        sha256: &sha256,
    };

    let mut detections = Vec::new();
    for engine in engines {
        detections.extend(engine.scan(&ctx));
    }
    detections.into_iter().max_by_key(|d| d.severity)
}

/// Like [`default_engines`], but returns a shareable `Arc` for the daemon to
/// build the engine set once and reuse across every scan and every real-time
/// event (YARA compilation happens exactly once).
pub fn shared_engines(
    config: &aegis_core::Config,
    user_rules_dir: &std::path::Path,
) -> std::sync::Arc<Vec<Box<dyn Engine>>> {
    std::sync::Arc::new(default_engines(config, user_rules_dir))
}

/// Build the default engine set from configuration, loading bundled + user
/// YARA rules and the built-in hash seeds.
pub fn default_engines(
    config: &aegis_core::Config,
    user_rules_dir: &std::path::Path,
) -> Vec<Box<dyn Engine>> {
    let mut engines: Vec<Box<dyn Engine>> = Vec::new();

    if config.engines.hash {
        let threat_intel_file = aegis_core::paths::threat_intel_dir().join("hashes.txt");
        let hash_engine = if threat_intel_file.exists() {
            HashEngine::from_file(&threat_intel_file)
        } else {
            HashEngine::with_builtin()
        };
        engines.push(Box::new(hash_engine));
    }
    if config.engines.yara {
        // Compile bundled rules first, then any user rules directory.
        let mut sources: Vec<String> = vec![
            BUNDLED_YARA.to_string(),
            BUNDLED_YARA_DROPPERS.to_string(),
            BUNDLED_YARA_RANSOM.to_string(),
        ];
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
    if config.engines.ml {
        engines.push(Box::new(MlEngine::default()));
    }
    engines
}
