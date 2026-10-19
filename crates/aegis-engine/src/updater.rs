//! Automated threat intelligence & signature updater.
//!
//! Manages feeds for:
//! * **MalwareBazaar** (abuse.ch): known malicious SHA-256 hashes.
//! * **Feodo Tracker / ThreatFox** (abuse.ch): C2 and botnet IP addresses.
//! * **YARA Forge**: standardized, tiered community YARA rules (Core / Extended / Full).

use aegis_core::{AegisError, BlockSets, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

pub const MALWAREBAZAAR_RECENT_URL: &str = "https://bazaar.abuse.ch/export/txt/sha256/recent/";
pub const FEODOTRACKER_IP_URL: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";
pub const THREATFOX_RECENT_URL: &str = "https://threatfox.abuse.ch/export/csv/ip-port/recent/";

/// Manifest of cached feeds with their ETag / last-modified values.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FeedManifest {
    pub etags: HashMap<String, String>,
    pub updated_at: HashMap<String, i64>,
}

#[derive(Debug, Clone, Default)]
pub struct FeedData {
    pub hashes: Vec<[u8; 32]>,
    pub block_sets: BlockSets,
    pub rule_sources: Vec<String>,
}

pub struct FeedManager {
    dir: PathBuf,
}

impl FeedManager {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let d = dir.into();
        let _ = std::fs::create_dir_all(&d);
        Self { dir: d }
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.dir.join("feeds_manifest.json")
    }

    pub fn load_manifest(&self) -> FeedManifest {
        std::fs::read_to_string(self.manifest_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save_manifest(&self, m: &FeedManifest) -> Result<()> {
        let json = serde_json::to_string_pretty(m)?;
        std::fs::write(self.manifest_path(), json)
            .map_err(|e| AegisError::io(self.manifest_path(), e))?;
        Ok(())
    }

    /// Parse newline-delimited SHA-256 hash list (MalwareBazaar style).
    pub fn parse_hashes(content: &str) -> Vec<[u8; 32]> {
        let mut hashes = Vec::new();
        for line in content.lines() {
            let s = line.trim();
            if s.is_empty() || s.starts_with('#') {
                continue;
            }
            // First token is hash
            let token = s.split_whitespace().next().unwrap_or(s);
            if token.len() == 64 {
                if let Ok(bytes) = hex::decode(token) {
                    if let Ok(arr) = bytes.try_into() {
                        hashes.push(arr);
                    }
                }
            }
        }
        hashes.sort_unstable();
        hashes.dedup();
        hashes
    }

    /// Parse IP blocklists (Feodo Tracker or ThreatFox style).
    pub fn parse_ips(content: &str) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for line in content.lines() {
            let s = line.trim();
            if s.is_empty() || s.starts_with('#') {
                continue;
            }
            // ThreatFox format is CSV, Feodo is plaintext IP
            let token = if s.contains(',') {
                s.split(',').nth(1).unwrap_or(s).trim_matches('"').trim()
            } else {
                s.split_whitespace().next().unwrap_or(s)
            };

            // Remove port if present (handle IPv6 with brackets or plain IPv4:port)
            let ip_str = if token.starts_with('[') {
                token.trim_start_matches('[').split(']').next().unwrap_or(token)
            } else if token.parse::<Ipv6Addr>().is_ok() {
                token
            } else if let Some((host, _port)) = token.split_once(':') {
                host
            } else {
                token
            };

            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                v4.push(ip);
            } else if let Ok(ip) = ip_str.parse::<Ipv6Addr>() {
                v6.push(ip);
            }
        }
        v4.sort_unstable();
        v4.dedup();
        v6.sort_unstable();
        v6.dedup();
        (v4, v6)
    }

    /// Store downloaded feed data locally.
    pub fn store_feed(&self, name: &str, content: &[u8], etag: Option<&str>) -> Result<()> {
        let path = self.dir.join(name);
        std::fs::write(&path, content).map_err(|e| AegisError::io(&path, e))?;

        let mut manifest = self.load_manifest();
        if let Some(e) = etag {
            manifest.etags.insert(name.to_string(), e.to_string());
        }
        manifest.updated_at.insert(name.to_string(), aegis_core::now_epoch());
        self.save_manifest(&manifest)?;
        Ok(())
    }

    /// Load all stored local feeds from disk into unified structures.
    pub fn load_all(&self) -> FeedData {
        let mut data = FeedData::default();

        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if fname.ends_with(".sha256") || fname.contains("hashes") {
                    if let Ok(text) = std::fs::read_to_string(&p) {
                        data.hashes.extend(Self::parse_hashes(&text));
                    }
                } else if fname.ends_with(".ips") || fname.contains("ipblocklist") || fname.contains("threatfox") {
                    if let Ok(text) = std::fs::read_to_string(&p) {
                        let (v4, v6) = Self::parse_ips(&text);
                        data.block_sets.ipv4.extend(v4);
                        data.block_sets.ipv6.extend(v6);
                    }
                } else if fname.ends_with(".yar") || fname.ends_with(".yara") {
                    if let Ok(text) = std::fs::read_to_string(&p) {
                        data.rule_sources.push(text);
                    }
                }
            }
        }

        data.hashes.sort_unstable();
        data.hashes.dedup();
        data.block_sets.ipv4.sort_unstable();
        data.block_sets.ipv4.dedup();
        data.block_sets.ipv6.sort_unstable();
        data.block_sets.ipv6.dedup();

        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_malwarebazaar_hashes() {
        let sample = "\
# MalwareBazaar export
# Generated 2026-10-17
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
# comment
";
        let hashes = FeedManager::parse_hashes(sample);
        assert_eq!(hashes.len(), 2);
    }

    #[test]
    fn parses_ips_both_formats() {
        let sample_plain = "1.2.3.4\n5.6.7.8:8080\n2001:db8::1\n";
        let (v4, v6) = FeedManager::parse_ips(sample_plain);
        assert_eq!(v4.len(), 2);
        assert_eq!(v6.len(), 1);

        let sample_csv = "\"id\",\"10.20.30.40:443\",\"c2\"\n";
        let (v4_csv, _) = FeedManager::parse_ips(sample_csv);
        assert_eq!(v4_csv.len(), 1);
        assert_eq!(v4_csv[0].to_string(), "10.20.30.40");
    }
}
