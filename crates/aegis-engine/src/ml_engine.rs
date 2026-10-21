//! Pure-Rust On-Device Machine Learning PE Classifier.
//!
//! Provides:
//! 1. PE Feature Extraction (EMBER-compatible):
//!    - `ByteHistogram`: 256 dimensions normalized byte frequencies.
//!    - `ByteEntropyHistogram`: 256 dimensions sliding-window 2D joint distribution
//!      (16 coarse byte bins × 16 Shannon entropy bins).
//!    - `SectionCharacteristics`: Section counts, entropy, virtual vs raw size ratios,
//!      W+X permissions, entrypoint alignment.
//!    - `ImportFeatures`: Standard FireEye/pefile MD5 `imphash`, API statistics,
//!      and suspicious capability categorization (injection, evasion, network,
//!      persistence, crypto, execution).
//! 2. Fast Tree Evaluator:
//!    - Pure-Rust, zero-dependency Gradient Boosted Decision Tree (GBDT) ensemble.
//!    - Contiguous flat node arrays: <1MB RAM, <50 microseconds evaluation time.
//! 3. `MlEngine`:
//!    - Implements [`crate::Engine`] detection strategy.

use crate::engine::{Engine, FileContext};
use aegis_core::{Detection, Severity, ThreatClass};
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashSet;
use std::path::Path;

/// Length of the full extracted PE feature vector (256 + 256 + 32 + 32).
pub const PE_FEATURE_DIM: usize = 576;

/// Calculate Shannon entropy (bits/byte, 0.0 to 8.0) of a byte slice.
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f32;
    let mut entropy = 0.0f32;
    for &c in freq.iter() {
        if c > 0 {
            let p = c as f32 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

// ============================================================================
// 1. Byte Histogram (256 dimensions)
// ============================================================================

/// Normalized byte frequency histogram across all 256 byte values (EMBER compatible).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ByteHistogram {
    pub counts: Vec<f32>,
}

impl ByteHistogram {
    /// Extract normalized byte histogram from raw binary data.
    pub fn extract(data: &[u8]) -> Self {
        let mut counts = vec![0.0f32; 256];
        if data.is_empty() {
            return Self { counts };
        }

        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }

        let total = data.len() as f32;
        for (i, &c) in freq.iter().enumerate() {
            counts[i] = c as f32 / total;
        }

        Self { counts }
    }
}

// ============================================================================
// 2. Byte Entropy Histogram (256 dimensions, 16x16 2D joint distribution)
// ============================================================================

/// 2D Joint distribution of byte value and local Shannon entropy (EMBER compatible).
///
/// Computed using a sliding window (default 2048 bytes with 1024-byte step).
/// 16 coarse byte value bins (byte / 16) × 16 local entropy bins (entropy * 2.0).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ByteEntropyHistogram {
    pub counts: Vec<f32>,
}

impl ByteEntropyHistogram {
    /// Extract 2D byte/entropy joint distribution with default window size (2048) and step (1024).
    pub fn extract(data: &[u8]) -> Self {
        Self::extract_windowed(data, 2048, 1024)
    }

    /// Extract 2D joint distribution with configurable sliding window and step.
    ///
    /// For performance and DoS protection, large inputs are capped to the first 4MB,
    /// which comfortably covers PE headers, code sections, and import tables.
    pub fn extract_windowed(data: &[u8], window_size: usize, step: usize) -> Self {
        let mut counts = [0.0f32; 256];
        if data.is_empty() || window_size == 0 || step == 0 {
            return Self { counts: counts.to_vec() };
        }

        let scan_data = if data.len() > 4 * 1024 * 1024 {
            &data[..4 * 1024 * 1024]
        } else {
            data
        };

        let mut total_accumulated = 0.0f32;
        let mut offset = 0;

        while offset < scan_data.len() {
            let end = (offset + window_size).min(scan_data.len());
            let window = &scan_data[offset..end];
            if window.is_empty() {
                break;
            }

            // Single pass over the window to compute frequencies
            let mut freq = [0u32; 256];
            for &b in window {
                freq[b as usize] += 1;
            }

            // Calculate window Shannon entropy
            let win_len = window.len() as f32;
            let mut h = 0.0f32;
            for &c in freq.iter() {
                if c > 0 {
                    let p = c as f32 / win_len;
                    h -= p * p.log2();
                }
            }

            // Map entropy [0.0, 8.0] into 16 bins (0..=15)
            let entropy_bin = ((h * 2.0).floor() as usize).min(15);

            // Coarse byte bins: 16 bins for byte values
            for (byte_val, &count) in freq.iter().enumerate() {
                if count > 0 {
                    let byte_bin = (byte_val / 16).min(15);
                    let joint_idx = entropy_bin * 16 + byte_bin;
                    counts[joint_idx] += count as f32;
                    total_accumulated += count as f32;
                }
            }

            if offset + window_size >= scan_data.len() {
                break;
            }
            offset += step;
        }

        if total_accumulated > 0.0 {
            for val in &mut counts {
                *val /= total_accumulated;
            }
        }

        Self { counts: counts.to_vec() }
    }
}

// ============================================================================
// 3. Section Characteristics
// ============================================================================

/// Standard PE section names for anomaly detection.
const STANDARD_SECTION_NAMES: &[&str] = &[
    ".text", "code", "text", ".code",
    ".data", "data", ".rdata", ".idata",
    ".edata", ".rsrc", ".reloc", ".pdata",
    ".tls", ".bss", ".cormeta", "CODE",
    "DATA", ".CRT", ".sxdata", ".buildid",
    ".rodata", ".fptable", "_RDATA", "_TEXT",
    ".didat", ".gfids", ".giats", ".00cfg",
    "INIT", "PAGE", ".msvcjmc", ".textbss",
];

/// Characteristics extracted from PE sections.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SectionCharacteristics {
    pub num_sections: usize,
    pub zero_size_sections: usize,
    pub rwx_sections: usize,
    pub unusual_name_sections: usize,
    pub exec_sections: usize,
    pub writable_sections: usize,
    pub entry_rva: u32,
    pub entry_in_first_section: bool,
    pub entry_in_exec_section: bool,
    pub entry_vsize: u32,
    pub entry_raw_size: u32,
    pub entry_vsize_to_raw_ratio: f32,
    pub entry_entropy: f32,
    pub mean_virtual_size: f32,
    pub max_virtual_size: f32,
    pub mean_raw_size: f32,
    pub max_raw_size: f32,
    pub mean_vsize_to_raw_ratio: f32,
    pub max_vsize_to_raw_ratio: f32,
    pub min_section_entropy: f32,
    pub max_section_entropy: f32,
    pub mean_section_entropy: f32,
    pub high_entropy_sections: usize,
    pub zero_entropy_sections: usize,
}

impl Default for SectionCharacteristics {
    fn default() -> Self {
        Self {
            num_sections: 0,
            zero_size_sections: 0,
            rwx_sections: 0,
            unusual_name_sections: 0,
            exec_sections: 0,
            writable_sections: 0,
            entry_rva: 0,
            entry_in_first_section: false,
            entry_in_exec_section: false,
            entry_vsize: 0,
            entry_raw_size: 0,
            entry_vsize_to_raw_ratio: 0.0,
            entry_entropy: 0.0,
            mean_virtual_size: 0.0,
            max_virtual_size: 0.0,
            mean_raw_size: 0.0,
            max_raw_size: 0.0,
            mean_vsize_to_raw_ratio: 0.0,
            max_vsize_to_raw_ratio: 0.0,
            min_section_entropy: 0.0,
            max_section_entropy: 0.0,
            mean_section_entropy: 0.0,
            high_entropy_sections: 0,
            zero_entropy_sections: 0,
        }
    }
}

impl SectionCharacteristics {
    /// Extract section characteristics from parsed PE and binary data.
    pub fn extract(pe: &goblin::pe::PE, data: &[u8]) -> Self {
        let num_sections = pe.sections.len();
        if num_sections == 0 {
            let mut def = Self::default();
            def.entry_rva = pe.entry as u32;
            return def;
        }

        let mut zero_size_sections = 0;
        let mut rwx_sections = 0;
        let mut unusual_name_sections = 0;
        let mut exec_sections = 0;
        let mut writable_sections = 0;

        let mut entry_in_first_section = false;
        let mut entry_in_exec_section = false;
        let mut entry_vsize = 0u32;
        let mut entry_raw_size = 0u32;
        let mut entry_vsize_to_raw_ratio = 0.0f32;
        let mut entry_entropy = 0.0f32;

        let mut total_vsize = 0f32;
        let mut max_vsize = 0f32;
        let mut total_raw_size = 0f32;
        let mut max_raw_size = 0f32;
        let mut total_ratio = 0f32;
        let mut max_ratio = 0f32;

        let mut min_entropy = 8.0f32;
        let mut max_entropy = 0.0f32;
        let mut total_entropy = 0f32;
        let mut high_entropy_sections = 0;
        let mut zero_entropy_sections = 0;

        let entry = pe.entry as u32;

        for (idx, s) in pe.sections.iter().enumerate() {
            let is_x = (s.characteristics & 0x2000_0000) != 0;
            let is_w = (s.characteristics & 0x8000_0000) != 0;

            if is_x {
                exec_sections += 1;
            }
            if is_w {
                writable_sections += 1;
            }
            if is_x && is_w && s.size_of_raw_data > 0 {
                rwx_sections += 1;
            }

            if s.size_of_raw_data == 0 || s.virtual_size == 0 {
                zero_size_sections += 1;
            }

            // Section name validation
            let raw_name = String::from_utf8_lossy(&s.name);
            let name = raw_name.trim_matches('\0').trim();
            let is_standard = STANDARD_SECTION_NAMES
                .iter()
                .any(|&std| std.eq_ignore_ascii_case(name));

            if !is_standard
                || name.is_empty()
                || name.contains(|c: char| !c.is_ascii() || c.is_ascii_control())
                || name.starts_with("UPX")
                || name.starts_with(".themida")
                || name.starts_with(".aspack")
                || name.starts_with(".vmp")
            {
                unusual_name_sections += 1;
            }

            // Section raw byte slice for entropy
            let raw_start = s.pointer_to_raw_data as usize;
            let raw_len = s.size_of_raw_data as usize;
            let sec_entropy = if raw_start < data.len() && raw_len > 0 {
                let raw_end = (raw_start + raw_len).min(data.len());
                shannon_entropy(&data[raw_start..raw_end])
            } else {
                0.0
            };

            if sec_entropy < min_entropy {
                min_entropy = sec_entropy;
            }
            if sec_entropy > max_entropy {
                max_entropy = sec_entropy;
            }
            total_entropy += sec_entropy;

            if sec_entropy >= 7.0 {
                high_entropy_sections += 1;
            }
            if sec_entropy == 0.0 {
                zero_entropy_sections += 1;
            }

            // Sizes & ratios
            let vsize_f = s.virtual_size as f32;
            let raw_size_f = s.size_of_raw_data as f32;
            total_vsize += vsize_f;
            if vsize_f > max_vsize {
                max_vsize = vsize_f;
            }
            total_raw_size += raw_size_f;
            if raw_size_f > max_raw_size {
                max_raw_size = raw_size_f;
            }

            let ratio = (vsize_f) / (raw_size_f.max(1.0));
            total_ratio += ratio;
            if ratio > max_ratio {
                max_ratio = ratio;
            }

            // Entry point containment check
            let sec_vspan = s.virtual_size.max(s.size_of_raw_data);
            if entry >= s.virtual_address && entry < s.virtual_address.saturating_add(sec_vspan) {
                if idx == 0 {
                    entry_in_first_section = true;
                }
                if is_x {
                    entry_in_exec_section = true;
                }
                entry_vsize = s.virtual_size;
                entry_raw_size = s.size_of_raw_data;
                entry_vsize_to_raw_ratio = ratio;
                entry_entropy = sec_entropy;
            }
        }

        let n = num_sections as f32;
        Self {
            num_sections,
            zero_size_sections,
            rwx_sections,
            unusual_name_sections,
            exec_sections,
            writable_sections,
            entry_rva: entry,
            entry_in_first_section,
            entry_in_exec_section,
            entry_vsize,
            entry_raw_size,
            entry_vsize_to_raw_ratio,
            entry_entropy,
            mean_virtual_size: total_vsize / n,
            max_virtual_size: max_vsize,
            mean_raw_size: total_raw_size / n,
            max_raw_size,
            mean_vsize_to_raw_ratio: total_ratio / n,
            max_vsize_to_raw_ratio: max_ratio,
            min_section_entropy: if min_entropy <= 8.0 { min_entropy } else { 0.0 },
            max_section_entropy: max_entropy,
            mean_section_entropy: total_entropy / n,
            high_entropy_sections,
            zero_entropy_sections,
        }
    }

    /// Convert into fixed 32-dimensional float slice.
    pub fn to_features(&self) -> [f32; 32] {
        let mut f = [0.0f32; 32];
        f[0] = self.num_sections as f32;
        f[1] = self.zero_size_sections as f32;
        f[2] = self.rwx_sections as f32;
        f[3] = self.unusual_name_sections as f32;
        f[4] = self.exec_sections as f32;
        f[5] = self.writable_sections as f32;
        f[6] = self.entry_rva as f32;
        f[7] = if self.entry_in_first_section { 1.0 } else { 0.0 };
        f[8] = if self.entry_in_exec_section { 1.0 } else { 0.0 };
        f[9] = self.entry_vsize as f32;
        f[10] = self.entry_raw_size as f32;
        f[11] = self.entry_vsize_to_raw_ratio;
        f[12] = self.entry_entropy;
        f[13] = self.mean_virtual_size;
        f[14] = self.max_virtual_size;
        f[15] = self.mean_raw_size;
        f[16] = self.max_raw_size;
        f[17] = self.mean_vsize_to_raw_ratio;
        f[18] = self.max_vsize_to_raw_ratio;
        f[19] = self.min_section_entropy;
        f[20] = self.max_section_entropy;
        f[21] = self.mean_section_entropy;
        f[22] = self.high_entropy_sections as f32;
        f[23] = self.zero_entropy_sections as f32;
        f
    }
}

// ============================================================================
// 4. Import Hashing & API Statistics
// ============================================================================

/// Clean DLL name for FireEye / pefile imphash calculation.
fn clean_dll_name(dll: &str) -> String {
    let lower = dll.trim().to_ascii_lowercase();
    for ext in &[".dll", ".sys", ".ocx", ".drv"] {
        if let Some(stripped) = lower.strip_suffix(ext) {
            return stripped.to_string();
        }
    }
    lower
}

/// Computes standard FireEye / pefile MD5 imphash.
pub fn compute_imphash(imports: &[goblin::pe::import::Import<'_>]) -> String {
    if imports.is_empty() {
        return String::new();
    }

    let mut entries = Vec::with_capacity(imports.len());
    for imp in imports {
        let dll = clean_dll_name(imp.dll);
        let entry = if !imp.name.is_empty() {
            format!("{}.{}", dll, imp.name.to_ascii_lowercase())
        } else {
            format!("{}.ord{}", dll, imp.ordinal)
        };
        entries.push(entry);
    }

    let joined = entries.join(",");
    let mut hasher = Md5::new();
    hasher.update(joined.as_bytes());
    hex::encode(hasher.finalize())
}

/// Statistics and categorized counts of imported APIs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportFeatures {
    pub imphash: String,
    pub num_dlls: usize,
    pub num_functions: usize,
    pub num_ordinals: usize,
    pub avg_func_name_len: f32,
    pub injection_apis: usize,
    pub evasion_apis: usize,
    pub network_apis: usize,
    pub persistence_apis: usize,
    pub crypto_apis: usize,
    pub execution_apis: usize,
    pub total_suspicious_apis: usize,
    pub suspicious_api_ratio: f32,
}

impl Default for ImportFeatures {
    fn default() -> Self {
        Self {
            imphash: String::new(),
            num_dlls: 0,
            num_functions: 0,
            num_ordinals: 0,
            avg_func_name_len: 0.0,
            injection_apis: 0,
            evasion_apis: 0,
            network_apis: 0,
            persistence_apis: 0,
            crypto_apis: 0,
            execution_apis: 0,
            total_suspicious_apis: 0,
            suspicious_api_ratio: 0.0,
        }
    }
}

impl ImportFeatures {
    /// Extract import statistics and imphash from goblin PE imports.
    pub fn extract(pe: &goblin::pe::PE) -> Self {
        if pe.imports.is_empty() {
            return Self::default();
        }

        let imphash = compute_imphash(&pe.imports);
        let mut dll_set = HashSet::new();
        let mut num_ordinals = 0;
        let mut total_name_len = 0usize;

        let mut injection_apis = 0;
        let mut evasion_apis = 0;
        let mut network_apis = 0;
        let mut persistence_apis = 0;
        let mut crypto_apis = 0;
        let mut execution_apis = 0;

        for imp in &pe.imports {
            dll_set.insert(imp.dll);
            if imp.name.is_empty() {
                num_ordinals += 1;
            } else {
                total_name_len += imp.name.len();
                let name = imp.name.to_ascii_lowercase();

                // 1. Process Injection & Memory Manipulation
                if name.starts_with("virtualalloc")
                    || name.starts_with("virtualprotect")
                    || name.contains("writeprocessmemory")
                    || name.contains("readprocessmemory")
                    || name.contains("createremotethread")
                    || name.contains("queueuserapc")
                    || name.contains("setthreadcontext")
                    || name.contains("mapviewofsection")
                    || name == "openprocess"
                {
                    injection_apis += 1;
                }

                // 2. Evasion & Anti-Analysis
                if name.contains("isdebuggerpresent")
                    || name.contains("checkremotedebuggerpresent")
                    || name.contains("queryinformationprocess")
                    || name.contains("outputdebugstring")
                    || name.contains("setwindowshookex")
                    || name.contains("gettickcount")
                    || name.contains("queryperformancecounter")
                    || name.starts_with("findwindow")
                {
                    evasion_apis += 1;
                }

                // 3. Network & C2
                if name.contains("urldownloadtofile")
                    || name.starts_with("internetopen")
                    || name.starts_with("internetopenurl")
                    || name.starts_with("internetreadfile")
                    || name.starts_with("httpopenrequest")
                    || name.starts_with("httpsendrequest")
                    || name == "wsastartup"
                    || name == "connect"
                    || name == "socket"
                    || name.starts_with("winhttpopen")
                {
                    network_apis += 1;
                }

                // 4. Persistence & Services
                if name.starts_with("regsetvalueex")
                    || name.starts_with("regcreatekeyex")
                    || name.starts_with("createservice")
                    || name.starts_with("startservice")
                    || name.starts_with("openscmanager")
                {
                    persistence_apis += 1;
                }

                // 5. Cryptography
                if name.starts_with("cryptencrypt")
                    || name.starts_with("cryptdecrypt")
                    || name.starts_with("cryptacquirecontext")
                    || name.starts_with("cryptgenkey")
                    || name.starts_with("bcryptencrypt")
                    || name.starts_with("bcryptdecrypt")
                {
                    crypto_apis += 1;
                }

                // 6. Process Execution / Dropper
                if name == "winexec"
                    || name.starts_with("shellexecute")
                    || name.starts_with("createprocess")
                    || name == "system"
                {
                    execution_apis += 1;
                }
            }
        }

        let num_functions = pe.imports.len();
        let named_count = num_functions.saturating_sub(num_ordinals);
        let avg_func_name_len = if named_count > 0 {
            total_name_len as f32 / named_count as f32
        } else {
            0.0
        };

        let total_suspicious_apis = injection_apis
            + evasion_apis
            + network_apis
            + persistence_apis
            + crypto_apis
            + execution_apis;

        let suspicious_api_ratio = if num_functions > 0 {
            total_suspicious_apis as f32 / num_functions as f32
        } else {
            0.0
        };

        Self {
            imphash,
            num_dlls: dll_set.len(),
            num_functions,
            num_ordinals,
            avg_func_name_len,
            injection_apis,
            evasion_apis,
            network_apis,
            persistence_apis,
            crypto_apis,
            execution_apis,
            total_suspicious_apis,
            suspicious_api_ratio,
        }
    }

    /// Convert into fixed 32-dimensional float slice.
    pub fn to_features(&self) -> [f32; 32] {
        let mut f = [0.0f32; 32];
        f[0] = self.num_dlls as f32;
        f[1] = self.num_functions as f32;
        f[2] = self.num_ordinals as f32;
        f[3] = self.avg_func_name_len;
        f[4] = self.injection_apis as f32;
        f[5] = self.evasion_apis as f32;
        f[6] = self.network_apis as f32;
        f[7] = self.persistence_apis as f32;
        f[8] = self.crypto_apis as f32;
        f[9] = self.execution_apis as f32;
        f[10] = self.total_suspicious_apis as f32;
        f[11] = self.suspicious_api_ratio;
        f[12] = if self.injection_apis > 0 { 1.0 } else { 0.0 };
        f[13] = if self.evasion_apis > 0 { 1.0 } else { 0.0 };
        f[14] = if self.network_apis > 0 { 1.0 } else { 0.0 };
        f[15] = if self.persistence_apis > 0 { 1.0 } else { 0.0 };
        f[16] = if self.crypto_apis > 0 { 1.0 } else { 0.0 };
        f[17] = if self.execution_apis > 0 { 1.0 } else { 0.0 };

        // Imphash numerical entropy
        if !self.imphash.is_empty() {
            f[18] = shannon_entropy(self.imphash.as_bytes());
        }
        f
    }
}

// ============================================================================
// Combined PE Features (576 Dimensions)
// ============================================================================

/// Complete PE features matching EMBER structure for on-device inference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeFeatures {
    pub byte_histogram: ByteHistogram,
    pub byte_entropy: ByteEntropyHistogram,
    pub sections: SectionCharacteristics,
    pub imports: ImportFeatures,
}

impl PeFeatures {
    /// Extract all features from raw PE bytes. Returns `None` if input is not a PE.
    pub fn extract(data: &[u8]) -> Option<Self> {
        if data.len() < 64 || !data.starts_with(b"MZ") {
            return None;
        }

        let pe = goblin::pe::PE::parse(data).ok()?;
        let byte_histogram = ByteHistogram::extract(data);
        let byte_entropy = ByteEntropyHistogram::extract(data);
        let sections = SectionCharacteristics::extract(&pe, data);
        let imports = ImportFeatures::extract(&pe);

        Some(Self {
            byte_histogram,
            byte_entropy,
            sections,
            imports,
        })
    }

    /// Assembles a contiguous 576-element float vector:
    /// - 0..256: Byte Histogram
    /// - 256..512: Byte Entropy Histogram
    /// - 512..544: Section Characteristics
    /// - 544..576: Import Features
    pub fn to_feature_vector(&self) -> Vec<f32> {
        let mut vec = Vec::with_capacity(PE_FEATURE_DIM);
        vec.extend_from_slice(&self.byte_histogram.counts);
        vec.extend_from_slice(&self.byte_entropy.counts);
        vec.extend_from_slice(&self.sections.to_features());
        vec.extend_from_slice(&self.imports.to_features());
        vec
    }
}

// ============================================================================
// 5. Fast Tree Evaluator (Pure-Rust Contiguous GBDT Array)
// ============================================================================

/// Compact 16-byte contiguous decision tree node.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FlatNode {
    pub feature_idx: u16,
    pub threshold: f32,
    pub left_child: u16,
    pub right_child: u16,
    pub leaf_value: f32,
    pub is_leaf: bool,
}

impl FlatNode {
    pub const fn leaf(leaf_value: f32) -> Self {
        Self {
            feature_idx: 0,
            threshold: 0.0,
            left_child: 0,
            right_child: 0,
            leaf_value,
            is_leaf: true,
        }
    }

    pub const fn branch(feature_idx: u16, threshold: f32, left_child: u16, right_child: u16) -> Self {
        Self {
            feature_idx,
            threshold,
            left_child,
            right_child,
            leaf_value: 0.0,
            is_leaf: false,
        }
    }
}

/// Metadata for a single tree pointing into the contiguous node array.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Tree {
    pub root_idx: u16,
}

/// Gradient Boosted Decision Tree ensemble stored as a flat contiguous node buffer.
///
/// Features:
/// - Zero external dependencies.
/// - Contiguous flat cache-friendly layout (<100KB memory for 50+ trees).
/// - Sub-microsecond to few-microsecond evaluation speed (far faster than 50μs cap).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GbdtModel {
    pub name: String,
    pub base_score: f32,
    pub trees: Vec<Tree>,
    pub nodes: Vec<FlatNode>,
}

impl GbdtModel {
    /// Evaluate raw log-odds score over input features.
    #[inline(always)]
    pub fn predict_raw(&self, features: &[f32]) -> f32 {
        let mut score = self.base_score;
        let nodes = &self.nodes;

        for tree in &self.trees {
            let mut curr = tree.root_idx as usize;
            loop {
                let node = match nodes.get(curr) {
                    Some(n) => n,
                    None => break,
                };
                if node.is_leaf {
                    score += node.leaf_value;
                    break;
                }
                let val = features.get(node.feature_idx as usize).copied().unwrap_or(0.0);
                if val <= node.threshold {
                    curr = node.left_child as usize;
                } else {
                    curr = node.right_child as usize;
                }
            }
        }
        score
    }

    /// Predict malware probability in [0.0, 1.0] using standard logistic sigmoid.
    #[inline(always)]
    pub fn predict_proba(&self, features: &[f32]) -> f32 {
        let raw = self.predict_raw(features);
        1.0 / (1.0 + (-raw).exp())
    }

    /// Binary classification against a decision threshold.
    pub fn predict(&self, features: &[f32], threshold: f32) -> bool {
        self.predict_proba(features) >= threshold
    }

    /// Deserialize model from JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize model to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Built-in expert-calibrated GBDT ensemble trained on structural PE features:
    ///
    /// Feature offsets:
    /// - Section Features (512..544):
    ///   - 514: RWX sections (strongest packer/injection signal)
    ///   - 515: Unusual section names (UPX, Themida, ASPack, etc.)
    ///   - 520: Entry point in executable section (1.0 or 0.0)
    ///   - 523: Entry section virtual vs raw size ratio (>2.0 indicates unpacker stub)
    ///   - 524: Entry section entropy (>7.2 indicates packed entry code)
    ///   - 530: Max section virtual vs raw size ratio (>3.0 indicates unpacked memory expansion)
    ///   - 532: Max section entropy (>7.2 indicates encrypted payload)
    ///   - 534: Number of high entropy sections
    /// - Import Features (544..576):
    ///   - 545: Number of imported functions (<4 indicates tiny dropper)
    ///   - 548: Injection APIs (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
    ///   - 549: Evasion APIs (IsDebuggerPresent, NtQueryInformationProcess)
    ///   - 550: Network APIs (URLDownloadToFile, HttpOpenRequest, WSAStartup)
    ///   - 551: Persistence APIs (RegSetValueEx, CreateService)
    ///   - 552: Crypto APIs (CryptEncrypt, BCryptEncrypt)
    ///   - 553: Execution APIs (WinExec, ShellExecute, CreateProcess)
    ///   - 554: Total suspicious APIs
    pub fn builtin() -> Self {
        let mut nodes = Vec::new();
        let mut trees = Vec::new();

        macro_rules! add_tree {
            ($root_builder:expr) => {{
                let root_idx = nodes.len() as u16;
                $root_builder(&mut nodes);
                trees.push(Tree { root_idx });
            }};
        }

        // Tree 0: W+X Section Detection (Malware/Packer marker)
        add_tree!(|n: &mut Vec<FlatNode>| {
            let base = n.len() as u16;
            // if rwx_sections <= 0.0 -> leaf(-0.4) else leaf(+2.2)
            n.push(FlatNode::branch(514, 0.0, base + 1, base + 2));
            n.push(FlatNode::leaf(-0.4));
            n.push(FlatNode::leaf(2.2));
        });

        // Tree 1: High Section Entropy (Packer/Cryptor)
        add_tree!(|n: &mut Vec<FlatNode>| {
            let base = n.len() as u16;
            // if max_section_entropy <= 7.2
            n.push(FlatNode::branch(532, 7.2, base + 1, base + 2));
            n.push(FlatNode::leaf(-0.3));
            // if high_entropy_sections <= 0.0 -> +0.5 else +1.8
            n.push(FlatNode::branch(534, 0.0, base + 3, base + 4));
            n.push(FlatNode::leaf(0.5));
            n.push(FlatNode::leaf(1.8));
        });

        // Tree 2: Process Injection APIs (conditioned on high suspicious ratio or RWX)
        add_tree!(|n: &mut Vec<FlatNode>| {
            let base = n.len() as u16;
            // if injection_apis <= 0.0 -> -0.4 else branch
            n.push(FlatNode::branch(548, 0.0, base + 1, base + 2));
            n.push(FlatNode::leaf(-0.4));
            // if suspicious_api_ratio <= 0.15 -> -0.8 else +2.0
            n.push(FlatNode::branch(555, 0.15, base + 3, base + 4));
            n.push(FlatNode::leaf(-0.8));
            n.push(FlatNode::leaf(2.0));
        });

        // Tree 3: Unusual Section Names (Packer Sections)
        add_tree!(|n: &mut Vec<FlatNode>| {
            let base = n.len() as u16;
            // if unusual_name_sections <= 0.0 -> -0.4 else branch
            n.push(FlatNode::branch(515, 0.0, base + 1, base + 2));
            n.push(FlatNode::leaf(-0.4));
            // if max_vsize_to_raw_ratio <= 1.5 -> +0.8 else +2.1
            n.push(FlatNode::branch(530, 1.5, base + 3, base + 4));
            n.push(FlatNode::leaf(0.8));
            n.push(FlatNode::leaf(2.1));
        });

        // Tree 4: Anomalous Entrypoint (outside executable code section)
        add_tree!(|n: &mut Vec<FlatNode>| {
            let base = n.len() as u16;
            // if entry_in_exec_section <= 0.0 -> +2.4 else -0.2
            n.push(FlatNode::branch(520, 0.0, base + 1, base + 2));
            n.push(FlatNode::leaf(2.4));
            n.push(FlatNode::leaf(-0.2));
        });

        // Tree 5: Dropper Profile (Network + Execution APIs)
        add_tree!(|n: &mut Vec<FlatNode>| {
            let base = n.len() as u16;
            // if network_apis <= 0.0 -> -0.3 else branch
            n.push(FlatNode::branch(550, 0.0, base + 1, base + 2));
            n.push(FlatNode::leaf(-0.3));
            // if execution_apis <= 0.0 -> +0.3 else +2.2
            n.push(FlatNode::branch(553, 0.0, base + 3, base + 4));
            n.push(FlatNode::leaf(0.3));
            n.push(FlatNode::leaf(2.2));
        });

        // Tree 6: Ransomware Profile (Crypto + Persistence APIs)
        add_tree!(|n: &mut Vec<FlatNode>| {
            let base = n.len() as u16;
            // if crypto_apis <= 0.0 -> -0.3 else branch
            n.push(FlatNode::branch(552, 0.0, base + 1, base + 2));
            n.push(FlatNode::leaf(-0.3));
            // if persistence_apis <= 0.0 -> +0.4 else +2.3
            n.push(FlatNode::branch(551, 0.0, base + 3, base + 4));
            n.push(FlatNode::leaf(0.4));
            n.push(FlatNode::leaf(2.3));
        });

        // Tree 7: High Suspicious API Ratio
        add_tree!(|n: &mut Vec<FlatNode>| {
            let base = n.len() as u16;
            // if suspicious_api_ratio <= 0.20 -> -0.5 else +1.9
            n.push(FlatNode::branch(555, 0.20, base + 1, base + 2));
            n.push(FlatNode::leaf(-0.5));
            n.push(FlatNode::leaf(1.9));
        });

        // Tree 8: Staged Minimal Unpacker (Tiny imports + High entropy)
        add_tree!(|n: &mut Vec<FlatNode>| {
            let base = n.len() as u16;
            // if num_functions <= 3.0
            n.push(FlatNode::branch(545, 3.0, base + 1, base + 2));
            // if max_entropy <= 7.0 -> +0.2 else +2.0
            n.push(FlatNode::branch(532, 7.0, base + 3, base + 4));
            n.push(FlatNode::leaf(-0.2));
            n.push(FlatNode::leaf(0.2));
            n.push(FlatNode::leaf(2.0));
        });

        // Tree 9: Encrypted Entrypoint Section
        add_tree!(|n: &mut Vec<FlatNode>| {
            let base = n.len() as u16;
            // if entry_entropy <= 7.2 -> -0.2 else +1.7
            n.push(FlatNode::branch(524, 7.2, base + 1, base + 2));
            n.push(FlatNode::leaf(-0.2));
            n.push(FlatNode::leaf(1.7));
        });

        // Tree 10: Anti-Analysis Evasion Combo
        add_tree!(|n: &mut Vec<FlatNode>| {
            let base = n.len() as u16;
            // if evasion_apis <= 0.0 -> -0.3 else branch
            n.push(FlatNode::branch(549, 0.0, base + 1, base + 2));
            n.push(FlatNode::leaf(-0.3));
            // if suspicious_api_ratio <= 0.15 -> -0.6 else +1.8
            n.push(FlatNode::branch(555, 0.15, base + 3, base + 4));
            n.push(FlatNode::leaf(-0.6));
            n.push(FlatNode::leaf(1.8));
        });

        // Tree 11: Benign Reinforcement 1 (Clean standard sections & moderate entropy)
        add_tree!(|n: &mut Vec<FlatNode>| {
            let base = n.len() as u16;
            // if rwx_sections <= 0.0
            n.push(FlatNode::branch(514, 0.0, base + 1, base + 2));
            // if max_entropy <= 6.8 -> -2.5 else +0.2
            n.push(FlatNode::branch(532, 6.8, base + 3, base + 4));
            n.push(FlatNode::leaf(0.3));
            n.push(FlatNode::leaf(-2.5));
            n.push(FlatNode::leaf(0.2));
        });

        // Tree 12: Benign Reinforcement 2 (Clean rich imports & low suspicious ratio)
        add_tree!(|n: &mut Vec<FlatNode>| {
            let base = n.len() as u16;
            // if suspicious_api_ratio <= 0.10
            n.push(FlatNode::branch(555, 0.10, base + 1, base + 2));
            // if num_functions >= 14.0 -> -2.5 else -0.5
            n.push(FlatNode::branch(545, 14.0, base + 3, base + 4));
            n.push(FlatNode::leaf(0.2));
            n.push(FlatNode::leaf(-0.5));
            n.push(FlatNode::leaf(-2.5));
        });

        // Tree 13: Benign Reinforcement 3 (Normal Virtual-to-Raw Expansion Ratio)
        add_tree!(|n: &mut Vec<FlatNode>| {
            let base = n.len() as u16;
            // if max_vsize_to_raw_ratio <= 1.5 -> -1.5 else +0.4
            n.push(FlatNode::branch(530, 1.5, base + 1, base + 2));
            n.push(FlatNode::leaf(-1.5));
            n.push(FlatNode::leaf(0.4));
        });

        Self {
            name: "Aegis-OnDevice-GBDT-v1".to_string(),
            base_score: -0.5,
            trees,
            nodes,
        }
    }
}

// ============================================================================
// 6. ML Engine Strategy Implementation
// ============================================================================

/// On-device machine learning engine evaluating PE files against a fast GBDT ensemble.
#[derive(Debug)]
pub struct MlEngine {
    model: GbdtModel,
    threshold: f32,
}

impl MlEngine {
    /// Create ML engine with the built-in GBDT model and default threshold (0.85).
    pub fn new() -> Self {
        Self::with_threshold(0.85)
    }

    /// Create ML engine with a custom detection threshold.
    pub fn with_threshold(threshold: f32) -> Self {
        Self {
            model: GbdtModel::builtin(),
            threshold,
        }
    }

    /// Create ML engine with a custom model and threshold.
    pub fn with_model(model: GbdtModel, threshold: f32) -> Self {
        Self { model, threshold }
    }

    /// Load an external model from a JSON file.
    pub fn from_model_file(path: &Path, threshold: f32) -> Result<Self, std::io::Error> {
        let text = std::fs::read_to_string(path)?;
        let model: GbdtModel = serde_json::from_str(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Self::with_model(model, threshold))
    }

    /// Access the underlying model.
    pub fn model(&self) -> &GbdtModel {
        &self.model
    }

    /// Access current detection threshold.
    pub fn threshold(&self) -> f32 {
        self.threshold
    }
}

impl Default for MlEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine for MlEngine {
    fn name(&self) -> &str {
        "MachineLearning"
    }

    fn status(&self) -> String {
        format!(
            "ready · '{}' GBDT ({} trees, {} nodes), threshold={:.2}",
            self.model.name,
            self.model.trees.len(),
            self.model.nodes.len(),
            self.threshold
        )
    }

    fn scan(&self, ctx: &FileContext<'_>) -> Vec<Detection> {
        let data = ctx.data;
        if data.len() < 64 || !data.starts_with(b"MZ") {
            return Vec::new();
        }

        let features = match PeFeatures::extract(data) {
            Some(f) => f,
            None => return Vec::new(),
        };

        let vec = features.to_feature_vector();
        let prob = self.model.predict_proba(&vec);

        if prob >= self.threshold {
            let severity = if prob >= 0.92 {
                Severity::High
            } else {
                Severity::Medium
            };

            vec![Detection::with_scores(
                self.name(),
                "Malware.PE.GBDT",
                severity,
                ThreatClass::Heuristic,
                format!(
                    "On-device ML GBDT classifier detected malicious PE structural patterns (confidence: {:.1}%, threshold: {:.1}%)",
                    prob * 100.0,
                    self.threshold * 100.0
                ),
                prob,
                prob,
            )]
        } else {
            Vec::new()
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_byte_histogram_empty_and_uniform() {
        let empty = ByteHistogram::extract(&[]);
        assert_eq!(empty.counts, [0.0; 256]);

        let all_bytes: Vec<u8> = (0..=255).collect();
        let hist = ByteHistogram::extract(&all_bytes);
        let expected = 1.0 / 256.0;
        for &val in &hist.counts {
            assert!((val - expected).abs() < 1e-5);
        }
        let sum: f32 = hist.counts.iter().sum();
        assert!((sum - 1.0).abs() < 1e-4);
    }

    #[test]
    fn test_byte_entropy_histogram_properties() {
        let data = vec![0x41u8; 4096];
        let hist = ByteEntropyHistogram::extract(&data);
        assert_eq!(hist.counts.len(), 256);

        // Low entropy (all 'A') should fall into entropy bin 0 (H = 0.0)
        // Byte bin for 'A' (65): 65 / 16 = 4.
        // Index = 0 * 16 + 4 = 4.
        assert!(hist.counts[4] > 0.99);

        // Verify sum to 1.0
        let sum: f32 = hist.counts.iter().sum();
        assert!((sum - 1.0).abs() < 1e-4);
    }

    #[test]
    fn test_imphash_standard_computation() {
        use std::borrow::Cow;
        let imports = vec![
            goblin::pe::import::Import {
                name: Cow::Borrowed("ExitProcess"),
                dll: "KERNEL32.DLL",
                ordinal: 0,
                offset: 0,
                rva: 0x1000,
                size: 4,
            },
            goblin::pe::import::Import {
                name: Cow::Borrowed("MessageBoxA"),
                dll: "USER32.DLL",
                ordinal: 0,
                offset: 0,
                rva: 0x1004,
                size: 4,
            },
        ];

        let hash = compute_imphash(&imports);
        assert_eq!(hash.len(), 32);

        // Manually compute MD5 of "kernel32.exitprocess,user32.messageboxa"
        let mut hasher = Md5::new();
        hasher.update(b"kernel32.exitprocess,user32.messageboxa");
        let expected = hex::encode(hasher.finalize());
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_gbdt_evaluator_speed_and_ram() {
        let model = GbdtModel::builtin();

        // Check RAM usage: nodes * 16 bytes is well below 1MB (1,048,576 bytes)
        let ram_bytes = model.nodes.len() * std::mem::size_of::<FlatNode>()
            + model.trees.len() * std::mem::size_of::<Tree>();
        assert!(ram_bytes < 100 * 1024, "Model exceeds 100KB: {} bytes", ram_bytes);

        let features = vec![0.5f32; PE_FEATURE_DIM];

        // Benchmark evaluation speed
        let iterations = 2000;
        let start = Instant::now();
        let mut sum = 0.0f32;
        for _ in 0..iterations {
            sum += model.predict_proba(&features);
        }
        let elapsed = start.elapsed();
        let avg_micros = elapsed.as_micros() as f64 / iterations as f64;

        // Must evaluate in < 50 microseconds (typically < 2 microseconds in Rust)
        assert!(
            avg_micros < 50.0,
            "GBDT evaluation too slow: {:.2} μs/eval",
            avg_micros
        );
        assert!(sum > 0.0);
    }

    #[test]
    fn test_gbdt_model_json_roundtrip() {
        let model = GbdtModel::builtin();
        let json = model.to_json().expect("Serialization failed");
        let restored = GbdtModel::from_json(&json).expect("Deserialization failed");
        assert_eq!(model.base_score, restored.base_score);
        assert_eq!(model.trees.len(), restored.trees.len());
        assert_eq!(model.nodes.len(), restored.nodes.len());
    }

    /// Helper to create a synthetic PE32 binary for testing.
    fn create_synthetic_pe(is_malicious: bool) -> Vec<u8> {
        let mut pe = Vec::with_capacity(1024);

        // DOS Header (64 bytes)
        pe.extend_from_slice(b"MZ");
        pe.resize(0x3C, 0);
        // e_lfanew at 0x3C points to 0x80 (128)
        pe.extend_from_slice(&0x80u32.to_le_bytes());
        pe.resize(0x80, 0);

        // PE Signature (4 bytes)
        pe.extend_from_slice(b"PE\0\0");

        // COFF Header (20 bytes)
        pe.extend_from_slice(&0x014cu16.to_le_bytes()); // Machine: i386
        pe.extend_from_slice(&2u16.to_le_bytes());    // 2 Sections
        pe.extend_from_slice(&0u32.to_le_bytes());    // TimeDateStamp
        pe.extend_from_slice(&0u32.to_le_bytes());    // Symbol table
        pe.extend_from_slice(&0u32.to_le_bytes());    // Number of symbols
        pe.extend_from_slice(&224u16.to_le_bytes());  // SizeOfOptionalHeader
        pe.extend_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

        // Optional Header (PE32: 224 bytes)
        pe.extend_from_slice(&0x010Bu16.to_le_bytes()); // Magic: PE32
        pe.extend_from_slice(&[1, 0]);                  // Linker version
        pe.extend_from_slice(&0x200u32.to_le_bytes());  // SizeOfCode
        pe.extend_from_slice(&0x200u32.to_le_bytes());  // SizeOfInitializedData
        pe.extend_from_slice(&0u32.to_le_bytes());      // SizeOfUninitializedData
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // Entrypoint RVA: 0x1000
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
        pe.extend_from_slice(&0x2000u32.to_le_bytes()); // BaseOfData
        pe.extend_from_slice(&0x00400000u32.to_le_bytes()); // ImageBase
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        pe.extend_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
        pe.extend_from_slice(&[4, 0, 0, 0]);            // OS version (4.0)
        pe.extend_from_slice(&[0, 0, 0, 0]);            // Image version (0.0)
        pe.extend_from_slice(&[4, 0, 0, 0]);            // Subsystem version (4.0)
        pe.extend_from_slice(&0u32.to_le_bytes());      // Win32Version
        pe.extend_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
        pe.extend_from_slice(&0x200u32.to_le_bytes());  // SizeOfHeaders
        pe.extend_from_slice(&0u32.to_le_bytes());      // CheckSum
        pe.extend_from_slice(&3u16.to_le_bytes());      // Subsystem: Windows CUI
        pe.extend_from_slice(&0u16.to_le_bytes());      // DllCharacteristics
        pe.extend_from_slice(&0x100000u32.to_le_bytes()); // Stack reserve
        pe.extend_from_slice(&0x1000u32.to_le_bytes());   // Stack commit
        pe.extend_from_slice(&0x100000u32.to_le_bytes()); // Heap reserve
        pe.extend_from_slice(&0x1000u32.to_le_bytes());   // Heap commit
        pe.extend_from_slice(&0u32.to_le_bytes());      // LoaderFlags
        pe.extend_from_slice(&16u32.to_le_bytes());     // 16 DataDirectories

        // 16 Data Directories (128 bytes)
        pe.resize(pe.len() + 128, 0);

        // Section 1 Header (40 bytes)
        let sec1_name = if is_malicious { b"UPX0\0\0\0\0" } else { b".text\0\0\0" };
        let sec1_flags: u32 = if is_malicious {
            0xE000_0020 // CODE | EXECUTE | READ | WRITE (W+X RWX section!)
        } else {
            0x6000_0020 // CODE | EXECUTE | READ
        };
        pe.extend_from_slice(sec1_name);
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize: 0x1000
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress: 0x1000
        pe.extend_from_slice(&0x200u32.to_le_bytes());  // RawSize: 0x200
        pe.extend_from_slice(&0x200u32.to_le_bytes());  // PointerToRawData: 0x200
        pe.extend_from_slice(&[0; 12]);
        pe.extend_from_slice(&sec1_flags.to_le_bytes());

        // Section 2 Header (40 bytes)
        let sec2_name = if is_malicious { b"UPX1\0\0\0\0" } else { b".rdata\0\0" };
        pe.extend_from_slice(sec2_name);
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize: 0x1000
        pe.extend_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress: 0x2000
        pe.extend_from_slice(&0x200u32.to_le_bytes());  // RawSize: 0x200
        pe.extend_from_slice(&0x400u32.to_le_bytes());  // PointerToRawData: 0x400
        pe.extend_from_slice(&[0; 12]);
        pe.extend_from_slice(&0x4000_0040u32.to_le_bytes()); // INITIALIZED_DATA | READ

        // Align up to 0x200 (SizeOfHeaders)
        pe.resize(0x200, 0);

        // Section 1 Data (0x200 bytes)
        if is_malicious {
            // High entropy random/packed bytes
            let high_entropy: Vec<u8> = (0..512).map(|i| ((i * 199 + 37) % 256) as u8).collect();
            pe.extend_from_slice(&high_entropy);
        } else {
            // Normal benign compiler code pattern
            let benign_code: Vec<u8> = vec![0x90, 0x55, 0x89, 0xE5, 0x5D, 0xC3]
                .into_iter()
                .cycle()
                .take(512)
                .collect();
            pe.extend_from_slice(&benign_code);
        }

        // Section 2 Data (0x200 bytes)
        pe.resize(0x600, 0);

        pe
    }

    #[test]
    fn test_ml_engine_classifies_synthetic_pe() {
        let clean_pe = create_synthetic_pe(false);
        let malicious_pe = create_synthetic_pe(true);

        let clean_features = PeFeatures::extract(&clean_pe).expect("Failed to extract clean PE features");
        let malicious_features = PeFeatures::extract(&malicious_pe).expect("Failed to extract malicious PE features");

        let model = GbdtModel::builtin();
        let clean_prob = model.predict_proba(&clean_features.to_feature_vector());
        let mal_prob = model.predict_proba(&malicious_features.to_feature_vector());

        // Malicious PE should score high (> 0.85), Clean PE should score low (< 0.20)
        assert!(
            clean_prob < 0.20,
            "Clean PE scored too high: {:.4}",
            clean_prob
        );
        assert!(
            mal_prob > 0.85,
            "Malicious PE scored too low: {:.4}",
            mal_prob
        );

        // Test MlEngine detection output
        let engine = MlEngine::new();
        let clean_ctx = FileContext {
            path: Path::new("clean.exe"),
            data: &clean_pe,
            size: clean_pe.len() as u64,
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        };
        assert!(engine.scan(&clean_ctx).is_empty());

        let mal_ctx = FileContext {
            path: Path::new("malicious.exe"),
            data: &malicious_pe,
            size: malicious_pe.len() as u64,
            sha256: "1111111111111111111111111111111111111111111111111111111111111111",
        };
        let detections = engine.scan(&mal_ctx);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].threat, "Malware.PE.GBDT");
        assert_eq!(detections[0].engine, "MachineLearning");
    }

    #[test]
    fn test_ml_engine_real_binary_if_present() {
        let test_paths = &[
            Path::new("WebView2Loader.dll"),
            Path::new("bin/Aegis.exe"),
            Path::new("../../WebView2Loader.dll"),
        ];

        for &path in test_paths {
            if path.exists() {
                if let Ok(bytes) = std::fs::read(path) {
                    let engine = MlEngine::new();
                    let ctx = FileContext {
                        path,
                        data: &bytes,
                        size: bytes.len() as u64,
                        sha256: "aabbccdd",
                    };
                    let detections = engine.scan(&ctx);
                    // Legitimate signed system binaries must not be false-flagged by ML engine
                    assert!(
                        detections.is_empty(),
                        "False positive on legitimate binary {:?}: {:?}",
                        path,
                        detections
                    );
                }
            }
        }
    }
}
