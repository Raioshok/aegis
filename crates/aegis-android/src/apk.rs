use crate::dex::{DexAnalysis, DexScanner};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkReport {
    pub filename: String,
    pub package_name: Option<String>,
    pub sha256: String,
    pub size_bytes: u64,
    pub dangerous_permissions: Vec<String>,
    pub total_permissions: usize,
    pub dex_analyses: Vec<DexAnalysis>,
    pub threats: Vec<String>,
    pub overall_risk_score: u32,
    pub verdict: String,
}

pub struct ApkScanner;

impl ApkScanner {
    /// Scan an APK file buffer or zip archive.
    pub fn scan_bytes(filename: &str, data: &[u8]) -> Result<ApkReport, String> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = format!("{:x}", hasher.finalize());

        let reader = std::io::Cursor::new(data);
        let mut zip = zip::ZipArchive::new(reader).map_err(|e| format!("Invalid APK/ZIP archive: {e}"))?;

        let mut dangerous_perms = Vec::new();
        let mut all_perms = Vec::new();
        let mut package_name = None;
        let mut dex_analyses = Vec::new();
        let mut threats = Vec::new();
        let mut risk_score: u32 = 0;

        // 1. Inspect AndroidManifest.xml string table
        if let Ok(mut manifest_file) = zip.by_name("AndroidManifest.xml") {
            let mut manifest_bytes = Vec::new();
            if manifest_file.read_to_end(&mut manifest_bytes).is_ok() {
                let manifest_lossy = String::from_utf8_lossy(&manifest_bytes);
                let perms_to_check = [
                    ("android.permission.SEND_SMS", "Send unauthorized premium SMS", 25),
                    ("android.permission.RECEIVE_SMS", "Intercept incoming SMS / 2FA codes", 25),
                    ("android.permission.READ_SMS", "Read private SMS conversations", 20),
                    ("android.permission.SYSTEM_ALERT_WINDOW", "Display deceptive overlay windows over banking apps", 25),
                    ("android.permission.BIND_ACCESSIBILITY_SERVICE", "Capture keystrokes and execute background actions", 35),
                    ("android.permission.RECEIVE_BOOT_COMPLETED", "Auto-start persistence on device boot", 10),
                    ("android.permission.REQUEST_INSTALL_PACKAGES", "Silently download and prompt dropper APKs", 20),
                    ("android.permission.BIND_DEVICE_ADMIN", "Acquire Device Administration lock rights", 30),
                    ("android.permission.QUERY_ALL_PACKAGES", "Enumerate all installed financial & crypto apps", 15),
                    ("android.permission.RECORD_AUDIO", "Eavesdrop via microphone", 15),
                ];

                for (perm, desc, weight) in perms_to_check {
                    if manifest_lossy.contains(perm) {
                        dangerous_perms.push(format!("{perm} ({desc})"));
                        all_perms.push(perm.to_string());
                        risk_score += weight;
                    }
                }

                // Try to extract package name heuristic
                if let Some(pos) = manifest_lossy.find("package\0") {
                    let sub = &manifest_lossy[pos + 8..];
                    if let Some(end) = sub.find('\0') {
                        let name = sub[..end].trim();
                        if !name.is_empty() && name.contains('.') {
                            package_name = Some(name.to_string());
                        }
                    }
                }
            }
        }

        // 2. Inspect classes*.dex code streams
        for i in 0..zip.len() {
            if let Ok(mut entry) = zip.by_index(i) {
                let name = entry.name().to_string();
                if name.ends_with(".dex") {
                    let mut dex_bytes = Vec::new();
                    if entry.read_to_end(&mut dex_bytes).is_ok() {
                        let analysis = DexScanner::scan(&dex_bytes);
                        risk_score = risk_score.max(analysis.risk_score);
                        for ind in &analysis.detected_indicators {
                            if !threats.contains(ind) {
                                threats.push(ind.clone());
                            }
                        }
                        dex_analyses.push(analysis);
                    }
                }
            }
        }

        // Correlate banking trojan permissions combo:
        // Accessibility + Overlay + SMS / QueryAllPackages = Definite Banking Trojan
        let has_accessibility = all_perms.iter().any(|p| p.contains("ACCESSIBILITY"));
        let has_overlay = all_perms.iter().any(|p| p.contains("SYSTEM_ALERT_WINDOW"));
        let has_sms = all_perms.iter().any(|p| p.contains("SMS"));
        let has_query_all = all_perms.iter().any(|p| p.contains("QUERY_ALL_PACKAGES"));
        let has_device_admin = all_perms.iter().any(|p| p.contains("BIND_DEVICE_ADMIN"));

        if has_accessibility && (has_overlay || has_sms || has_query_all) {
            threats.push("Trojan.AndroidOS.Banker".into());
            risk_score = risk_score.max(90);
        }
        if has_device_admin && has_accessibility {
            threats.push("Trojan.AndroidOS.Locker".into());
            risk_score = risk_score.max(95);
        }

        let clamped_score = risk_score.min(100);
        let verdict = if clamped_score >= 70 {
            "Malicious".to_string()
        } else if clamped_score >= 35 {
            "Suspicious".to_string()
        } else {
            "Clean".to_string()
        };

        Ok(ApkReport {
            filename: filename.to_string(),
            package_name,
            sha256,
            size_bytes: data.len() as u64,
            dangerous_permissions: dangerous_perms,
            total_permissions: all_perms.len(),
            dex_analyses,
            threats,
            overall_risk_score: clamped_score,
            verdict,
        })
    }
}
