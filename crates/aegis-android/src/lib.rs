use sha2::Digest;

pub mod apk;
pub mod dex;

pub use apk::{ApkReport, ApkScanner};
pub use dex::{DexAnalysis, DexScanner};

/// Convenience function to scan an Android APK or DEX binary from disk.
pub fn scan_android_file(path: &std::path::Path) -> Result<ApkReport, String> {
    let data = std::fs::read(path).map_err(|e| format!("Failed to read file {}: {e}", path.display()))?;
    let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("unknown.apk");

    if filename.ends_with(".dex") {
        let dex = DexScanner::scan(&data);
        let mut hasher = sha2::Sha256::new();
        hasher.update(&data);
        let sha256 = format!("{:x}", hasher.finalize());
        return Ok(ApkReport {
            filename: filename.to_string(),
            package_name: None,
            sha256,
            size_bytes: data.len() as u64,
            dangerous_permissions: Vec::new(),
            total_permissions: 0,
            threats: dex.detected_indicators.clone(),
            dex_analyses: vec![dex.clone()],
            overall_risk_score: dex.risk_score,
            verdict: if dex.risk_score >= 70 {
                "Malicious".into()
            } else if dex.risk_score >= 35 {
                "Suspicious".into()
            } else {
                "Clean".into()
            },
        });
    }

    ApkScanner::scan_bytes(filename, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dex_scan() {
        let data = b"dex\n035\0some test bytes";
        let res = DexScanner::scan(data);
        assert!(res.is_valid_dex);
    }
}
