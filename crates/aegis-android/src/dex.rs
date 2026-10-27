use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexAnalysis {
    pub is_valid_dex: bool,
    pub string_count: usize,
    pub detected_indicators: Vec<String>,
    pub suspicious_strings: Vec<String>,
    pub risk_score: u32,
}

pub struct DexScanner;

impl DexScanner {
    /// Scan a raw byte buffer containing Dalvik Executable (.dex) code.
    pub fn scan(data: &[u8]) -> DexAnalysis {
        let is_valid = data.len() >= 8
            && &data[0..4] == b"dex\n"
            && (data[4] == b'0' && data[7] == 0);

        let mut indicators = Vec::new();
        let mut suspicious = Vec::new();
        let mut score: u32 = 0;

        let content_lossy = String::from_utf8_lossy(data);
        let lower = content_lossy.to_lowercase();

        // 1. Accessibility Service Abuse (Common in Banking Trojans: SharkBot, Hydra, Godfather)
        if lower.contains("accessibilityservice") || lower.contains("accessibility_service") {
            if lower.contains("performaction") || lower.contains("action_accessibility_settings") {
                indicators.push("Trojan.AndroidOS.AccessibilityAbuse".into());
                suspicious.push("Abuses AccessibilityService to automate clicks and steal credentials".into());
                score += 35;
            }
        }

        // 2. Overlay Hijacking / WindowManager Injection (Fake banking overlays)
        if lower.contains("type_application_overlay") || lower.contains("type_system_alert") {
            indicators.push("Trojan.AndroidOS.OverlayInjection".into());
            suspicious.push("Requests system overlay windows to display deceptive login screens".into());
            score += 30;
        }

        // 3. SMS Interception / 2FA Theft
        if lower.contains("sms_received") && (lower.contains("getdisplayoriginatingaddress") || lower.contains("pdus")) {
            indicators.push("Trojan.AndroidOS.SmsStealer".into());
            suspicious.push("Intercepts incoming SMS messages to steal two-factor authentication codes".into());
            score += 30;
        }

        // 4. Telegram C2 Communication Channels
        if lower.contains("api.telegram.org/bot") || (lower.contains("sendmessage?chat_id=") && lower.contains("bot")) {
            indicators.push("Trojan.AndroidOS.TelegramC2".into());
            suspicious.push("Uses Telegram Bot API as an exfiltration and Command-and-Control channel".into());
            score += 25;
        }

        // 5. Dynamic DEX Loading (Stage 2 Payload Dropper)
        if lower.contains("dexclassloader") || lower.contains("inmemorydexclassloader") {
            indicators.push("Dropper.AndroidOS.DynamicLoader".into());
            suspicious.push("Loads encrypted secondary DEX payloads at runtime to evade static scans".into());
            score += 20;
        }

        // 6. Device Admin Lock Screen Ransomware
        if lower.contains("devicepolicymanager") && lower.contains("locknow") {
            indicators.push("Ransom.AndroidOS.Locker".into());
            suspicious.push("Attempts to lock screen using Device Administration privileges".into());
            score += 40;
        }

        // 7. Root Exploits / Magisk Detection
        if lower.contains("/system/bin/su") || lower.contains("/system/xbin/su") || lower.contains("magisk") {
            indicators.push("Riskware.AndroidOS.RootAccess".into());
            suspicious.push("References root binaries or Magisk su execution stubs".into());
            score += 15;
        }

        // 8. DEX Packer & High Entropy Code Section
        let sample = &data[..data.len().min(64 * 1024)];
        let mut freq = [0u64; 256];
        for &b in sample {
            freq[b as usize] += 1;
        }
        let len_f = sample.len() as f64;
        let mut ent = 0.0f64;
        if len_f > 0.0 {
            for &c in &freq {
                if c > 0 {
                    let p = c as f64 / len_f;
                    ent -= p * p.log2();
                }
            }
        }
        if ent > 7.35 {
            indicators.push("Packer.AndroidOS.EncryptedDex".into());
            suspicious.push(format!("DEX file has high Shannon entropy ({:.2} bits/byte), indicating packer encryption (Jiagu/Legu)", ent));
            score += 35;
        }

        DexAnalysis {
            is_valid_dex: is_valid,
            string_count: lower.matches('\0').count(),
            detected_indicators: indicators,
            suspicious_strings: suspicious,
            risk_score: score.min(100),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sms_stealer_and_overlay_in_dex() {
        let mut fake_dex = b"dex\n035\0".to_vec();
        fake_dex.extend_from_slice(b"android.provider.Telephony.SMS_RECEIVED\0pdus\0TYPE_APPLICATION_OVERLAY\0");

        let res = DexScanner::scan(&fake_dex);
        assert!(res.is_valid_dex);
        assert!(res.detected_indicators.iter().any(|i| i.contains("SmsStealer")));
        assert!(res.detected_indicators.iter().any(|i| i.contains("OverlayInjection")));
        assert!(res.risk_score >= 60);
    }
}
