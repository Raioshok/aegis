//! OS hardening audit: reads real system settings and can apply the fix for
//! settings that are a single, well-defined value.

use aegis_core::{AegisError, Result};
use serde::Serialize;

/// Outcome of one hardening check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    Pass,
    Fail,
    /// The setting could not be read (missing permission or not applicable).
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct HardeningCheck {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    /// "Critical" | "High" | "Medium" | "Low"
    pub severity: &'static str,
    pub state: CheckState,
    /// What was actually observed on this machine.
    pub detail: String,
    /// `apply_fix(id)` can remediate this check (needs admin/root).
    pub fixable: bool,
}

/// 100 minus a weight per failed check, by severity.
pub fn score(checks: &[HardeningCheck]) -> u8 {
    let lost: u32 = checks
        .iter()
        .filter(|c| c.state == CheckState::Fail)
        .map(|c| match c.severity {
            "Critical" => 25,
            "High" => 15,
            "Medium" => 8,
            _ => 3,
        })
        .sum();
    100u32.saturating_sub(lost) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(severity: &'static str, state: CheckState) -> HardeningCheck {
        HardeningCheck { id: "x", title: "x", category: "x", severity, state, detail: String::new(), fixable: false }
    }

    #[test]
    fn score_counts_only_failures() {
        let checks = [
            check("Critical", CheckState::Fail),
            check("High", CheckState::Pass),
            check("Medium", CheckState::Unknown),
            check("Low", CheckState::Fail),
        ];
        assert_eq!(score(&checks), 72);
        assert_eq!(score(&vec![check("Critical", CheckState::Fail); 5]), 0);
    }

    #[test]
    fn audit_runs_on_this_machine() {
        let checks = audit();
        assert!(!checks.is_empty());
        // The registry / sysctl plumbing really reads values: these always exist.
        #[cfg(windows)]
        assert!(checks.iter().any(|c| c.id == "firewall" && c.state != CheckState::Unknown), "{checks:#?}");
        #[cfg(target_os = "linux")]
        assert!(checks.iter().any(|c| c.id == "aslr" && c.state != CheckState::Unknown), "{checks:#?}");
        assert!(apply_fix("no_such_check").is_err());
    }
}

// --- Windows ---------------------------------------------------------------

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, RegSetKeyValueW, HKEY_LOCAL_MACHINE, REG_DWORD, RRF_RT_REG_DWORD,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(super) fn reg_dword(subkey: &str, value: &str) -> Option<u32> {
        let (k, v) = (wide(subkey), wide(value));
        let mut data = 0u32;
        let mut len = 4u32;
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                k.as_ptr(),
                v.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                &mut data as *mut u32 as *mut std::ffi::c_void,
                &mut len,
            )
        };
        (rc == 0).then_some(data)
    }

    fn reg_key_exists(subkey: &str) -> bool {
        use windows_sys::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, KEY_READ};
        let k = wide(subkey);
        let mut h = std::ptr::null_mut();
        let ok = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, k.as_ptr(), 0, KEY_READ, &mut h) } == 0;
        if ok {
            unsafe { RegCloseKey(h) };
        }
        ok
    }

    fn set_reg_dword(subkey: &str, value: &str, data: u32) -> Result<()> {
        let (k, v) = (wide(subkey), wide(value));
        let rc = unsafe {
            RegSetKeyValueW(
                HKEY_LOCAL_MACHINE,
                k.as_ptr(),
                v.as_ptr(),
                REG_DWORD,
                &data as *const u32 as *const std::ffi::c_void,
                4,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(AegisError::Permission(format!(
                "cannot write HKLM\\{subkey}\\{value} (error {rc}); run Aegis as administrator"
            )))
        }
    }

    const UAC: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    const SMB_SERVER: &str = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
    const SMB1_CLIENT: &str = r"SYSTEM\CurrentControlSet\Services\mrxsmb10";
    const EXPLORER_POLICY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    const CI_CONFIG: &str = r"SYSTEM\CurrentControlSet\Control\CI\Config";
    const HVCI: &str = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";
    const FW_STANDARD: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile";
    const FW_PUBLIC: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile";
    const TERMINAL_SERVER: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server";
    const RDP_TCP: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";

    fn state(pass: Option<bool>) -> CheckState {
        match pass {
            Some(true) => CheckState::Pass,
            Some(false) => CheckState::Fail,
            None => CheckState::Unknown,
        }
    }

    pub fn audit() -> Vec<HardeningCheck> {
        let mut out = Vec::new();

        // EnableLUA defaults to 1 when absent.
        let lua = reg_dword(UAC, "EnableLUA").unwrap_or(1);
        out.push(HardeningCheck {
            id: "uac",
            title: "User Account Control",
            category: "System policy",
            severity: "High",
            state: state(Some(lua == 1)),
            detail: format!("EnableLUA = {lua}{}", if lua == 1 { "" } else { " (UAC is off; every program runs with full rights)" }),
            fixable: true,
        });

        let smb1 = reg_dword(SMB_SERVER, "SMB1");
        let client = reg_key_exists(SMB1_CLIENT);
        let smb_ok = smb1 == Some(0) || (smb1.is_none() && !client);
        out.push(HardeningCheck {
            id: "smb1",
            title: "Legacy SMBv1 protocol",
            category: "Network",
            severity: "Critical",
            state: state(Some(smb_ok)),
            detail: format!(
                "SMB1 server value = {}, SMBv1 client driver {}",
                smb1.map_or("not set".into(), |v| v.to_string()),
                if client { "installed" } else { "not installed" }
            ),
            fixable: true,
        });

        let autorun = reg_dword(EXPLORER_POLICY, "NoDriveTypeAutoRun");
        out.push(HardeningCheck {
            id: "autorun",
            title: "AutoRun on all drive types",
            category: "Removable media",
            severity: "Medium",
            state: state(Some(autorun == Some(0xFF))),
            detail: match autorun {
                Some(v) => format!("NoDriveTypeAutoRun = 0x{v:02X} (0xFF disables AutoRun everywhere)"),
                None => "NoDriveTypeAutoRun not set (Windows default leaves some drive types enabled)".into(),
            },
            fixable: true,
        });

        // Enabled by default from Windows 11 22H2 when the value is absent.
        let blocklist = reg_dword(CI_CONFIG, "VulnerableDriverBlocklistEnable");
        out.push(HardeningCheck {
            id: "driver_blocklist",
            title: "Microsoft vulnerable driver blocklist",
            category: "Kernel",
            severity: "Critical",
            state: state(Some(blocklist != Some(0))),
            detail: match blocklist {
                Some(v) => format!("VulnerableDriverBlocklistEnable = {v}"),
                None => "Not set (on by default on Windows 11 22H2 and later)".into(),
            },
            fixable: true,
        });

        let hvci = reg_dword(HVCI, "Enabled");
        out.push(HardeningCheck {
            id: "hvci",
            title: "Memory integrity (HVCI)",
            category: "Kernel",
            severity: "High",
            state: state(Some(hvci == Some(1))),
            detail: format!("HypervisorEnforcedCodeIntegrity Enabled = {}", hvci.map_or("not set".into(), |v| v.to_string())),
            // Turning HVCI on can stop incompatible drivers from loading; leave it to Windows Security.
            fixable: false,
        });

        let fw: Vec<Option<u32>> = [FW_STANDARD, FW_PUBLIC].iter().map(|k| reg_dword(k, "EnableFirewall")).collect();
        out.push(HardeningCheck {
            id: "firewall",
            title: "Windows Firewall (private and public profiles)",
            category: "Network",
            severity: "High",
            state: state(if fw.iter().any(|v| v.is_none()) { None } else { Some(fw.iter().all(|v| *v == Some(1))) }),
            detail: format!("Private = {:?}, Public = {:?}", fw[0], fw[1]),
            fixable: true,
        });

        let rdp_off = reg_dword(TERMINAL_SERVER, "fDenyTSConnections").unwrap_or(1) == 1;
        let nla = reg_dword(RDP_TCP, "UserAuthentication").unwrap_or(1) == 1;
        out.push(HardeningCheck {
            id: "rdp_nla",
            title: "Remote Desktop requires Network Level Authentication",
            category: "Remote access",
            severity: "High",
            state: state(Some(rdp_off || nla)),
            detail: if rdp_off {
                "Remote Desktop is off".into()
            } else if nla {
                "Remote Desktop is on, NLA required".into()
            } else {
                "Remote Desktop is on WITHOUT Network Level Authentication".into()
            },
            fixable: true,
        });

        out
    }

    pub fn apply_fix(id: &str) -> Result<()> {
        match id {
            "uac" => set_reg_dword(UAC, "EnableLUA", 1),
            "smb1" => set_reg_dword(SMB_SERVER, "SMB1", 0),
            "autorun" => set_reg_dword(EXPLORER_POLICY, "NoDriveTypeAutoRun", 0xFF),
            "driver_blocklist" => set_reg_dword(CI_CONFIG, "VulnerableDriverBlocklistEnable", 1),
            "firewall" => {
                set_reg_dword(FW_STANDARD, "EnableFirewall", 1)?;
                set_reg_dword(FW_PUBLIC, "EnableFirewall", 1)
            }
            "rdp_nla" => set_reg_dword(RDP_TCP, "UserAuthentication", 1),
            other => Err(AegisError::NotFound(format!("no automatic fix for '{other}'"))),
        }
    }
}

// --- Linux -----------------------------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    struct Sysctl {
        id: &'static str,
        key: &'static str,
        title: &'static str,
        category: &'static str,
        severity: &'static str,
        /// Value written by the fix.
        want: i64,
        /// Whether the current value is acceptable.
        ok: fn(i64) -> bool,
    }

    const SYSCTLS: &[Sysctl] = &[
        Sysctl { id: "aslr", key: "kernel/randomize_va_space", title: "Full address space layout randomization", category: "Kernel", severity: "Critical", want: 2, ok: |v| v == 2 },
        Sysctl { id: "suid_dumpable", key: "fs/suid_dumpable", title: "No core dumps from setuid programs", category: "Information disclosure", severity: "Medium", want: 0, ok: |v| v == 0 },
        Sysctl { id: "kptr_restrict", key: "kernel/kptr_restrict", title: "Kernel pointers hidden from users", category: "Kernel", severity: "Medium", want: 1, ok: |v| v >= 1 },
        Sysctl { id: "dmesg_restrict", key: "kernel/dmesg_restrict", title: "Kernel log restricted to root", category: "Information disclosure", severity: "Low", want: 1, ok: |v| v == 1 },
        Sysctl { id: "unprivileged_bpf", key: "kernel/unprivileged_bpf_disabled", title: "Unprivileged eBPF disabled", category: "Kernel", severity: "High", want: 1, ok: |v| v >= 1 },
        Sysctl { id: "ptrace_scope", key: "kernel/yama/ptrace_scope", title: "Processes cannot debug unrelated processes", category: "Kernel", severity: "Medium", want: 1, ok: |v| v >= 1 },
    ];

    fn read_sysctl(key: &str) -> Option<i64> {
        std::fs::read_to_string(format!("/proc/sys/{key}")).ok()?.trim().parse().ok()
    }

    /// Effective `PermitRootLogin` (first match wins in sshd_config; default is prohibit-password).
    fn permit_root_login(config: &str) -> String {
        config
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .find_map(|l| {
                let mut parts = l.split_whitespace();
                parts.next()?.eq_ignore_ascii_case("PermitRootLogin").then(|| parts.next().unwrap_or("").to_ascii_lowercase())
            })
            .unwrap_or_else(|| "prohibit-password".into())
    }

    pub fn audit() -> Vec<HardeningCheck> {
        let mut out: Vec<HardeningCheck> = SYSCTLS
            .iter()
            .map(|s| {
                let v = read_sysctl(s.key);
                HardeningCheck {
                    id: s.id,
                    title: s.title,
                    category: s.category,
                    severity: s.severity,
                    state: match v {
                        Some(v) if (s.ok)(v) => CheckState::Pass,
                        Some(_) => CheckState::Fail,
                        None => CheckState::Unknown,
                    },
                    detail: match v {
                        Some(v) => format!("{} = {v}", s.key.replace('/', ".")),
                        None => format!("{} not available on this kernel", s.key.replace('/', ".")),
                    },
                    fixable: v.is_some(),
                }
            })
            .collect();

        if let Ok(cfg) = std::fs::read_to_string("/etc/ssh/sshd_config") {
            let v = permit_root_login(&cfg);
            out.push(HardeningCheck {
                id: "ssh_root_login",
                title: "SSH root login with password disabled",
                category: "Authentication",
                severity: "High",
                state: if v == "yes" { CheckState::Fail } else { CheckState::Pass },
                detail: format!("PermitRootLogin {v}"),
                // Editing sshd_config safely needs a reload and review; not automated.
                fixable: false,
            });
        }
        out
    }

    pub fn apply_fix(id: &str) -> Result<()> {
        let s = SYSCTLS
            .iter()
            .find(|s| s.id == id)
            .ok_or_else(|| AegisError::NotFound(format!("no automatic fix for '{id}'")))?;
        let path = format!("/proc/sys/{}", s.key);
        std::fs::write(&path, s.want.to_string()).map_err(|e| {
            AegisError::Permission(format!("cannot write {path}: {e}; run Aegis as root (the change lasts until reboot)"))
        })
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn root_login_first_uncommented_match_wins() {
            assert_eq!(super::permit_root_login("#PermitRootLogin yes\nPermitRootLogin no\nPermitRootLogin yes"), "no");
            assert_eq!(super::permit_root_login(""), "prohibit-password");
        }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod imp {
    use super::*;
    pub fn audit() -> Vec<HardeningCheck> {
        Vec::new()
    }
    pub fn apply_fix(id: &str) -> Result<()> {
        Err(AegisError::NotFound(format!("no automatic fix for '{id}'")))
    }
}

/// Run every hardening check for this OS.
pub fn audit() -> Vec<HardeningCheck> {
    imp::audit()
}

/// Apply the fix for check `id`. Needs administrator (Windows) or root (Linux).
pub fn apply_fix(id: &str) -> Result<()> {
    imp::apply_fix(id)
}
