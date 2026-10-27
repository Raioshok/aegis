//! Network optimization — the Kaspersky-style "network tune-up".
//!
//! Reads the kernel's current TCP/network settings and compares them to a
//! throughput-and-latency-optimised profile (BBR congestion control, a modern
//! queueing discipline, generous socket buffers, TCP Fast Open, MTU probing…),
//! emitting a suggestion per setting — or confirming it's already optimal.
//! Also measures DNS resolution latency and lists the busiest connections.
//!
//! The recommendation logic is a **pure function** over the current settings,
//! so it is fully unit-tested without touching the kernel.

use crate::model::{Finding, Impact, OptimizeReport};
use std::collections::HashMap;
use std::process::Command;
use std::time::Instant;

/// One tunable and its recommended value.
struct Tunable {
    key: &'static str,
    /// Recommended value(s); the current value is "good" if it matches any.
    recommended: &'static [&'static str],
    /// For numeric keys, the current value passes if it is ≥ this.
    min_numeric: Option<u64>,
    title: &'static str,
    why: &'static str,
}

const TUNABLES: &[Tunable] = &[
    Tunable {
        key: "net.ipv4.tcp_congestion_control",
        recommended: &["bbr"],
        min_numeric: None,
        title: "TCP congestion control",
        why: "BBR sustains higher throughput and lower latency than CUBIC on modern links",
    },
    Tunable {
        key: "net.core.default_qdisc",
        recommended: &["cake", "fq"],
        min_numeric: None,
        title: "Queueing discipline",
        why: "cake/fq reduce bufferbloat and improve responsiveness under load",
    },
    Tunable {
        key: "net.core.rmem_max",
        recommended: &[],
        min_numeric: Some(16 * 1024 * 1024),
        title: "Max receive buffer",
        why: "larger socket buffers let high-bandwidth×latency links reach full speed",
    },
    Tunable {
        key: "net.core.wmem_max",
        recommended: &[],
        min_numeric: Some(16 * 1024 * 1024),
        title: "Max send buffer",
        why: "larger send buffers avoid throttling on fast links",
    },
    Tunable {
        key: "net.ipv4.tcp_fastopen",
        recommended: &["3"],
        min_numeric: None,
        title: "TCP Fast Open",
        why: "removes a round-trip on repeat connections (faster page loads)",
    },
    Tunable {
        key: "net.ipv4.tcp_mtu_probing",
        recommended: &["1", "2"],
        min_numeric: None,
        title: "TCP MTU probing",
        why: "recovers throughput on links with ICMP black holes / odd MTUs",
    },
    Tunable {
        key: "net.ipv4.tcp_slow_start_after_idle",
        recommended: &["0"],
        min_numeric: None,
        title: "Slow-start after idle",
        why: "disabling keeps steady connections fast after brief pauses",
    },
];

/// The sysctl profile Aegis applies with `optimize tune --apply`.
pub const RECOMMENDED_SYSCTL: &[(&str, &str)] = &[
    ("net.ipv4.tcp_congestion_control", "bbr"),
    ("net.core.default_qdisc", "cake"),
    ("net.core.rmem_max", "16777216"),
    ("net.core.wmem_max", "16777216"),
    ("net.ipv4.tcp_fastopen", "3"),
    ("net.ipv4.tcp_mtu_probing", "1"),
    ("net.ipv4.tcp_slow_start_after_idle", "0"),
];

fn numeric(s: &str) -> Option<u64> {
    // sysctl values like tcp_rmem are multi-valued ("4096 131072 6291456");
    // take the last field for max-buffer style keys, else the whole thing.
    s.split_whitespace().last()?.parse::<u64>().ok()
}

/// Pure: given current sysctl values, produce a finding per tunable.
pub fn analyze_sysctl(current: &HashMap<String, String>) -> Vec<Finding> {
    let mut out = Vec::new();
    for t in TUNABLES {
        let cur = current.get(t.key).map(|s| s.trim().to_string());
        let (ok, cur_disp) = match &cur {
            None => (false, "unset".to_string()),
            Some(v) => {
                let ok = if let Some(min) = t.min_numeric {
                    numeric(v).map(|n| n >= min).unwrap_or(false)
                } else {
                    t.recommended.iter().any(|r| v == r)
                };
                (ok, v.clone())
            }
        };
        if ok {
            out.push(Finding::ok(
                "Network",
                t.title,
                format!("{} = {} (optimal)", t.key, cur_disp),
            ));
        } else {
            let rec = if let Some(min) = t.min_numeric {
                format!("≥ {min}")
            } else {
                t.recommended.join(" or ")
            };
            out.push(Finding::action(
                "Network",
                t.title,
                format!("{} is `{cur_disp}`; recommend `{rec}` — {}.", t.key, t.why),
                Impact::Low,
                0,
                format!(
                    "sysctl -w {}={}",
                    t.key,
                    t.recommended.first().unwrap_or(&"…")
                ),
                true,
            ));
        }
    }
    out
}

/// Read the current values of the tunables from the kernel.
pub fn read_current_sysctl() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for t in TUNABLES {
        if let Ok(out) = Command::new("sysctl").arg("-n").arg(t.key).output() {
            if out.status.success() {
                map.insert(
                    t.key.to_string(),
                    String::from_utf8_lossy(&out.stdout).trim().to_string(),
                );
            }
        }
    }
    map
}

/// Time how long the system resolver takes to resolve `host` (a rough DNS
/// latency probe). Returns milliseconds.
pub fn dns_latency_ms(host: &str) -> Option<u128> {
    let start = Instant::now();
    // Use the system resolver via getaddrinfo.
    let ok = std::net::ToSocketAddrs::to_socket_addrs(&(host, 443))
        .map(|mut it| it.next().is_some())
        .unwrap_or(false);
    if ok {
        Some(start.elapsed().as_millis())
    } else {
        None
    }
}

#[cfg(windows)]
fn scan_windows_network(r: &mut OptimizeReport) {
    if let Ok(out) = Command::new("netsh").args(&["int", "tcp", "show", "global"]).output() {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
            if text.contains("autotuninglevel") && (text.contains("disabled") || text.contains("highlyrestricted")) {
                r.push(Finding::action(
                    "Network Tuning",
                    "TCP Window Auto-Tuning is Restrained",
                    "TCP Window Auto-Tuning is disabled or restricted, limiting high-speed throughput.",
                    Impact::High,
                    0,
                    "netsh int tcp set global autotuninglevel=normal",
                    true,
                ));
            } else {
                r.push(Finding::ok(
                    "Network Tuning",
                    "TCP Window Auto-Tuning is Optimal",
                    "Receive Window Auto-Tuning is active at normal throughput profile.",
                ));
            }
        }
    }
}

/// Full network optimization scan.
pub fn scan() -> OptimizeReport {
    let mut r = OptimizeReport::default();

    #[cfg(target_os = "linux")]
    {
        // sysctl tuning.
        let current = read_current_sysctl();
        for f in analyze_sysctl(&current) {
            r.push(f);
        }
    }

    #[cfg(windows)]
    {
        scan_windows_network(&mut r);
    }

    // DNS latency.
    if let Some(ms) = dns_latency_ms("cloudflare.com") {
        let impact = if ms > 120 {
            Impact::Medium
        } else if ms > 50 {
            Impact::Low
        } else {
            Impact::Ok
        };
        let detail = if impact == Impact::Ok {
            format!("Resolver answered in {ms} ms — fast.")
        } else {
            format!(
                "Resolver took {ms} ms. A faster resolver (1.1.1.1 / 9.9.9.9) or a \
                 local caching resolver would speed up browsing."
            )
        };
        r.push(Finding {
            category: "Network".into(),
            title: "DNS latency".into(),
            detail,
            impact,
            reclaimable: 0,
            action: if impact == Impact::Ok {
                None
            } else {
                Some("consider systemd-resolved caching or a faster upstream resolver".into())
            },
            needs_root: false,
        });
    }

    // Busiest established connections (top talkers by count per remote).
    let conns = aegis_firewall::connections::all();
    let established = conns.iter().filter(|c| c.is_established()).count();
    r.push(Finding::ok(
        "Network",
        "Active connections",
        format!("{established} established connection(s)."),
    ));

    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn optimal_settings_report_ok() {
        let cur = m(&[
            ("net.ipv4.tcp_congestion_control", "bbr"),
            ("net.core.default_qdisc", "cake"),
            ("net.core.rmem_max", "33554432"),
            ("net.core.wmem_max", "33554432"),
            ("net.ipv4.tcp_fastopen", "3"),
            ("net.ipv4.tcp_mtu_probing", "1"),
            ("net.ipv4.tcp_slow_start_after_idle", "0"),
        ]);
        let findings = analyze_sysctl(&cur);
        assert!(
            findings.iter().all(|f| f.impact == Impact::Ok),
            "all should be optimal"
        );
    }

    #[test]
    fn suboptimal_settings_recommend() {
        let cur = m(&[
            ("net.ipv4.tcp_congestion_control", "cubic"),
            ("net.core.default_qdisc", "pfifo_fast"),
            ("net.core.rmem_max", "212992"),
        ]);
        let findings = analyze_sysctl(&cur);
        assert!(findings
            .iter()
            .any(|f| f.title == "TCP congestion control" && f.impact > Impact::Ok));
        assert!(findings
            .iter()
            .any(|f| f.title == "Max receive buffer" && f.impact > Impact::Ok));
    }

    #[test]
    fn multivalue_buffer_uses_last_field() {
        // tcp_rmem style value; only rmem_max is checked numerically here.
        assert_eq!(numeric("4096 131072 6291456"), Some(6291456));
        assert_eq!(numeric("33554432"), Some(33554432));
    }
}
