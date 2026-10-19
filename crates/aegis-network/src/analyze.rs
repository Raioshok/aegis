//! Connection analysis — classify live sockets into threat detections.

use crate::intel::IpBlocklist;
use aegis_core::{Detection, Severity, ThreatClass};
use aegis_firewall::connections::Connection;
use std::net::IpAddr;

/// Ports strongly associated with backdoors / C2 / anonymity networks.
const SUSPICIOUS_PORTS: &[(u16, &str)] = &[
    (23, "Telnet (plaintext, often IoT-botnet)"),
    (2323, "Telnet-alt (Mirai)"),
    (4444, "Metasploit default / reverse shell"),
    (5555, "Android ADB (botnet target)"),
    (1337, "Common backdoor port"),
    (31337, "Elite/back-orifice backdoor"),
    (6667, "IRC (legacy botnet C2)"),
    (9001, "Tor OR port"),
    (9030, "Tor directory port"),
    (9050, "Tor SOCKS proxy"),
    (9051, "Tor control port"),
    (50050, "Cobalt Strike default team server port"),
    (8888, "Havoc C2 / AsyncRAT default listener"),
    (4005, "Remcos RAT default port"),
    (7000, "Frp / Chisel reverse tunnel port"),
    (3333, "Monero Stratum cryptomining port"),
    (14444, "XMRig stratum TLS mining port"),
];

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        v4 => v4,
    }
}

fn is_public(ip: IpAddr) -> bool {
    match normalize_ip(ip) {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast())
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            let is_ula = (seg[0] & 0xfe00) == 0xfc00; // fc00::/7
            let is_link_local = (seg[0] & 0xffc0) == 0xfe80; // fe80::/10
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_ula
                || is_link_local)
        }
    }
}

/// Classify one connection against threat intel + heuristics.
pub fn classify(conn: &Connection, blocklist: &IpBlocklist) -> Vec<Detection> {
    let mut out = Vec::new();

    // 1. Threat-intel blocklist hit on the remote address.
    if is_public(conn.remote) && blocklist.contains(conn.remote) {
        out.push(Detection::new(
            "Network",
            format!("C2.KnownBadIP:{}", conn.remote),
            Severity::Critical,
            ThreatClass::Behavioral,
            format!(
                "{} connection to blocklisted address {}:{}",
                conn.protocol, conn.remote, conn.remote_port
            ),
        ));
    }

    // 2. Suspicious remote/local port.
    for (port, desc) in SUSPICIOUS_PORTS {
        let port_sev = if *port == 5555 || *port == 9001 {
            Severity::Low
        } else {
            Severity::High
        };
        if conn.remote_port == *port && conn.is_established() && is_public(conn.remote) {
            out.push(Detection::new(
                "Network",
                format!("Suspicious.Port:{port}"),
                port_sev,
                ThreatClass::Behavioral,
                format!("Outbound to {}:{} — {desc}", conn.remote, port),
            ));
        }
        if conn.local_port == *port && conn.is_listening() {
            out.push(Detection::new(
                "Network",
                format!("Suspicious.Listen:{port}"),
                Severity::Medium,
                ThreatClass::Behavioral,
                format!("Listening on port {port} — {desc}"),
            ));
        }
    }

    // 3. Listening on all interfaces on a high, non-standard port (potential
    //    backdoor bind shell).
    if conn.is_listening()
        && conn.local.is_unspecified()
        && conn.local_port > 1024
        && !is_common_service(conn.local_port)
    {
        out.push(Detection::new(
            "Network",
            format!("Listen.AllIfaces:{}", conn.local_port),
            Severity::Low,
            ThreatClass::Behavioral,
            format!(
                "Service listening on 0.0.0.0:{} (exposed to the network)",
                conn.local_port
            ),
        ));
    }

    // 4. LOLBin process initiating outbound public connection (living-off-the-land dropper/C2)
    if let Some(pid) = conn.pid {
        let proc_ctrl = aegis_platform::default_process_control();
        if let Some(img_path) = proc_ctrl.image_path(pid) {
            let name = img_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if is_known_lolbin(name) && is_public(conn.remote) && conn.is_established() {
                out.push(Detection::new(
                    "Network",
                    format!("Suspicious.LOLBinNetwork:{name}"),
                    Severity::High,
                    ThreatClass::Behavioral,
                    format!("Living-off-the-land binary '{name}' (PID {pid}) connected to public endpoint {}:{}", conn.remote, conn.remote_port),
                ));
            }
        }
    }

    out
}

const LOLBINS: &[&str] = &[
    "certutil.exe",
    "bitsadmin.exe",
    "mshta.exe",
    "regsvr32.exe",
    "cscript.exe",
    "wscript.exe",
    "rundll32.exe",
    "hh.exe",
    "installutil.exe",
    "regasm.exe",
];

pub fn is_known_lolbin(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    LOLBINS.iter().any(|&lb| lower == lb || lower.ends_with(&format!("\\{lb}")) || lower.ends_with(&format!("/{lb}")))
}

fn is_common_service(port: u16) -> bool {
    matches!(
        port,
        3000 | 3306 | 5432 | 6379 | 8000 | 8080 | 8443 | 9090 | 27017 | 5173
    )
}

/// Analyse every live connection, evaluating threat intel, port anomalies, and multi-port scans.
pub fn scan(blocklist: &IpBlocklist) -> Vec<Detection> {
    let mut out = Vec::new();
    let conns = aegis_firewall::connections::all();
    for conn in &conns {
        out.extend(classify(conn, blocklist));
    }
    out.extend(detect_port_scans(&conns));
    out
}

/// Detects port scanning activity where a single remote IP connects to many distinct ports.
pub fn detect_port_scans(conns: &[Connection]) -> Vec<Detection> {
    use std::collections::{HashMap, HashSet};
    let mut ports_per_ip: HashMap<IpAddr, HashSet<u16>> = HashMap::new();
    for c in conns {
        if is_public(c.remote) {
            ports_per_ip.entry(c.remote).or_default().insert(c.remote_port);
        }
    }
    let mut detections = Vec::new();
    for (ip, ports) in ports_per_ip {
        if ports.len() >= 8 {
            detections.push(Detection::new(
                "Network",
                format!("Suspicious.PortScan:{ip}"),
                Severity::High,
                ThreatClass::Behavioral,
                format!("Host {ip} targeted {} distinct ports (active port scan / network reconnaissance)", ports.len()),
            ));
        }
    }
    detections
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_firewall::connections::Connection;

    fn conn(remote: &str, rport: u16, state: &'static str) -> Connection {
        Connection {
            protocol: "tcp",
            local: "0.0.0.0".parse().unwrap(),
            local_port: 40000,
            remote: remote.parse().unwrap(),
            remote_port: rport,
            state,
            uid: 1000,
            pid: None,
            inode: 1,
        }
    }

    #[test]
    fn flags_blocklisted_remote() {
        let bl = IpBlocklist::from_lines(["203.0.113.66"]);
        let d = classify(&conn("203.0.113.66", 443, "ESTABLISHED"), &bl);
        assert!(d.iter().any(|x| x.threat.starts_with("C2.KnownBadIP")));
    }

    #[test]
    fn flags_reverse_shell_port() {
        let bl = IpBlocklist::new();
        let d = classify(&conn("198.51.100.7", 4444, "ESTABLISHED"), &bl);
        assert!(d.iter().any(|x| x.threat.contains("4444")));
    }

    #[test]
    fn ignores_normal_https_to_public() {
        let bl = IpBlocklist::new();
        let d = classify(&conn("140.82.112.3", 443, "ESTABLISHED"), &bl);
        assert!(d.is_empty());
    }

    #[test]
    fn lolbin_detection_works() {
        assert!(is_known_lolbin("certutil.exe"));
        assert!(is_known_lolbin("C:\\Windows\\System32\\mshta.exe"));
        assert!(is_known_lolbin("rundll32.exe"));
        assert!(!is_known_lolbin("notepad.exe"));
    }

    #[test]
    fn detects_port_scan_behavior() {
        let mut conns = Vec::new();
        for port in 1000..1010 {
            conns.push(conn("198.51.100.99", port, "SYN_SENT"));
        }
        let detections = detect_port_scans(&conns);
        assert_eq!(detections.len(), 1);
        assert!(detections[0].threat.contains("Suspicious.PortScan"));
    }

    #[test]
    fn ignores_private_and_loopback() {
        let bl = IpBlocklist::from_lines(["10.0.0.0/8"]);
        // even though 10/8 is "blocklisted" in this test, private ranges are skipped
        let d = classify(&conn("10.0.0.5", 4444, "ESTABLISHED"), &bl);
        assert!(d.iter().all(|x| !x.threat.starts_with("C2.KnownBadIP")));
    }
}
