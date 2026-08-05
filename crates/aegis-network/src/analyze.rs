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
];

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast())
        }
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || v6.is_multicast()),
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
        if conn.remote_port == *port && conn.is_established() && is_public(conn.remote) {
            out.push(Detection::new(
                "Network",
                format!("Suspicious.Port:{port}"),
                Severity::High,
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

    out
}

fn is_common_service(port: u16) -> bool {
    matches!(
        port,
        3000 | 3306 | 5432 | 6379 | 8000 | 8080 | 8443 | 9090 | 27017 | 5173
    )
}

/// Analyse every live connection.
pub fn scan(blocklist: &IpBlocklist) -> Vec<Detection> {
    let mut out = Vec::new();
    for conn in aegis_firewall::connections::all() {
        out.extend(classify(&conn, blocklist));
    }
    out
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
    fn ignores_private_and_loopback() {
        let bl = IpBlocklist::from_lines(["10.0.0.0/8"]);
        // even though 10/8 is "blocklisted" in this test, private ranges are skipped
        let d = classify(&conn("10.0.0.5", 4444, "ESTABLISHED"), &bl);
        assert!(d.iter().all(|x| !x.threat.starts_with("C2.KnownBadIP")));
    }
}
