//! IP threat-intelligence: match addresses against a blocklist of CIDRs.

use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::path::Path;

/// A set of malicious networks (C2, botnet, abuse feeds).
#[derive(Debug, Default, Clone)]
pub struct IpBlocklist {
    nets: Vec<IpNetwork>,
}

impl IpBlocklist {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse one CIDR or bare IP per line (`#` comments allowed).
    pub fn from_lines<I, S>(lines: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut nets = Vec::new();
        for line in lines {
            let l = line.as_ref().trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            if let Ok(net) = l.parse::<IpNetwork>() {
                nets.push(net);
            } else if let Ok(ip) = l.parse::<IpAddr>() {
                if let Ok(net) = IpNetwork::new(ip, if ip.is_ipv4() { 32 } else { 128 }) {
                    nets.push(net);
                }
            }
        }
        Self { nets }
    }

    pub fn from_file(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_lines(text.lines()),
            Err(_) => Self::default(),
        }
    }

    /// The user's `ip-blocklist.txt` plus the synced Feodo Tracker C2 feed.
    pub fn load_default() -> Self {
        let read = |p: std::path::PathBuf| std::fs::read_to_string(p).unwrap_or_default();
        let user = read(aegis_core::paths::config_dir().join("ip-blocklist.txt"));
        let feed = read(aegis_core::paths::threat_intel_dir().join("feodotracker.ips"));
        Self::from_lines(user.lines().chain(feed.lines()))
    }

    pub fn len(&self) -> usize {
        self.nets.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// True if `ip` falls within any blocked network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_cidr_and_bare_ip() {
        let bl = IpBlocklist::from_lines(["10.0.0.0/8", "1.2.3.4", "# comment"]);
        assert_eq!(bl.len(), 2);
        assert!(bl.contains("10.9.9.9".parse().unwrap()));
        assert!(bl.contains("1.2.3.4".parse().unwrap()));
        assert!(!bl.contains("8.8.8.8".parse().unwrap()));
    }
}
