//! Firewall rule model and nftables ruleset generation.
//!
//! Aegis manages its **own** nftables table (`inet aegis`) so it never clashes
//! with a system firewall (ufw/firewalld/hand-written rules). Rule → nft-script
//! translation is a pure function and is unit-tested; applying the script is a
//! separate, privileged step (see [`crate::apply`]).

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

pub const TABLE: &str = "aegis";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Any,
}

/// A single firewall rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub action: Action,
    pub direction: Direction,
    pub protocol: Protocol,
    /// Port (destination for Out, local for In). `None` = any.
    pub port: Option<u16>,
    /// Remote address/CIDR the rule matches. `None` = any.
    pub remote: Option<IpNetwork>,
    #[serde(default)]
    pub comment: String,
}

impl Rule {
    /// Convenience: block all traffic to/from a host.
    pub fn block_ip(ip: IpNetwork, comment: impl Into<String>) -> Self {
        Self {
            action: Action::Drop,
            direction: Direction::Out,
            protocol: Protocol::Any,
            port: None,
            remote: Some(ip),
            comment: comment.into(),
        }
    }

    /// Render this rule as one nftables statement line (without the chain).
    pub fn to_nft(&self) -> String {
        let mut parts = Vec::new();
        if let Some(net) = &self.remote {
            let fam = if net.is_ipv4() { "ip" } else { "ip6" };
            // For Out the remote is the daddr; for In it is the saddr.
            let field = match self.direction {
                Direction::Out => "daddr",
                Direction::In => "saddr",
            };
            parts.push(format!("{fam} {field} {net}"));
        }
        match self.protocol {
            Protocol::Tcp => parts.push("meta l4proto tcp".into()),
            Protocol::Udp => parts.push("meta l4proto udp".into()),
            Protocol::Any => {}
        }
        if let Some(port) = self.port {
            let proto = match self.protocol {
                Protocol::Udp => "udp",
                _ => "tcp",
            };
            let field = match self.direction {
                Direction::Out => "dport",
                Direction::In => "dport",
            };
            parts.push(format!("{proto} {field} {port}"));
        }
        parts.push(
            match self.action {
                Action::Accept => "accept",
                Action::Drop => "drop",
            }
            .to_string(),
        );
        let mut line = parts.join(" ");
        if !self.comment.is_empty() {
            let clean_comment = self.comment.replace(['\n', '\r', '"'], " ");
            line.push_str(&format!(" comment \"{}\"", clean_comment));
        }
        line
    }
}

/// A complete Aegis ruleset.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ruleset {
    pub rules: Vec<Rule>,
}

impl Ruleset {
    /// Render the full `nft -f` script that (re)creates the `aegis` table.
    ///
    /// The table is flushed and rebuilt atomically so applying is idempotent.
    pub fn to_nft_script(&self) -> String {
        let mut s = String::new();
        // Recreate the table from scratch (atomic replace).
        s.push_str(&format!("add table inet {TABLE}\n"));
        s.push_str(&format!("flush table inet {TABLE}\n"));
        s.push_str(&format!(
            "add chain inet {TABLE} input {{ type filter hook input priority 0; }}\n"
        ));
        s.push_str(&format!(
            "add chain inet {TABLE} output {{ type filter hook output priority 0; }}\n"
        ));
        for rule in &self.rules {
            let chain = match rule.direction {
                Direction::In => "input",
                Direction::Out => "output",
            };
            s.push_str(&format!(
                "add rule inet {TABLE} {chain} {}\n",
                rule.to_nft()
            ));
        }
        s
    }

    pub fn add(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Remove rules whose remote matches `ip` exactly.
    pub fn remove_ip(&mut self, ip: &IpNetwork) -> usize {
        let before = self.rules.len();
        self.rules.retain(|r| r.remote.as_ref() != Some(ip));
        before - self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_ip_rule_renders() {
        let net: IpNetwork = "1.2.3.4/32".parse().unwrap();
        let r = Rule::block_ip(net, "known C2");
        let line = r.to_nft();
        assert!(line.contains("ip daddr 1.2.3.4/32"));
        assert!(line.contains("drop"));
        assert!(line.contains("comment \"known C2\""));
    }

    #[test]
    fn port_rule_renders() {
        let r = Rule {
            action: Action::Drop,
            direction: Direction::In,
            protocol: Protocol::Tcp,
            port: Some(23),
            remote: None,
            comment: String::new(),
        };
        let line = r.to_nft();
        assert!(line.contains("tcp dport 23"));
        assert!(line.contains("drop"));
    }

    #[test]
    fn script_has_table_and_chains() {
        let mut rs = Ruleset::default();
        rs.add(Rule::block_ip("10.0.0.9/32".parse().unwrap(), "test"));
        let script = rs.to_nft_script();
        assert!(script.contains("add table inet aegis"));
        assert!(script.contains("flush table inet aegis"));
        assert!(script.contains("chain inet aegis output"));
        assert!(script.contains("10.0.0.9/32"));
    }

    #[test]
    fn remove_ip_works() {
        let mut rs = Ruleset::default();
        let net: IpNetwork = "5.5.5.5/32".parse().unwrap();
        rs.add(Rule::block_ip(net, "x"));
        assert_eq!(rs.remove_ip(&net), 1);
        assert!(rs.rules.is_empty());
    }
}
