//! # aegis-network
//!
//! Network intrusion detection over live connections and DNS activity.
//!
//! * [`intel`] — CIDR threat-intel blocklist matching (C2 / malicious IPs).
//! * [`dns`] — DNS-tunneling / DGA suspicion scoring.
//! * [`analyze`] — classify live `/proc/net` connections (blocklist hits,
//!   backdoor/Tor ports, exposed listeners) into detections.
//!
//! Connection- and DNS-level analysis covers C2, reverse shells, DNS tunneling,
//! malicious IPs and Tor abuse without a packet-capture pipeline. Packet-level
//! eBPF/pcap inspection is a planned deepening.

#![forbid(unsafe_code)]

pub mod analyze;
pub mod dns;
pub mod intel;

pub use analyze::{classify, scan};
pub use dns::{is_suspicious, tunnel_score};
pub use intel::IpBlocklist;
