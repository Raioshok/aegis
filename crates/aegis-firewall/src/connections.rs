//! Live connection enumeration by parsing `/proc/net/{tcp,tcp6,udp,udp6}`.
//!
//! The kernel exposes socket tables as hex rows; the address/port parsing is a
//! pure function and unit-tested against known values.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// TCP connection states (from the kernel's `tcp_states` enum).
pub fn tcp_state(code: u8) -> &'static str {
    match code {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub protocol: &'static str, // "tcp" | "udp"
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
    pub state: &'static str,
    pub uid: u32,
    pub inode: u64,
}

impl Connection {
    pub fn is_listening(&self) -> bool {
        self.state == "LISTEN"
    }
    pub fn is_established(&self) -> bool {
        self.state == "ESTABLISHED"
    }
}

/// Parse a `HEXADDR:HEXPORT` token into an IP + port.
///
/// IPv4 addresses are 8 hex chars in **little-endian** byte order; IPv6 are 32
/// hex chars as four little-endian 32-bit words.
pub fn parse_addr(token: &str) -> Option<(IpAddr, u16)> {
    let (addr_hex, port_hex) = token.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = match addr_hex.len() {
        8 => {
            let raw = u32::from_str_radix(addr_hex, 16).ok()?;
            // bytes are little-endian in /proc
            IpAddr::V4(Ipv4Addr::from(raw.swap_bytes().to_be_bytes()))
        }
        32 => {
            let mut octets = [0u8; 16];
            for i in 0..4 {
                let word = u32::from_str_radix(&addr_hex[i * 8..i * 8 + 8], 16).ok()?;
                let be = word.swap_bytes().to_be_bytes();
                octets[i * 4..i * 4 + 4].copy_from_slice(&be);
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some((ip, port))
}

/// Parse a single `/proc/net/tcp` data row into a [`Connection`].
pub fn parse_row(line: &str, protocol: &'static str) -> Option<Connection> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 10 {
        return None;
    }
    let (local, local_port) = parse_addr(f[1])?;
    let (remote, remote_port) = parse_addr(f[2])?;
    let state_code = u8::from_str_radix(f[3], 16).ok()?;
    let uid = f[7].parse::<u32>().ok()?;
    let inode = f[9].parse::<u64>().ok()?;
    Some(Connection {
        protocol,
        local,
        local_port,
        remote,
        remote_port,
        state: if protocol == "tcp" {
            tcp_state(state_code)
        } else {
            "—"
        },
        uid,
        inode,
    })
}

fn read_table(path: &Path, protocol: &'static str, out: &mut Vec<Connection>) {
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines().skip(1) {
            if let Some(c) = parse_row(line, protocol) {
                out.push(c);
            }
        }
    }
}

/// Enumerate all TCP/UDP connections (IPv4 + IPv6).
pub fn all() -> Vec<Connection> {
    let mut out = Vec::new();
    read_table(Path::new("/proc/net/tcp"), "tcp", &mut out);
    read_table(Path::new("/proc/net/tcp6"), "tcp", &mut out);
    read_table(Path::new("/proc/net/udp"), "udp", &mut out);
    read_table(Path::new("/proc/net/udp6"), "udp", &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_localhost_dns() {
        // 0100007F:0035 == 127.0.0.1:53
        let (ip, port) = parse_addr("0100007F:0035").unwrap();
        assert_eq!(ip.to_string(), "127.0.0.1");
        assert_eq!(port, 53);
    }

    #[test]
    fn parses_row() {
        let line = "   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000 100";
        let c = parse_row(line, "tcp").unwrap();
        assert_eq!(c.local.to_string(), "127.0.0.1");
        assert_eq!(c.local_port, 53);
        assert_eq!(c.state, "LISTEN");
        assert!(c.is_listening());
        assert_eq!(c.inode, 12345);
    }

    #[test]
    fn state_decoding() {
        assert_eq!(tcp_state(0x0A), "LISTEN");
        assert_eq!(tcp_state(0x01), "ESTABLISHED");
    }

    #[test]
    fn live_enumeration_runs() {
        // Should return something on any running system (at least loopback).
        let _ = all();
    }
}
