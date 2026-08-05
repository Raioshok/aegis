//! CLI subcommands for the firewall, network IDS and plugin SDK (Milestone 5).

use crate::render::{self, BOLD, CYAN, DIM, GREEN, RED, RESET};
use aegis_core::{paths, Detection, Severity};
use aegis_firewall::model::{Rule, Ruleset};
use aegis_network::IpBlocklist;
use aegis_plugin::{KeyPair, PluginStatus, TrustStore};
use std::path::PathBuf;

fn firewall_state() -> PathBuf {
    paths::config_dir().join("firewall.json")
}
fn blocklist_file() -> PathBuf {
    paths::config_dir().join("ip-blocklist.txt")
}
fn plugins_dir() -> PathBuf {
    paths::config_dir().join("plugins")
}
fn trust_file() -> PathBuf {
    paths::config_dir().join("trusted-keys.txt")
}

fn load_ruleset() -> Ruleset {
    match std::fs::read_to_string(firewall_state()) {
        Ok(t) => serde_json::from_str(&t).unwrap_or_default(),
        Err(_) => Ruleset::default(),
    }
}
fn save_ruleset(rs: &Ruleset) -> Result<(), String> {
    paths::ensure_dirs().map_err(|e| e.to_string())?;
    std::fs::write(
        firewall_state(),
        serde_json::to_string_pretty(rs).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn print_detections(title: &str, dets: &[Detection]) -> i32 {
    println!("{BOLD}{title}{RESET}");
    if dets.is_empty() {
        println!("  {}", render::paint(GREEN, "✓ nothing suspicious found"));
        return 0;
    }
    let mut worst = Severity::Clean;
    for d in dets {
        worst = worst.max(d.severity);
        println!(
            "  {}  {}",
            render::sev_paint(d.severity, &format!("[{}]", d.severity.label())),
            d.threat
        );
        println!("        {DIM}{}{RESET}", d.detail);
    }
    if worst >= Severity::High {
        1
    } else {
        0
    }
}

// --- firewall ---------------------------------------------------------

#[allow(clippy::print_literal)]
pub fn firewall_connections() -> i32 {
    let conns = aegis_firewall::connections::all();
    println!(
        "{BOLD}{:<7}{:<24}{:<24}{}{RESET}",
        "PROTO", "LOCAL", "REMOTE", "STATE"
    );
    for c in conns
        .iter()
        .filter(|c| c.remote_port != 0 || c.is_listening())
    {
        println!(
            "{:<7}{:<24}{:<24}{}",
            c.protocol,
            format!("{}:{}", c.local, c.local_port),
            format!("{}:{}", c.remote, c.remote_port),
            c.state
        );
    }
    println!("{DIM}{} sockets{RESET}", conns.len());
    0
}

pub fn firewall_block(ip: &str, comment: Option<String>) -> i32 {
    let net = match ip.parse() {
        Ok(n) => n,
        Err(_) => match ip.parse::<std::net::IpAddr>() {
            Ok(a) => ipnetwork_single(a),
            Err(_) => {
                eprintln!("invalid IP/CIDR: {ip}");
                return 2;
            }
        },
    };
    let mut rs = load_ruleset();
    rs.add(Rule::block_ip(
        net,
        comment.unwrap_or_else(|| "aegis block".into()),
    ));
    if let Err(e) = save_ruleset(&rs) {
        eprintln!("failed to save ruleset: {e}");
        return 2;
    }
    println!("Blocked {net} (saved). Applying…");
    apply_ruleset(&rs)
}

pub fn firewall_unblock(ip: &str) -> i32 {
    let net = match ip.parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("invalid CIDR: {ip}");
            return 2;
        }
    };
    let mut rs = load_ruleset();
    let removed = rs.remove_ip(&net);
    let _ = save_ruleset(&rs);
    println!("Removed {removed} rule(s) for {net}. Applying…");
    apply_ruleset(&rs)
}

pub fn firewall_list() -> i32 {
    let rs = load_ruleset();
    println!("{BOLD}Aegis firewall rules ({}){RESET}", rs.rules.len());
    for r in &rs.rules {
        println!("  {CYAN}{}{RESET}", r.to_nft());
    }
    if rs.rules.is_empty() {
        println!("  {DIM}(none){RESET}");
    }
    // Try to show the live kernel table too.
    match aegis_firewall::apply::list() {
        Ok(dump) if !dump.trim().is_empty() => {
            println!("\n{DIM}live kernel table:{RESET}\n{dump}");
        }
        _ => {}
    }
    0
}

fn apply_ruleset(rs: &Ruleset) -> i32 {
    match aegis_firewall::apply::apply(rs) {
        Ok(()) => {
            println!("{} applied to kernel", render::paint(GREEN, "✓"));
            0
        }
        Err(e) => {
            eprintln!(
                "{}",
                render::paint(
                    RED,
                    &format!("could not apply (needs root — try `sudo aegis firewall apply`): {e}")
                )
            );
            // Rules are saved regardless; non-fatal.
            0
        }
    }
}

pub fn firewall_apply() -> i32 {
    apply_ruleset(&load_ruleset())
}

pub fn firewall_flush() -> i32 {
    match aegis_firewall::apply::flush() {
        Ok(()) => {
            println!("{} flushed the aegis table", render::paint(GREEN, "✓"));
            0
        }
        Err(e) => {
            eprintln!("flush failed (needs root?): {e}");
            2
        }
    }
}

fn ipnetwork_single(a: std::net::IpAddr) -> ipnetwork::IpNetwork {
    ipnetwork::IpNetwork::new(a, if a.is_ipv4() { 32 } else { 128 }).expect("valid single-host net")
}

// --- network IDS ------------------------------------------------------

pub fn network_scan(json: bool) -> i32 {
    let bl = IpBlocklist::from_file(&blocklist_file());
    let dets = aegis_network::scan(&bl);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&dets).unwrap_or_default()
        );
        return if dets.iter().any(|d| d.severity >= Severity::High) {
            1
        } else {
            0
        };
    }
    let title = format!("Network scan ({} blocklisted nets loaded)", bl.len());
    print_detections(&title, &dets)
}

// --- plugins ----------------------------------------------------------

pub fn plugins_list() -> i32 {
    let trust = TrustStore::load(&trust_file());
    let plugins = aegis_plugin::discover(&plugins_dir(), &trust);
    println!("{BOLD}Plugins in {}{RESET}", plugins_dir().display());
    if plugins.is_empty() {
        println!("  {DIM}(none installed){RESET}");
        return 0;
    }
    for p in &plugins {
        let (label, color) = match &p.status {
            PluginStatus::Trusted => ("trusted", GREEN),
            PluginStatus::Untrusted => ("UNTRUSTED", RED),
            PluginStatus::Incompatible => ("incompatible", render::DIM),
            PluginStatus::Invalid(_) => ("invalid", RED),
        };
        let name = p.manifest.as_ref().map(|m| m.name.as_str()).unwrap_or("?");
        println!(
            "  {} {}  {DIM}{}{RESET}",
            render::paint(color, &format!("[{label}]")),
            name,
            p.dir.display()
        );
    }
    0
}

pub fn plugins_verify(dir: &std::path::Path) -> i32 {
    let trust = TrustStore::load(&trust_file());
    let p = aegis_plugin::evaluate(dir, &trust);
    match p.status {
        PluginStatus::Trusted => {
            println!(
                "{} plugin signature is valid and trusted",
                render::paint(GREEN, "✓")
            );
            if let Some(m) = &p.manifest {
                println!("  {DIM}permissions: {:?}{RESET}", m.permissions);
            }
            0
        }
        other => {
            println!("{} not trusted: {:?}", render::paint(RED, "✗"), other);
            2
        }
    }
}

pub fn plugins_keygen() -> i32 {
    let kp = KeyPair::generate();
    println!("{BOLD}New Aegis plugin signing key{RESET}");
    println!(
        "  {DIM}public  (add to trusted-keys.txt){RESET}  {}",
        kp.public_hex()
    );
    println!(
        "  {DIM}private (keep secret){RESET}                {}",
        kp.private_hex()
    );
    0
}
