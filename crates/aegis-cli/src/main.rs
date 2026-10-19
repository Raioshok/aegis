//! # aegis — command-line interface
//!
//! The user-facing entry point for the Aegis platform. In later milestones the
//! same commands proxy to the background daemon over IPC; today they run the
//! scan engine directly in-process.

mod behavior_cmds;
mod commands;
mod context;
mod daemon_cmds;
mod net_cmds;
mod optimize_cmds;
mod render;

use clap::{Parser, Subcommand};
use context::App;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "aegis",
    version,
    about = "Aegis — next-generation antivirus for Linux",
    long_about = None,
)]
struct Cli {
    /// Emit machine-readable JSON where supported.
    #[arg(long, global = true)]
    json: bool,

    /// Increase log verbosity (-v, -vv).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a specific file or directory.
    Scan {
        /// Path to scan.
        path: PathBuf,
    },
    /// Quick scan of common high-risk locations in your home directory.
    Quick,
    /// Full system scan starting from `/` (may require privileges).
    Full,
    /// Show engine status and configuration.
    Engines,
    /// Show recent scan history.
    History {
        #[arg(long, default_value_t = 20)]
        limit: i64,
    },
    /// Manage the trusted-project whitelist.
    Whitelist {
        #[command(subcommand)]
        action: WhitelistCmd,
    },
    /// Manage quarantined files.
    Quarantine {
        #[command(subcommand)]
        action: QuarantineCmd,
    },
    /// Run the background daemon in the foreground (real-time + IPC + scheduler).
    Daemon,
    /// Query the running daemon's status.
    Status,
    /// Real-time protection controls.
    Realtime {
        #[command(subcommand)]
        action: RealtimeCmd,
    },
    /// Ask the daemon to reload its configuration and whitelist.
    Reload,
    /// Ask the daemon to shut down.
    Stop,
    /// Scan the system for rootkits (cross-view /proc & /sys integrity checks).
    Rootkit,
    /// Scan process memory for injection / W^X / deleted-backing code.
    Memory {
        /// A specific PID to scan (default: all accessible processes).
        pid: Option<u32>,
    },
    /// Run a command confined by Landlock + resource limits.
    Sandbox {
        /// Extra paths the command may read/execute (repeatable).
        #[arg(long = "allow-read", value_name = "PATH")]
        allow_read: Vec<PathBuf>,
        /// Extra paths the command may write (repeatable).
        #[arg(long = "allow-write", value_name = "PATH")]
        allow_write: Vec<PathBuf>,
        /// CPU-seconds limit for the command.
        #[arg(long)]
        cpu: Option<u64>,
        /// The command and its arguments, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Manage the Aegis nftables firewall.
    Firewall {
        #[command(subcommand)]
        action: FirewallCmd,
    },
    /// Scan live network connections for C2 / backdoor / Tor indicators.
    Network,
    /// Score domain names for DNS-tunneling / DGA characteristics.
    Dns {
        /// Domains to score (default: read ~/.config/aegis/dns-queries.txt).
        domains: Vec<String>,
    },
    /// Manage signed plugins.
    Plugins {
        #[command(subcommand)]
        action: PluginsCmd,
    },
    /// System & network optimization (Arch tune-up).
    Optimize {
        #[command(subcommand)]
        action: Option<OptimizeCmd>,
    },
    /// Manage Windows / Linux startup autostart.
    Autostart {
        #[command(subcommand)]
        action: AutostartCmd,
    },
    /// Kaspersky-style Game Mode controls (auto-detect full-screen & throttle CPU).
    Gamemode {
        #[command(subcommand)]
        action: Option<GameModeCmd>,
    },
    /// Manage modular protection shields.
    Shields {
        #[command(subcommand)]
        action: Option<ShieldsCmd>,
    },
    /// Telemetry & training gateway for guest detonation labs.
    Gateway {
        #[command(subcommand)]
        action: Option<GatewayCmd>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum GatewayCmd {
    /// Start the telemetry and training gateway server.
    Start {
        #[arg(long, default_value_t = 9090)]
        port: u16,
    },
    /// Query current detonation lab telemetry stats.
    Status {
        #[arg(long, default_value_t = 9090)]
        port: u16,
    },
}

#[derive(Subcommand, Debug, Clone, Copy)]
enum GameModeCmd {
    /// Check live Game Mode status and full-screen D3D detection.
    Status,
    /// Enable Game Mode (throttles background scans & drops CPU priority).
    Enable,
    /// Disable Game Mode (restores full background scanning).
    Disable,
}

#[derive(Subcommand, Debug, Clone, Copy)]
enum ShieldsCmd {
    /// Show all modular shields and their armed status.
    Status,
    /// Enable all defensive shields.
    EnableAll,
    /// Disable all defensive shields.
    DisableAll,
}

#[derive(Subcommand, Debug)]
enum AutostartCmd {
    /// Check whether autostart on system boot is enabled.
    Status,
    /// Enable starting Aegis automatically on login.
    Enable,
    /// Disable starting Aegis automatically on login.
    Disable,
}

#[derive(Subcommand)]
enum OptimizeCmd {
    /// Full read-only scan (default).
    Scan,
    /// Network-only tune-up scan.
    Network,
    /// Reclaim disk space (dry-run unless --apply).
    Clean {
        /// Actually perform the cleanup (privileged steps need sudo).
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        pacman: bool,
        #[arg(long)]
        journal: bool,
        #[arg(long)]
        orphans: bool,
        /// Include clearing ~/.cache (close apps first).
        #[arg(long)]
        user_cache: bool,
    },
    /// Apply the recommended network sysctl profile (dry-run unless --apply).
    Tune {
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum FirewallCmd {
    /// List live network connections.
    Connections,
    /// Block an IP or CIDR.
    Block {
        ip: String,
        #[arg(long)]
        comment: Option<String>,
    },
    /// Remove a block for an IP or CIDR.
    Unblock { ip: String },
    /// Show the Aegis rules (and live kernel table).
    List,
    /// Re-apply the saved ruleset to the kernel (needs root).
    Apply,
    /// Remove the Aegis nftables table (needs root).
    Flush,
}

#[derive(Subcommand)]
enum PluginsCmd {
    /// List installed plugins and their trust status.
    List,
    /// Verify a plugin directory's signature.
    Verify { dir: PathBuf },
    /// Generate a new plugin signing key pair.
    Keygen,
    /// Sign a plugin's manifest with a private key.
    Sign {
        dir: PathBuf,
        #[arg(long)]
        key: String,
    },
    /// Execute a trusted plugin (enforcing its signature + permissions).
    Run {
        dir: PathBuf,
        #[arg(long)]
        target: Option<String>,
    },
}

#[derive(Subcommand)]
enum RealtimeCmd {
    /// Show real-time protection status.
    Status,
}

#[derive(Subcommand)]
enum WhitelistCmd {
    /// Trust a project folder or file.
    Add {
        path: PathBuf,
        #[arg(long)]
        label: Option<String>,
        /// Trust only this exact path, not its subtree.
        #[arg(long)]
        no_recursive: bool,
    },
    /// Remove a whitelist rule by its value (path or hash).
    Remove { value: String },
    /// List whitelist rules.
    List,
}

#[derive(Subcommand)]
enum QuarantineCmd {
    /// List quarantined files.
    List,
    /// Quarantine a detected file now.
    Add { path: PathBuf },
    /// Restore a quarantined file by its sha256.
    Restore { sha256: String },
    /// Permanently delete a quarantined file by its sha256.
    Delete { sha256: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let code = match run(&cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            2
        }
    };
    ExitCode::from(code as u8)
}

fn run(cli: &Cli) -> aegis_core::Result<i32> {
    // Daemon/whitelist commands don't build the in-process App (DB); they either
    // run the daemon or talk to it over IPC. Everything else builds App.
    match &cli.command {
        Command::Whitelist { action } => match action {
            WhitelistCmd::Add {
                path,
                label,
                no_recursive,
            } => commands::whitelist_add(path, label.clone(), !no_recursive),
            WhitelistCmd::Remove { value } => commands::whitelist_remove(value),
            WhitelistCmd::List => commands::whitelist_list(),
        },
        Command::Daemon => Ok(daemon_cmds::run_daemon()),
        Command::Status => Ok(daemon_cmds::status(cli.json)),
        Command::Realtime { action } => match action {
            RealtimeCmd::Status => Ok(daemon_cmds::realtime_status()),
        },
        Command::Reload => Ok(daemon_cmds::reload()),
        Command::Stop => Ok(daemon_cmds::stop()),
        Command::Rootkit => Ok(behavior_cmds::rootkit(cli.json)),
        Command::Memory { pid } => Ok(behavior_cmds::memory(*pid, cli.json)),
        Command::Firewall { action } => Ok(match action {
            FirewallCmd::Connections => net_cmds::firewall_connections(),
            FirewallCmd::Block { ip, comment } => net_cmds::firewall_block(ip, comment.clone()),
            FirewallCmd::Unblock { ip } => net_cmds::firewall_unblock(ip),
            FirewallCmd::List => net_cmds::firewall_list(),
            FirewallCmd::Apply => net_cmds::firewall_apply(),
            FirewallCmd::Flush => net_cmds::firewall_flush(),
        }),
        Command::Network => Ok(net_cmds::network_scan(cli.json)),
        Command::Dns { domains } => Ok(net_cmds::dns_check(domains)),
        Command::Plugins { action } => Ok(match action {
            PluginsCmd::List => net_cmds::plugins_list(),
            PluginsCmd::Verify { dir } => net_cmds::plugins_verify(dir),
            PluginsCmd::Keygen => net_cmds::plugins_keygen(),
            PluginsCmd::Sign { dir, key } => net_cmds::plugins_sign(dir, key),
            PluginsCmd::Run { dir, target } => net_cmds::plugins_run(dir, target.clone()),
        }),
        Command::Optimize { action } => Ok(match action {
            None | Some(OptimizeCmd::Scan) => optimize_cmds::scan(cli.json),
            Some(OptimizeCmd::Network) => optimize_cmds::network(cli.json),
            Some(OptimizeCmd::Clean {
                apply,
                pacman,
                journal,
                orphans,
                user_cache,
            }) => optimize_cmds::clean(*apply, *pacman, *journal, *orphans, *user_cache),
            Some(OptimizeCmd::Tune { apply }) => optimize_cmds::tune(*apply),
        }),
        Command::Sandbox {
            allow_read,
            allow_write,
            cpu,
            command,
        } => Ok(behavior_cmds::sandbox(
            allow_read.clone(),
            allow_write.clone(),
            *cpu,
            command.clone(),
        )),
        Command::Autostart { action } => {
            let mgr = aegis_platform::default_autostart();
            match action {
                AutostartCmd::Status => {
                    let active = mgr.is_enabled();
                    println!("Aegis autostart: {}", if active { "ENABLED (starts on user logon)" } else { "DISABLED" });
                }
                AutostartCmd::Enable => {
                    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aegis"));
                    mgr.set_enabled(true, &current_exe)?;
                    println!("Aegis autostart enabled: registered in startup registry & task scheduler.");
                }
                AutostartCmd::Disable => {
                    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aegis"));
                    mgr.set_enabled(false, &current_exe)?;
                    println!("Aegis autostart disabled: removed from startup registry & task scheduler.");
                }
            }
            Ok(0)
        }
        Command::Gamemode { action } => {
            let action = action.unwrap_or(GameModeCmd::Status);
            let mut cfg = aegis_core::Config::load();
            let is_gaming = aegis_platform::is_gaming_active();
            match action {
                GameModeCmd::Status => {
                    println!("Aegis Kaspersky-Style Game Mode:");
                    println!("  Enabled:             {}", if cfg.game_mode.enabled { "YES" } else { "NO" });
                    println!("  Auto-Detect Fullscreen/D3D: {}", if cfg.game_mode.auto_detect { "YES" } else { "NO" });
                    println!("  Live Game Detected:  {}", if is_gaming { "YES (Active Full-Screen App)" } else { "NO" });
                    let throttled = cfg.game_mode.enabled && (is_gaming || !cfg.game_mode.auto_detect);
                    println!("  CPU Priority:        {}", if throttled { "IDLE_PRIORITY_CLASS (Throttled)" } else { "NORMAL_PRIORITY_CLASS" });
                    println!("  Background Scans:    {}", if throttled { "PAUSED" } else { "ACTIVE" });
                }
                GameModeCmd::Enable => {
                    cfg.game_mode.enabled = true;
                    cfg.save()?;
                    println!("Game Mode enabled. CPU will automatically throttle when games launch.");
                }
                GameModeCmd::Disable => {
                    cfg.game_mode.enabled = false;
                    cfg.save()?;
                    aegis_platform::set_process_resource_mode(false);
                    println!("Game Mode disabled. Running in full performance mode.");
                }
            }
            Ok(0)
        }
        Command::Shields { action } => {
            let action = action.unwrap_or(ShieldsCmd::Status);
            let mut cfg = aegis_core::Config::load();
            match action {
                ShieldsCmd::Status => {
                    println!("Aegis Modular Protection Shields:");
                    println!("  Real-time File System: {}", if cfg.shields.realtime_filesystem { "ARMED" } else { "OFF" });
                    println!("  Memory & Injection:    {}", if cfg.shields.memory_defense { "ARMED" } else { "OFF" });
                    println!("  Network & Firewall:    {}", if cfg.shields.network_firewall { "ARMED" } else { "OFF" });
                    println!("  Ransomware Watchdog:   {}", if cfg.shields.ransomware_guard { "ARMED" } else { "OFF" });
                    println!("  Cloud Threat Feeds:    {}", if cfg.shields.cloud_threat_feeds { "ARMED" } else { "OFF" });
                }
                ShieldsCmd::EnableAll => {
                    cfg.shields.realtime_filesystem = true;
                    cfg.shields.memory_defense = true;
                    cfg.shields.network_firewall = true;
                    cfg.shields.ransomware_guard = true;
                    cfg.shields.cloud_threat_feeds = true;
                    cfg.save()?;
                    println!("All protection shields ARMED.");
                }
                ShieldsCmd::DisableAll => {
                    cfg.shields.realtime_filesystem = false;
                    cfg.shields.memory_defense = false;
                    cfg.shields.network_firewall = false;
                    cfg.shields.ransomware_guard = false;
                    cfg.shields.cloud_threat_feeds = false;
                    cfg.save()?;
                    println!("All protection shields DISABLED.");
                }
            }
            Ok(0)
        }
        Command::Gateway { action } => {
            let action = action.clone().unwrap_or(GatewayCmd::Start { port: 9090 });
            match action {
                GatewayCmd::Start { port } => {
                    println!("Aegis Telemetry & Training Gateway starting on 0.0.0.0:{port}...");
                    println!("Listening for guest VM reports on host-only adapter (192.168.58.1:{port})");
                    let server = aegis_daemon::GatewayServer::new(port);
                    let rt = tokio::runtime::Runtime::new()
                        .map_err(|e| aegis_core::AegisError::Engine { engine: "gateway".into(), reason: e.to_string() })?;
                    rt.block_on(async {
                        server.run().await
                    })
                    .map_err(|e| aegis_core::AegisError::Engine { engine: "gateway".into(), reason: e.to_string() })?;
                    Ok(0)
                }
                GatewayCmd::Status { port } => {
                    let rt = tokio::runtime::Runtime::new()
                        .map_err(|e| aegis_core::AegisError::Engine { engine: "gateway".into(), reason: e.to_string() })?;
                    rt.block_on(async {
                        let client = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await;
                        match client {
                            Ok(mut stream) => {
                                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                                let req = format!("GET /api/v1/telemetry/stats HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
                                let _ = stream.write_all(req.as_bytes()).await;
                                let mut buf = vec![0u8; 4096];
                                if let Ok(n) = stream.read(&mut buf).await {
                                    let s = String::from_utf8_lossy(&buf[..n]);
                                    if let Some(pos) = s.find("\r\n\r\n") {
                                        println!("{}", &s[pos + 4..]);
                                    } else {
                                        println!("{s}");
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Gateway not reachable on port {port}: {e}");
                            }
                        }
                    });
                    Ok(0)
                }
            }
        }
        other => {
            let app = App::new()?;
            match other {
                Command::Scan { path } => commands::scan(&app, path, "custom", cli.json),
                Command::Quick => commands::scan(&app, &commands::home_target(), "quick", cli.json),
                Command::Full => commands::scan(&app, std::path::Path::new("/"), "full", cli.json),
                Command::Engines => commands::engines(&app),
                Command::History { limit } => commands::history(&app, *limit),
                Command::Quarantine { action } => match action {
                    QuarantineCmd::List => commands::quarantine_list(&app),
                    QuarantineCmd::Add { path } => commands::quarantine_add(&app, path),
                    QuarantineCmd::Restore { sha256 } => commands::quarantine_restore(&app, sha256),
                    QuarantineCmd::Delete { sha256 } => commands::quarantine_delete(&app, sha256),
                },
                // Daemon/whitelist variants are handled at the top level.
                _ => unreachable!("handled before App construction"),
            }
        }
    }
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| format!("aegis={level}"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();
}
