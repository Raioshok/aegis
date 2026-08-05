//! # aegis — command-line interface
//!
//! The user-facing entry point for the Aegis platform. In later milestones the
//! same commands proxy to the background daemon over IPC; today they run the
//! scan engine directly in-process.

mod commands;
mod context;
mod daemon_cmds;
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
