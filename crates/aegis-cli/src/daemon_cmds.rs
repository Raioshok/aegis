//! CLI subcommands that talk to (or launch) the daemon over IPC.

use crate::render::{self, BOLD, CYAN, DIM, GREEN, RED, RESET};
use aegis_ipc::protocol::{Request, Response};
use aegis_ipc::Client;

/// Run the daemon in the foreground (used by the systemd unit as `aegis daemon`).
pub fn run_daemon() -> i32 {
    aegis_daemon::init_logging();
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to start runtime: {e}");
            return 2;
        }
    };
    match rt.block_on(aegis_daemon::run()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("daemon error: {e}");
            2
        }
    }
}

/// Block on a single IPC round-trip.
fn call(req: Request) -> Result<Response, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async {
        let client = Client::new();
        client.request(&req).await.map_err(|e| e.to_string())
    })
}

fn not_running_hint() {
    eprintln!(
        "{}",
        render::paint(
            RED,
            "Aegis daemon is not running. Start it with `aegis daemon` \
             (or `systemctl start aegis-daemon`)."
        )
    );
}

/// `aegis status` — daemon health snapshot.
pub fn status(json: bool) -> i32 {
    match call(Request::Status) {
        Ok(Response::Status(s)) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&s).unwrap_or_default());
                return 0;
            }
            println!("{BOLD}Aegis daemon{RESET}  (pid {}, v{})", s.pid, s.version);
            let up = format_uptime(s.uptime_secs);
            println!("  {DIM}uptime{RESET}   {up}");
            println!("  {DIM}scans{RESET}    {}", s.scans_run);
            println!("  {DIM}threats{RESET}  {}", s.threats_found);
            let rt = &s.realtime;
            let rt_state = if rt.enabled {
                render::paint(GREEN, "on")
            } else {
                render::paint(DIM, "off")
            };
            println!(
                "  {DIM}realtime{RESET} {rt_state} · {} · {} events · {} blocked",
                rt.backend, rt.events_seen, rt.threats_blocked
            );
            if let Some(err) = &rt.error {
                println!("           {}", render::paint(RED, err));
            }
            println!("  {DIM}engines{RESET}");
            for e in &s.engines {
                println!("    {CYAN}{:<10}{RESET} {}", e.name, e.status);
            }
            0
        }
        Ok(Response::Error { message }) => {
            eprintln!("daemon error: {message}");
            2
        }
        Ok(_) => {
            eprintln!("unexpected response");
            2
        }
        Err(_) => {
            not_running_hint();
            2
        }
    }
}

/// `aegis realtime status`
pub fn realtime_status() -> i32 {
    match call(Request::RealtimeStatus) {
        Ok(Response::Realtime(rt)) => {
            let state = if rt.enabled { "enabled" } else { "disabled" };
            println!("{BOLD}Real-time protection: {state}{RESET}");
            println!("  backend: {}", rt.backend);
            println!("  watched:");
            for p in &rt.watched_paths {
                println!("    {}", p.display());
            }
            println!("  events seen:     {}", rt.events_seen);
            println!("  threats blocked: {}", rt.threats_blocked);
            0
        }
        Ok(Response::Error { message }) => {
            eprintln!("daemon error: {message}");
            2
        }
        Ok(_) => 2,
        Err(_) => {
            not_running_hint();
            2
        }
    }
}

/// `aegis reload` — ask the daemon to reload config + whitelist.
pub fn reload() -> i32 {
    ok_message(Request::ReloadConfig)
}

/// `aegis stop` — ask the daemon to shut down.
pub fn stop() -> i32 {
    ok_message(Request::Shutdown)
}

fn ok_message(req: Request) -> i32 {
    match call(req) {
        Ok(Response::Ok { message }) => {
            println!("{} {message}", render::paint(GREEN, "✓"));
            0
        }
        Ok(Response::Error { message }) => {
            eprintln!("daemon error: {message}");
            2
        }
        Ok(_) => 2,
        Err(_) => {
            not_running_hint();
            2
        }
    }
}

fn format_uptime(secs: u64) -> String {
    let (d, h, m, s) = (
        secs / 86400,
        (secs % 86400) / 3600,
        (secs % 3600) / 60,
        secs % 60,
    );
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m {s}s")
    } else {
        format!("{m}m {s}s")
    }
}
