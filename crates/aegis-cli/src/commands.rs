//! Implementation of each CLI subcommand.

use crate::context::App;
use crate::render::{self, BOLD, CYAN, DIM, RESET};
use aegis_core::{now_epoch, paths, Event, FileVerdict, Whitelist};
use aegis_quarantine::Quarantine;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Run a scan over `target` and persist results. `kind` labels the scan
/// (quick/full/custom) in history.
pub fn scan(app: &App, target: &Path, kind: &str, json: bool) -> aegis_core::Result<i32> {
    if !target.exists() {
        eprintln!("{}: no such path", target.display());
        return Ok(2);
    }

    // Live progress on the event bus (skipped in JSON mode).
    if !json {
        let last = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
        app.bus.subscribe(Arc::new(move |ev: &Event| match ev {
            Event::ScanStarted { target, total } => {
                println!(
                    "{}Scanning{} {} ({} files)…",
                    CYAN,
                    RESET,
                    target.display(),
                    total
                );
            }
            Event::FileScanned { index, total, .. } => {
                // throttle progress to ~10/s to avoid spamming the terminal
                let mut l = last.lock().unwrap();
                if l.elapsed().as_millis() >= 100 || index == total {
                    print!("\r{DIM}  {index}/{total}{RESET}   ");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    *l = std::time::Instant::now();
                }
            }
            Event::ThreatFound(v) => {
                print!("\r");
                print_threat(v);
            }
            _ => {}
        }));
    }

    let scanner = app.scanner();
    let started = now_epoch();
    let (stats, verdicts) = scanner.scan(target);

    // Persist to history.
    let repo = app.db.scans();
    let scan_id = repo.insert_scan(
        started,
        now_epoch(),
        &target.to_string_lossy(),
        stats.scanned as i64,
        stats.threats as i64,
        kind,
    )?;
    for v in verdicts.iter().filter(|v| v.is_threat()) {
        for d in &v.detections {
            repo.insert_threat(
                scan_id,
                now_epoch(),
                &v.path.to_string_lossy(),
                &v.sha256,
                &d.threat,
                &d.engine,
                d.severity as i64,
                "detected",
            )?;
        }
    }

    if json {
        let threats: Vec<&FileVerdict> = verdicts.iter().filter(|v| v.is_threat()).collect();
        let out = serde_json::json!({
            "target": target.to_string_lossy(),
            "stats": stats,
            "threats": threats,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print!("\r");
        render::print_summary(&stats);
    }

    Ok(if stats.threats > 0 { 1 } else { 0 })
}

fn print_threat(v: &FileVerdict) {
    let sev = v.severity();
    println!(
        "{}  {}",
        render::sev_paint(sev, &format!("[{}]", sev.label())),
        v.path.display()
    );
    for d in &v.detections {
        println!(
            "        {DIM}{}{RESET} {} — {}",
            d.engine, d.threat, d.detail
        );
    }
}

/// Show engine readiness and configuration.
pub fn engines(app: &App) -> aegis_core::Result<i32> {
    let scanner = app.scanner();
    println!("{BOLD}Aegis engines{RESET}");
    for e in scanner.engines() {
        println!("  {CYAN}{:<10}{RESET} {}", e.name(), e.status());
    }
    let (scans, files, threats) = app.db.scans().totals()?;
    println!("\n{DIM}history:{RESET} {scans} scans · {files} files · {threats} threats");
    println!("{DIM}config:{RESET}  {}", paths::config_file().display());
    Ok(0)
}

/// Whitelist management.
pub fn whitelist_add(
    path: &Path,
    label: Option<String>,
    recursive: bool,
) -> aegis_core::Result<i32> {
    let mut wl = Whitelist::load();
    wl.add_path(path, label.unwrap_or_default(), recursive, now_epoch());
    wl.save()?;
    println!("Whitelisted {}", path.display());
    Ok(0)
}

pub fn whitelist_remove(value: &str) -> aegis_core::Result<i32> {
    let mut wl = Whitelist::load();
    if wl.remove(value) {
        wl.save()?;
        println!("Removed whitelist rule: {value}");
        Ok(0)
    } else {
        eprintln!("No whitelist rule matched: {value}");
        Ok(2)
    }
}

#[allow(clippy::print_literal)]
pub fn whitelist_list() -> aegis_core::Result<i32> {
    let wl = Whitelist::load();
    if wl.rules.is_empty() {
        println!("{DIM}(whitelist is empty){RESET}");
        return Ok(0);
    }
    println!("{BOLD}{:<10} {:<9} {}{RESET}", "TYPE", "SCOPE", "VALUE");
    for r in &wl.rules {
        let kind = format!("{:?}", r.kind).to_lowercase();
        let scope = if matches!(r.kind, aegis_core::whitelist::RuleKind::Path) {
            if r.recursive {
                "recursive"
            } else {
                "single"
            }
        } else {
            "hash"
        };
        println!("{:<10} {:<9} {}", kind, scope, r.value);
    }
    Ok(0)
}

/// Quarantine subcommands.
#[allow(clippy::print_literal)]
pub fn quarantine_list(app: &App) -> aegis_core::Result<i32> {
    let q = Quarantine::open(&app.db)?;
    let items = q.list()?;
    if items.is_empty() {
        println!("{DIM}(quarantine is empty){RESET}");
        return Ok(0);
    }
    println!(
        "{BOLD}{:<20} {:<24} {}{RESET}",
        "WHEN", "THREAT", "ORIGINAL PATH"
    );
    for it in items {
        println!(
            "{:<20} {:<24} {}",
            render::fmt_epoch(it.quarantined_at),
            truncate(&it.threat, 24),
            it.original_path
        );
        println!(
            "  {DIM}sha256={} size={}{RESET}",
            it.sha256,
            render::human_bytes(it.size as u64)
        );
    }
    Ok(0)
}

pub fn quarantine_add(app: &App, path: &Path) -> aegis_core::Result<i32> {
    // Scan the single file to obtain a verdict (hash + threat name).
    let scanner = app.scanner();
    let v = scanner.scan_file(path);
    if !v.is_threat() {
        eprintln!(
            "{} is not detected as a threat; refusing to quarantine.",
            path.display()
        );
        return Ok(2);
    }
    let top = v.top_detection().unwrap();
    let q = Quarantine::open(&app.db)?;
    q.quarantine(
        path,
        &v.sha256,
        &top.threat,
        &top.engine,
        v.severity() as i64,
        now_epoch(),
    )?;
    println!("Quarantined {} ({})", path.display(), top.threat);
    Ok(0)
}

pub fn quarantine_restore(app: &App, sha256: &str) -> aegis_core::Result<i32> {
    let q = Quarantine::open(&app.db)?;
    let dest = q.restore(sha256)?;
    println!("Restored {}", dest.display());
    Ok(0)
}

pub fn quarantine_delete(app: &App, sha256: &str) -> aegis_core::Result<i32> {
    let q = Quarantine::open(&app.db)?;
    q.delete(sha256)?;
    println!("Deleted {sha256} from quarantine");
    Ok(0)
}

/// Scan history.
#[allow(clippy::print_literal)]
pub fn history(app: &App, limit: i64) -> aegis_core::Result<i32> {
    let scans = app.db.scans().recent(limit)?;
    if scans.is_empty() {
        println!("{DIM}(no scans yet){RESET}");
        return Ok(0);
    }
    println!(
        "{BOLD}{:<20} {:<8} {:<8} {}{RESET}",
        "WHEN", "FILES", "THREATS", "TARGET"
    );
    for s in scans {
        println!(
            "{:<20} {:<8} {:<8} {}",
            render::fmt_epoch(s.finished),
            s.files_scanned,
            s.threats,
            s.target
        );
    }
    Ok(0)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

/// Convenience: default quick-scan target (the user's home directory).
pub fn home_target() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"))
}
