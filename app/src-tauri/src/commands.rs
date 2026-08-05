//! Tauri commands — the bridge between the React UI and the Aegis engine.
//!
//! Scans, history, quarantine, whitelist and behavioural checks run in-process
//! (so the UI is fully functional without the daemon); live daemon status and
//! real-time counters are fetched from the running daemon over `aegis-ipc`.

use aegis_behavior::{memory, rootkit};
use aegis_core::{now_epoch, paths, Config, Detection, FileVerdict, Severity, Whitelist};
use aegis_engine::{shared_engines, Engine, Scanner};
use aegis_ipc::protocol::Request;
use aegis_ipc::{Client, Response};
use aegis_quarantine::Quarantine;
use aegis_storage::Database;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Shared application state held by Tauri.
pub struct AppState {
    pub db: Arc<Database>,
    pub engines: Mutex<Arc<Vec<Box<dyn Engine>>>>,
}

impl AppState {
    pub fn new() -> Result<Self, String> {
        paths::ensure_dirs().map_err(|e| e.to_string())?;
        let db = Arc::new(Database::open(&paths::database_file()).map_err(|e| e.to_string())?);
        let cfg = Config::load();
        let engines = shared_engines(&cfg, &paths::user_rules_dir());
        Ok(Self {
            db,
            engines: Mutex::new(engines),
        })
    }

}

// --- DTOs -------------------------------------------------------------

#[derive(Serialize)]
pub struct EngineInfo {
    pub name: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct RealtimeInfo {
    pub enabled: bool,
    pub backend: String,
    pub events_seen: u64,
    pub threats_blocked: u64,
}

#[derive(Serialize)]
pub struct Dashboard {
    pub daemon_running: bool,
    pub version: String,
    pub scans: i64,
    pub files: i64,
    pub threats: i64,
    pub whitelist_count: usize,
    pub quarantine_count: usize,
    pub engines: Vec<EngineInfo>,
    pub realtime: Option<RealtimeInfo>,
}

#[derive(Serialize)]
pub struct ThreatRow {
    pub severity: u8,
    pub severity_label: String,
    pub path: PathBuf,
    pub sha256: String,
    pub names: String,
    pub engines: String,
}

#[derive(Serialize)]
pub struct ScanReport {
    pub target: PathBuf,
    pub total_files: u64,
    pub scanned: u64,
    pub threats: u64,
    pub duration_ms: u64,
    pub results: Vec<ThreatRow>,
}

#[derive(Serialize)]
pub struct HistoryRow {
    pub finished: i64,
    pub target: String,
    pub files: i64,
    pub threats: i64,
    pub kind: String,
}

#[derive(Serialize)]
pub struct QuarantineRow {
    pub sha256: String,
    pub original_path: String,
    pub threat: String,
    pub quarantined_at: i64,
    pub size: i64,
}

#[derive(Serialize)]
pub struct WhitelistRow {
    pub kind: String,
    pub value: String,
    pub label: String,
    pub recursive: bool,
}

// --- helpers ----------------------------------------------------------

fn threat_row(v: &FileVerdict) -> ThreatRow {
    let sev = v.severity();
    ThreatRow {
        severity: sev as u8,
        severity_label: sev.label().to_string(),
        path: v.path.clone(),
        sha256: v.sha256.clone(),
        names: v.threat_names(),
        engines: v
            .detections
            .iter()
            .map(|d| d.engine.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn detection_rows(dets: Vec<Detection>) -> Vec<ThreatRow> {
    dets.into_iter()
        .map(|d| ThreatRow {
            severity: d.severity as u8,
            severity_label: d.severity.label().to_string(),
            path: PathBuf::from(&d.detail),
            sha256: String::new(),
            names: d.threat,
            engines: d.engine,
        })
        .collect()
}

async fn daemon_status() -> Option<aegis_ipc::protocol::DaemonStatus> {
    let client = Client::new();
    match client.request(&Request::Status).await {
        Ok(Response::Status(s)) => Some(s),
        _ => None,
    }
}

// --- commands ---------------------------------------------------------

#[tauri::command]
pub async fn dashboard(state: tauri::State<'_, AppState>) -> Result<Dashboard, String> {
    let (scans, files, threats) = state.db.scans().totals().map_err(|e| e.to_string())?;
    let whitelist_count = Whitelist::load().rules.len();
    let quarantine_count = state.db.quarantine().all().map_err(|e| e.to_string())?.len();

    let engines = {
        let engs = state.engines.lock().unwrap();
        engs.iter()
            .map(|e| EngineInfo {
                name: e.name().to_string(),
                status: e.status(),
            })
            .collect()
    };

    let status = daemon_status().await;
    let (daemon_running, version, realtime) = match status {
        Some(s) => (
            true,
            s.version.clone(),
            Some(RealtimeInfo {
                enabled: s.realtime.enabled,
                backend: s.realtime.backend,
                events_seen: s.realtime.events_seen,
                threats_blocked: s.realtime.threats_blocked,
            }),
        ),
        None => (false, env!("CARGO_PKG_VERSION").to_string(), None),
    };

    Ok(Dashboard {
        daemon_running,
        version,
        scans,
        files,
        threats,
        whitelist_count,
        quarantine_count,
        engines,
        realtime,
    })
}

#[tauri::command]
pub async fn run_scan(
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<ScanReport, String> {
    let target = PathBuf::from(&path);
    if !target.exists() {
        return Err(format!("path does not exist: {path}"));
    }
    let db = state.db.clone();
    let engines = state.engines.lock().unwrap().clone();

    let report = tokio::task::spawn_blocking(move || {
        let cfg = Config::load();
        let wl = Whitelist::load();
        let scanner = Scanner::new_shared(cfg, wl, engines, aegis_core::EventBus::new());
        let (stats, verdicts) = scanner.scan(&target);

        // persist
        let repo = db.scans();
        if let Ok(scan_id) = repo.insert_scan(
            now_epoch(),
            now_epoch(),
            &target.to_string_lossy(),
            stats.scanned as i64,
            stats.threats as i64,
            "ui",
        ) {
            for v in verdicts.iter().filter(|v| v.is_threat()) {
                for d in &v.detections {
                    let _ = repo.insert_threat(
                        scan_id,
                        now_epoch(),
                        &v.path.to_string_lossy(),
                        &v.sha256,
                        &d.threat,
                        &d.engine,
                        d.severity as i64,
                        "detected",
                    );
                }
            }
        }
        let results = verdicts
            .iter()
            .filter(|v| v.is_threat())
            .map(threat_row)
            .collect();
        ScanReport {
            target,
            total_files: stats.total_files,
            scanned: stats.scanned,
            threats: stats.threats,
            duration_ms: stats.duration_ms,
            results,
        }
    })
    .await
    .map_err(|e| e.to_string())?;

    Ok(report)
}

#[tauri::command]
pub async fn list_history(
    state: tauri::State<'_, AppState>,
    limit: i64,
) -> Result<Vec<HistoryRow>, String> {
    Ok(state
        .db
        .scans()
        .recent(limit)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|r| HistoryRow {
            finished: r.finished,
            target: r.target,
            files: r.files_scanned,
            threats: r.threats,
            kind: r.kind,
        })
        .collect())
}

#[tauri::command]
pub async fn list_threats(
    state: tauri::State<'_, AppState>,
    limit: i64,
) -> Result<Vec<ThreatRow>, String> {
    Ok(state
        .db
        .scans()
        .recent_threats(limit)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|t| {
            let sev = Severity::from_u8(t.severity as u8);
            ThreatRow {
                severity: t.severity as u8,
                severity_label: sev.label().to_string(),
                path: PathBuf::from(t.path),
                sha256: t.sha256,
                names: t.threat,
                engines: t.engine,
            }
        })
        .collect())
}

#[tauri::command]
pub async fn list_quarantine(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<QuarantineRow>, String> {
    Ok(state
        .db
        .quarantine()
        .all()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|q| QuarantineRow {
            sha256: q.sha256,
            original_path: q.original_path,
            threat: q.threat,
            quarantined_at: q.quarantined_at,
            size: q.size,
        })
        .collect())
}

#[tauri::command]
pub async fn quarantine_action(
    state: tauri::State<'_, AppState>,
    sha256: String,
    action: String,
) -> Result<(), String> {
    let q = Quarantine::open(&state.db).map_err(|e| e.to_string())?;
    match action.as_str() {
        "restore" => q.restore(&sha256).map(|_| ()).map_err(|e| e.to_string()),
        "delete" => q.delete(&sha256).map_err(|e| e.to_string()),
        other => Err(format!("unknown action: {other}")),
    }
}

#[tauri::command]
pub async fn list_whitelist() -> Result<Vec<WhitelistRow>, String> {
    Ok(Whitelist::load()
        .rules
        .into_iter()
        .map(|r| WhitelistRow {
            kind: format!("{:?}", r.kind).to_lowercase(),
            value: r.value,
            label: r.label,
            recursive: r.recursive,
        })
        .collect())
}

#[tauri::command]
pub async fn add_whitelist(path: String, label: String) -> Result<(), String> {
    let mut wl = Whitelist::load();
    wl.add_path(std::path::Path::new(&path), label, true, now_epoch());
    wl.save().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn remove_whitelist(value: String) -> Result<(), String> {
    let mut wl = Whitelist::load();
    wl.remove(&value);
    wl.save().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn rootkit_scan() -> Result<Vec<ThreatRow>, String> {
    let dets = tokio::task::spawn_blocking(rootkit::scan)
        .await
        .map_err(|e| e.to_string())?;
    Ok(detection_rows(dets))
}

#[tauri::command]
pub async fn memory_scan(pid: Option<u32>) -> Result<Vec<ThreatRow>, String> {
    let dets = tokio::task::spawn_blocking(move || match pid {
        Some(p) => memory::scan_pid(p),
        None => memory::scan_all(),
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(detection_rows(dets))
}

#[derive(Serialize)]
pub struct ConnRow {
    pub protocol: String,
    pub local: String,
    pub remote: String,
    pub state: String,
}

#[derive(Serialize)]
pub struct NetworkReport {
    pub findings: Vec<ThreatRow>,
    pub connections: Vec<ConnRow>,
    pub listening: usize,
    pub established: usize,
}

#[tauri::command]
pub async fn network_scan() -> Result<NetworkReport, String> {
    let report = tokio::task::spawn_blocking(|| {
        let blocklist = aegis_network::IpBlocklist::from_file(
            &aegis_core::paths::config_dir().join("ip-blocklist.txt"),
        );
        let conns = aegis_firewall::connections::all();
        let findings = detection_rows(
            conns
                .iter()
                .flat_map(|c| aegis_network::classify(c, &blocklist))
                .collect(),
        );
        let listening = conns.iter().filter(|c| c.is_listening()).count();
        let established = conns.iter().filter(|c| c.is_established()).count();
        let rows = conns
            .iter()
            .filter(|c| c.is_listening() || c.is_established())
            .map(|c| ConnRow {
                protocol: c.protocol.to_string(),
                local: format!("{}:{}", c.local, c.local_port),
                remote: format!("{}:{}", c.remote, c.remote_port),
                state: c.state.to_string(),
            })
            .collect();
        NetworkReport {
            findings,
            connections: rows,
            listening,
            established,
        }
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(report)
}

#[derive(Serialize)]
pub struct PluginRow {
    pub name: String,
    pub status: String,
    pub trusted: bool,
    pub permissions: Vec<String>,
}

#[derive(Serialize)]
pub struct OptimizeFinding {
    pub category: String,
    pub title: String,
    pub detail: String,
    pub impact: u8,
    pub impact_label: String,
    pub reclaimable: u64,
    pub reclaimable_human: String,
    pub action: Option<String>,
    pub needs_root: bool,
}

#[derive(Serialize)]
pub struct OptimizeReport {
    pub findings: Vec<OptimizeFinding>,
    pub total_reclaimable: u64,
    pub total_reclaimable_human: String,
    pub opportunities: usize,
}

#[tauri::command]
pub async fn optimize_scan() -> Result<OptimizeReport, String> {
    let report = tokio::task::spawn_blocking(aegis_optimize::full_scan)
        .await
        .map_err(|e| e.to_string())?;
    let findings = report
        .findings
        .iter()
        .map(|f| OptimizeFinding {
            category: f.category.clone(),
            title: f.title.clone(),
            detail: f.detail.clone(),
            impact: f.impact as u8,
            impact_label: f.impact.label().to_string(),
            reclaimable: f.reclaimable,
            reclaimable_human: aegis_optimize::human_bytes(f.reclaimable),
            action: f.action.clone(),
            needs_root: f.needs_root,
        })
        .collect();
    let total = report.total_reclaimable();
    Ok(OptimizeReport {
        findings,
        total_reclaimable: total,
        total_reclaimable_human: aegis_optimize::human_bytes(total),
        opportunities: report.actionable().count(),
    })
}

#[tauri::command]
pub async fn plugins_list() -> Result<Vec<PluginRow>, String> {
    let dir = aegis_core::paths::config_dir().join("plugins");
    let trust = aegis_plugin::TrustStore::load(
        &aegis_core::paths::config_dir().join("trusted-keys.txt"),
    );
    Ok(aegis_plugin::discover(&dir, &trust)
        .into_iter()
        .map(|p| PluginRow {
            name: p
                .manifest
                .as_ref()
                .map(|m| m.name.clone())
                .unwrap_or_else(|| "?".into()),
            status: format!("{:?}", p.status),
            trusted: p.is_enabled(),
            permissions: p.permissions().iter().map(|x| format!("{x:?}")).collect(),
        })
        .collect())
}
