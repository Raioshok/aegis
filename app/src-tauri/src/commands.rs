//! Tauri commands — the bridge between the React UI and the Aegis engine.
//!
//! Scans, history, quarantine, whitelist and behavioural checks run in-process
//! (so the UI is fully functional without the daemon); live daemon status and
//! real-time counters are fetched from the running daemon over `aegis-ipc`.

use aegis_behavior::{memory, rootkit, LineageAlert, ProcessDagSnapshot, ProcessTreeDag};
use aegis_core::{now_epoch, paths, Config, Detection, FileVerdict, Severity, Whitelist};
use aegis_engine::{shared_engines, Engine, Scanner};
use aegis_ipc::protocol::Request;
use aegis_ipc::{Client, Response};
use aegis_quarantine::Quarantine;
use aegis_storage::Database;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub is_active: bool,
    pub current_file: String,
    pub scanned: u64,
    pub total: u64,
    pub threats: u64,
    pub rate: u64,
    pub elapsed_secs: u64,
    pub percent: f32,
}

impl Default for ScanProgress {
    fn default() -> Self {
        Self {
            is_active: false,
            current_file: String::new(),
            scanned: 0,
            total: 0,
            threats: 0,
            rate: 0,
            elapsed_secs: 0,
            percent: 0.0,
        }
    }
}

/// Shared application state held by Tauri.
pub struct AppState {
    pub db: Arc<Database>,
    pub engines: Mutex<Arc<Vec<Box<dyn Engine>>>>,
    pub scan_progress: Arc<Mutex<ScanProgress>>,
    pub process_dag: Arc<ProcessTreeDag>,
    /// image path -> trusted-binary verdict (signature checks are slow).
    pub signed_cache: Arc<Mutex<HashMap<PathBuf, bool>>>,
}

fn is_signed_cached(cache: &Mutex<HashMap<PathBuf, bool>>, exe: &std::path::Path) -> bool {
    if let Some(v) = cache.lock().unwrap().get(exe) {
        return *v;
    }
    let v = aegis_platform::is_trusted_binary(exe);
    cache.lock().unwrap().insert(exe.to_path_buf(), v);
    v
}

impl AppState {
    pub fn new() -> Result<Self, String> {
        paths::ensure_dirs().map_err(|e| e.to_string())?;
        let db = Arc::new(Database::open(&paths::database_file()).map_err(|e| e.to_string())?);
        let cfg = Config::load();
        let engines = shared_engines(&cfg, &paths::user_rules_dir());
        let process_dag = Arc::new(ProcessTreeDag::new());
        let signed_cache: Arc<Mutex<HashMap<PathBuf, bool>>> = Default::default();
        // Feed the lineage graph continuously, not only when the Processes page is open.
        {
            let (dag, cache) = (process_dag.clone(), signed_cache.clone());
            let events = aegis_platform::start_process_poller(std::time::Duration::from_millis(750));
            std::thread::spawn(move || {
                for ev in events {
                    let signed = is_signed_cached(&cache, &ev.exe);
                    dag.add_process(&ev, signed, None);
                }
            });
        }
        Ok(Self {
            db,
            engines: Mutex::new(engines),
            scan_progress: Arc::new(Mutex::new(ScanProgress::default())),
            process_dag,
            signed_cache,
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
    /// Unix time of the last threat-feed download (None = never synced).
    pub last_feed_sync: Option<i64>,
    /// Known vulnerable-driver hashes (0 where kernel drivers do not apply).
    pub vulnerable_driver_signatures: usize,
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
        last_feed_sync: last_feed_sync(),
        #[cfg(windows)]
        vulnerable_driver_signatures: aegis_platform::windows::vulnerable_driver_count(),
        #[cfg(not(windows))]
        vulnerable_driver_signatures: 0,
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
    let progress = state.scan_progress.clone();

    let report = tokio::task::spawn_blocking(move || {
        let cfg = Config::load();
        let wl = Whitelist::load();

        let bus = aegis_core::EventBus::new();
        let p_for_bus = progress.clone();
        let start_time = std::time::Instant::now();

        if let Ok(mut p) = progress.lock() {
            p.is_active = true;
            p.current_file = "Enumerating target files...".into();
            p.scanned = 0;
            p.total = 0;
            p.threats = 0;
            p.rate = 0;
            p.elapsed_secs = 0;
            p.percent = 0.0;
        }

        bus.subscribe(Arc::new(move |ev| {
            match ev {
                aegis_core::Event::FileScanned { path, index, total } => {
                    if *index % 16 == 0 || *index == *total {
                        if let Ok(mut p) = p_for_bus.lock() {
                            p.is_active = true;
                            p.current_file = path.to_string_lossy().into_owned();
                            p.scanned = *index;
                            p.total = *total;
                            p.percent = if *total > 0 { (*index as f32 / *total as f32) * 100.0 } else { 0.0 };
                            let elapsed = start_time.elapsed().as_secs();
                            p.elapsed_secs = elapsed;
                            p.rate = if elapsed > 0 { *index / elapsed } else { *index };
                        }
                    }
                }
                aegis_core::Event::ScanStarted { total, .. } => {
                    if let Ok(mut p) = p_for_bus.lock() {
                        p.is_active = true;
                        p.total = *total;
                        p.scanned = 0;
                        p.threats = 0;
                        p.current_file = "Starting parallel inspection...".into();
                    }
                }
                aegis_core::Event::ThreatFound(_) => {
                    if let Ok(mut p) = p_for_bus.lock() {
                        p.threats += 1;
                    }
                }
                aegis_core::Event::ScanFinished(_) => {
                    if let Ok(mut p) = p_for_bus.lock() {
                        p.is_active = false;
                    }
                }
                _ => {}
            }
        }));

        let scanner = Scanner::new_shared(cfg, wl, engines, bus);
        let (stats, verdicts) = scanner.scan(&target);

        if let Ok(mut p) = progress.lock() {
            p.is_active = false;
        }

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
pub fn get_scan_progress(state: tauri::State<'_, AppState>) -> ScanProgress {
    state.scan_progress.lock().unwrap().clone()
}

#[tauri::command]
pub fn get_smart_scan_target() -> String {
    if let Some(user_dir) = dirs::download_dir() {
        return user_dir.to_string_lossy().into_owned();
    }
    if let Some(home) = dirs::home_dir() {
        return home.to_string_lossy().into_owned();
    }
    if cfg!(windows) { "C:\\Users".into() } else { "/tmp".into() }
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
pub async fn quarantine_file(
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<String, String> {
    let path_clone = path.clone();
    let db = std::sync::Arc::clone(&state.db);
    tokio::task::spawn_blocking(move || {
        let p = std::path::Path::new(&path_clone);
        let q = Quarantine::open(&db).map_err(|e| e.to_string())?;
        let rec = q.quarantine(p, "Manual.Quarantine", "UserAction", 3)
            .map_err(|e| e.to_string())?;
        Ok(rec.sha256)
    })
    .await
    .map_err(|e| e.to_string())?
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
        let blocklist = aegis_network::IpBlocklist::load_default();
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

// --- Windows Autostart Commands --------------------------------------

#[tauri::command]
pub fn is_autostart_active() -> bool {
    aegis_platform::default_autostart().is_enabled()
}

#[tauri::command]
pub fn toggle_autostart(enable: bool) -> Result<bool, String> {
    let exe_path = std::env::current_exe().map_err(|e| e.to_string())?;
    let mgr = aegis_platform::default_autostart();
    mgr.set_enabled(enable, &exe_path).map_err(|e| e.to_string())?;
    Ok(mgr.is_enabled())
}

// --- Modular Shields & Kaspersky-Style Game Mode Commands -------------

#[derive(Serialize, Deserialize, Clone)]
pub struct ProtectionConfigDto {
    /// Real-time file protection in aegisd (takes effect when aegisd restarts).
    pub realtime_enabled: bool,
    pub auto_quarantine: bool,
    /// Linux fanotify only: deny launching detected programs.
    pub block_exec: bool,
    pub ransomware_guard: bool,
    pub ransomware_auto_kill: bool,
    pub auto_update_feeds: bool,
    pub ml_engine: bool,
    pub game_mode_enabled: bool,
    pub game_mode_auto_detect: bool,
    pub entropy_threshold: f64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GameModeStatusDto {
    pub is_gaming_active: bool,
    pub game_mode_enabled: bool,
    pub auto_detect: bool,
    pub priority_lowered: bool,
    pub background_scans_paused: bool,
}

#[tauri::command]
pub fn get_protection_config() -> ProtectionConfigDto {
    let cfg = aegis_core::Config::load();
    ProtectionConfigDto {
        realtime_enabled: cfg.realtime.enabled,
        auto_quarantine: cfg.realtime.auto_quarantine,
        block_exec: cfg.realtime.block_exec,
        ransomware_guard: cfg.ransomware.enabled,
        ransomware_auto_kill: cfg.ransomware.auto_kill,
        auto_update_feeds: cfg.auto_update_feeds,
        ml_engine: cfg.engines.ml,
        game_mode_enabled: cfg.game_mode.enabled,
        game_mode_auto_detect: cfg.game_mode.auto_detect,
        entropy_threshold: cfg.entropy_threshold,
    }
}

#[tauri::command]
pub fn set_protection_config(dto: ProtectionConfigDto) -> Result<(), String> {
    let mut cfg = aegis_core::Config::load();
    cfg.realtime.enabled = dto.realtime_enabled;
    cfg.realtime.auto_quarantine = dto.auto_quarantine;
    cfg.realtime.block_exec = dto.block_exec;
    cfg.ransomware.enabled = dto.ransomware_guard;
    cfg.ransomware.auto_kill = dto.ransomware_auto_kill;
    cfg.auto_update_feeds = dto.auto_update_feeds;
    cfg.game_mode.enabled = dto.game_mode_enabled;
    cfg.game_mode.auto_detect = dto.game_mode_auto_detect;
    cfg.entropy_threshold = dto.entropy_threshold;
    cfg.engines.ml = dto.ml_engine;
    cfg.save().map_err(|e| e.to_string())?;

    let is_gaming = aegis_platform::is_gaming_active();
    if dto.game_mode_enabled && is_gaming {
        aegis_platform::set_process_resource_mode(true);
    } else {
        aegis_platform::set_process_resource_mode(false);
    }

    Ok(())
}

#[tauri::command]
pub fn get_game_mode_status() -> GameModeStatusDto {
    let cfg = aegis_core::Config::load();
    let is_gaming = aegis_platform::is_gaming_active();
    let throttled = cfg.game_mode.enabled && (is_gaming || !cfg.game_mode.auto_detect);
    if throttled {
        aegis_platform::set_process_resource_mode(true);
    } else {
        aegis_platform::set_process_resource_mode(false);
    }
    GameModeStatusDto {
        is_gaming_active: is_gaming,
        game_mode_enabled: cfg.game_mode.enabled,
        auto_detect: cfg.game_mode.auto_detect,
        priority_lowered: throttled,
        background_scans_paused: throttled && cfg.game_mode.pause_background_scans,
    }
}

#[tauri::command]
pub fn toggle_game_mode(enabled: bool) -> Result<GameModeStatusDto, String> {
    let mut cfg = aegis_core::Config::load();
    cfg.game_mode.enabled = enabled;
    cfg.save().map_err(|e| e.to_string())?;
    Ok(get_game_mode_status())
}

// --- Extended Enterprise Features -------------------------------------

#[derive(Serialize)]
pub struct ProcessItem {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub is_signed: bool,
    pub is_suspicious: bool,
    pub risk_score: u8,
    pub is_agent_context: bool,
    pub agent_label: Option<String>,
    pub mitre_techniques: Vec<String>,
    pub risk_factors: Vec<String>,
}

#[tauri::command]
pub async fn list_processes(state: tauri::State<'_, AppState>) -> Result<Vec<ProcessItem>, String> {
    let dag = state.process_dag.clone();
    let cache = state.signed_cache.clone();
    tokio::task::spawn_blocking(move || {
        let ctrl = aegis_platform::default_process_control();
        let procs = ctrl.enumerate_processes_snapshot().map_err(|e| e.to_string())?;

        let mut items = Vec::new();
        let now = aegis_core::now_epoch() * 1000;

        for (pid, ppid, raw_name) in procs {
            let path_opt = ctrl.image_path(pid);
            let path_str = path_opt
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| format!("[PID {pid}]"));

            let name = if !raw_name.is_empty() {
                raw_name
            } else {
                path_opt
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| format!("Process {pid}"))
            };

            let is_signed = path_opt.as_deref().is_some_and(|p| is_signed_cached(&cache, p));

            // The background poller normally added this process already; cover the gap at startup.
            if dag.get_process(pid).is_none() {
                let pevent = aegis_core::ProcessEvent {
                    pid,
                    ppid,
                    exe: path_opt.clone().unwrap_or_else(|| PathBuf::from(&name)),
                    cmdline: ctrl.command_line(pid).unwrap_or_else(|| vec![name.clone()]),
                    kind: aegis_core::ProcessEventKind::Exec,
                    timestamp_ms: now as u64,
                };
                dag.add_process(&pevent, is_signed, None);
            }

            let node_opt = dag.get_process(pid);
            let (risk_score, is_agent_context, agent_label, mitre_techniques, risk_factors) = if let Some(n) = node_opt {
                (n.risk_score, n.is_agent_context, n.agent_type.map(|a| a.label().to_string()), n.mitre_techniques, n.risk_factors)
            } else {
                (if is_signed { 5 } else { 35 }, false, None, Vec::new(), Vec::new())
            };

            let is_suspicious = risk_score >= 60;

            items.push(ProcessItem {
                pid,
                ppid,
                name,
                path: path_str,
                is_signed,
                is_suspicious,
                risk_score,
                is_agent_context,
                agent_label,
                mitre_techniques,
                risk_factors,
            });
        }
        items.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
        Ok(items)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn get_process_dag_snapshot(
    state: tauri::State<'_, AppState>,
) -> Result<ProcessDagSnapshot, String> {
    Ok(state.process_dag.snapshot())
}

#[tauri::command]
pub async fn get_process_lineage_alerts(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<LineageAlert>, String> {
    Ok(state.process_dag.get_alerts(100))
}

#[tauri::command]
pub async fn kill_process(pid: u32) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let ctrl = aegis_platform::default_process_control();
        ctrl.kill(pid).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn inspect_process_memory(pid: u32) -> Result<Vec<ThreatRow>, String> {
    tokio::task::spawn_blocking(move || {
        let detections = aegis_behavior::memory::scan_pid(pid);
        Ok(detections
            .into_iter()
            .map(|d| ThreatRow {
                severity: d.severity as u8,
                severity_label: format!("{:?}", d.severity),
                path: format!("PID {pid} Address Space").into(),
                sha256: String::new(),
                names: d.threat,
                engines: "Behavior.Memory".into(),
            })
            .collect())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[derive(Serialize)]
pub struct SecurityAuditReport {
    pub overall_score: u8,
    pub items: Vec<aegis_platform::hardening::HardeningCheck>,
    pub issues_count: usize,
}

/// Read the machine's real hardening settings.
#[tauri::command]
pub async fn security_audit() -> Result<SecurityAuditReport, String> {
    tokio::task::spawn_blocking(|| {
        let items = aegis_platform::hardening::audit();
        let issues_count = items
            .iter()
            .filter(|c| c.state == aegis_platform::hardening::CheckState::Fail)
            .count();
        SecurityAuditReport {
            overall_score: aegis_platform::hardening::score(&items),
            items,
            issues_count,
        }
    })
    .await
    .map_err(|e| e.to_string())
}

/// Apply the fix for one hardening check (needs administrator / root).
#[tauri::command]
pub async fn apply_hardening_fix(id: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || aegis_platform::hardening::apply_fix(&id))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// Hash every registered kernel driver and report known vulnerable ones (BYOVD).
#[tauri::command]
pub async fn driver_audit() -> Result<Vec<ThreatRow>, String> {
    let dets = tokio::task::spawn_blocking(|| aegis_platform::default_platform_security().audit_registered_drivers())
        .await
        .map_err(|e| e.to_string())?;
    Ok(detection_rows(dets))
}

/// Download the live abuse.ch and LOLDrivers feeds, then reload the engines so
/// new hashes apply to the next scan.
#[tauri::command]
pub async fn sync_threat_feeds(
    state: tauri::State<'_, AppState>,
) -> Result<aegis_engine::updater::SyncReport, String> {
    let report = tokio::task::spawn_blocking(|| {
        aegis_engine::FeedManager::new(paths::threat_intel_dir()).sync_online()
    })
    .await
    .map_err(|e| e.to_string())?;
    let cfg = Config::load();
    *state.engines.lock().unwrap() = shared_engines(&cfg, &paths::user_rules_dir());
    Ok(report)
}

/// Unix time of the last successful feed download, if any.
fn last_feed_sync() -> Option<i64> {
    aegis_engine::FeedManager::new(paths::threat_intel_dir())
        .load_manifest()
        .updated_at
        .into_values()
        .max()
}

/// Write decoy files into Documents and Desktop and add those folders to
/// real-time protection so the ransomware guard sees any tampering.
#[tauri::command]
pub async fn deploy_ransomware_honeypot() -> Result<String, String> {
    use aegis_behavior::ransomware::{CANARY_NAMES, CANARY_PAYLOAD};
    tokio::task::spawn_blocking(|| {
        let targets: Vec<PathBuf> = [dirs::document_dir(), dirs::desktop_dir()].into_iter().flatten().collect();
        let mut deployed = 0;
        for dir in &targets {
            for name in CANARY_NAMES {
                // create_new: never overwrite a real user file that happens to share a decoy name.
                let written = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(dir.join(name))
                    .and_then(|mut f| std::io::Write::write_all(&mut f, CANARY_PAYLOAD));
                if written.is_ok() || dir.join(name).exists() {
                    deployed += 1;
                }
            }
        }

        let mut cfg = Config::load();
        let mut added = false;
        for dir in &targets {
            if !cfg.realtime.paths.contains(dir) {
                cfg.realtime.paths.push(dir.clone());
                added = true;
            }
        }
        cfg.ransomware.enabled = true;
        cfg.save().map_err(|e| e.to_string())?;

        let mut msg = format!("{deployed} decoy files in place across {} folders.", targets.len());
        if added {
            msg.push_str(" Restart real-time protection (aegisd) to start watching them.");
        }
        Ok(msg)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn scan_android_package(path: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        aegis_android::scan_android_json(std::path::Path::new(&path))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GatewayStatsDto {
    pub total_reports: u64,
    pub detected_count: u64,
    pub missed_count: u64,
    pub detection_rate_pct: f64,
    pub recent_threats: Vec<String>,
    pub auto_trained_hashes: u64,
}

#[tauri::command]
pub async fn get_gateway_stats() -> Result<GatewayStatsDto, String> {
    tokio::task::spawn_blocking(|| {
        let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        rt.block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut stream = tokio::net::TcpStream::connect("127.0.0.1:9090")
                .await
                .map_err(|e| format!("Gateway offline: {e}"))?;
            let req = "GET /api/v1/telemetry/stats HTTP/1.1\r\nHost: 127.0.0.1:9090\r\nConnection: close\r\n\r\n";
            stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
            let resp = String::from_utf8_lossy(&buf[..n]);
            if let Some(pos) = resp.find("\r\n\r\n") {
                serde_json::from_str::<GatewayStatsDto>(&resp[pos + 4..]).map_err(|e| e.to_string())
            } else {
                Err("Malformed gateway response".into())
            }
        })
    })
    .await
    .map_err(|e| e.to_string())?
}
