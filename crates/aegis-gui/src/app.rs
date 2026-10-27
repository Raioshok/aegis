use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use aegis_core::{Config, Detection};
use aegis_storage::{Database, QuarantineRecord};
use eframe::egui::{self, Align, Layout, RichText};
use sha2::Digest;

use crate::theme::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Scan,
    Quarantine,
    Behavior,
    Network,
    Settings,
}

pub enum BackgroundMsg {
    ScanFileDone { path: String, detection: Option<Detection> },
    ScanProgress { scanned: usize, total: usize, current_path: String },
    ScanFinished { scanned: usize, threats: usize, duration_ms: u64 },
    MemoryAuditResult { alerts: Vec<String> },
    #[allow(dead_code)]
    ActionStatus(String),
}

pub struct AegisApp {
    pub current_tab: Tab,
    pub config: Config,
    pub db: Option<Database>,
    pub rx: Receiver<BackgroundMsg>,
    pub tx: Sender<BackgroundMsg>,
    
    // Scan State
    pub is_scanning: bool,
    pub scan_target_path: String,
    pub scan_scanned: usize,
    pub scan_total: usize,
    pub scan_current_file: String,
    pub scan_findings: Vec<(String, Detection)>,
    pub scan_summary: Option<String>,

    // Quarantine State
    pub quarantine_records: Vec<QuarantineRecord>,
    pub status_message: Option<(String, std::time::Instant)>,

    // Behavior & DAG State
    pub is_auditing_memory: bool,
    pub memory_alerts: Vec<String>,

    /// (name, status) of the engines a scan loads, read once at startup.
    pub engine_status: Vec<(String, String)>,
}

impl AegisApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = channel();
        let config = Config::load();
        let engine_status = aegis_engine::default_engines(&config, &aegis_core::paths::user_rules_dir())
            .iter()
            .map(|e| (e.name().to_string(), e.status()))
            .collect();
        let db = Database::open(&aegis_core::paths::database_file()).ok();

        let mut app = Self {
            current_tab: Tab::Dashboard,
            config,
            db,
            rx,
            tx,
            is_scanning: false,
            scan_target_path: String::new(),
            scan_scanned: 0,
            scan_total: 0,
            scan_current_file: String::new(),
            scan_findings: Vec::new(),
            scan_summary: None,
            quarantine_records: Vec::new(),
            status_message: None,
            is_auditing_memory: false,
            memory_alerts: Vec::new(),
            engine_status,
        };
        app.refresh_quarantine();
        app
    }

    pub fn refresh_quarantine(&mut self) {
        if let Some(ref db) = self.db {
            if let Ok(records) = db.quarantine().all() {
                self.quarantine_records = records;
            }
        }
    }

    pub fn set_status(&mut self, msg: &str) {
        self.status_message = Some((msg.to_string(), std::time::Instant::now()));
    }

    pub fn start_scan(&mut self, path: PathBuf) {
        if self.is_scanning {
            return;
        }
        self.is_scanning = true;
        self.scan_scanned = 0;
        self.scan_total = 0;
        self.scan_findings.clear();
        self.scan_summary = None;
        self.scan_target_path = path.to_string_lossy().to_string();

        let tx = self.tx.clone();
        let config = self.config.clone();

        thread::spawn(move || {
            let start = std::time::Instant::now();
            let mut files = Vec::new();
            if path.is_file() {
                files.push(path);
            } else if path.is_dir() {
                for entry in walkdir::WalkDir::new(&path).into_iter().filter_map(|e| e.ok()) {
                    if entry.file_type().is_file() {
                        files.push(entry.into_path());
                    }
                }
            }

            let total = files.len();
            let _ = tx.send(BackgroundMsg::ScanProgress {
                scanned: 0,
                total,
                current_path: "Initializing multi-engine detection suite...".into(),
            });

            let engines = aegis_engine::default_engines(&config, &aegis_core::paths::user_rules_dir());

            let mut threats = 0;
            for (idx, file) in files.iter().enumerate() {
                let file_str = file.to_string_lossy().to_string();
                if idx % 10 == 0 || idx == total - 1 {
                    let _ = tx.send(BackgroundMsg::ScanProgress {
                        scanned: idx + 1,
                        total,
                        current_path: file_str.clone(),
                    });
                }

                if let Ok(data) = std::fs::read(file) {
                    let sha = sha2::Sha256::digest(&data);
                    let sha_hex = hex::encode(sha);
                    let ctx = aegis_engine::FileContext {
                        path: file,
                        data: &data,
                        size: data.len() as u64,
                        sha256: &sha_hex,
                    };
                    let mut detections = Vec::new();
                    for eng in &engines {
                        detections.extend(eng.scan(&ctx));
                    }
                    if let Some(det) = detections.into_iter().max_by_key(|d| d.severity) {
                        threats += 1;
                        let _ = tx.send(BackgroundMsg::ScanFileDone {
                            path: file_str,
                            detection: Some(det),
                        });
                    }
                }
            }

            let duration_ms = start.elapsed().as_millis() as u64;
            let _ = tx.send(BackgroundMsg::ScanFinished {
                scanned: total,
                threats,
                duration_ms,
            });
        });
    }

    pub fn start_memory_audit(&mut self) {
        if self.is_auditing_memory {
            return;
        }
        self.is_auditing_memory = true;
        self.memory_alerts.clear();
        let tx = self.tx.clone();

        thread::spawn(move || {
            let detections = aegis_behavior::memory::scan_all();
            let mut alerts: Vec<String> = detections
                .iter()
                .map(|d| format!("[{}] {} — {}", d.severity.label(), d.threat, d.detail))
                .collect();
            if alerts.is_empty() {
                alerts.push("Memory scan finished: no injected or unbacked code found.".into());
            }

            let _ = tx.send(BackgroundMsg::MemoryAuditResult { alerts });
        });
    }

    pub fn quarantine_file(&mut self, path_str: &str, detection: &Detection) {
        let path = Path::new(path_str);
        if !path.exists() {
            self.set_status("File no longer exists on disk");
            return;
        }

        if let Some(ref db) = self.db {
            match aegis_quarantine::Quarantine::open(db) {
                Ok(q) => {
                    match q.quarantine(
                        path,
                        &detection.threat,
                        &detection.engine,
                        detection.severity as i64,
                    ) {
                        Ok(rec) => {
                            self.set_status(&format!("Quarantined: {} ({})", path.file_name().unwrap_or_default().to_string_lossy(), rec.threat));
                            self.refresh_quarantine();
                        }
                        Err(e) => {
                            self.set_status(&format!("Quarantine failed: {}", e));
                        }
                    }
                }
                Err(e) => {
                    self.set_status(&format!("Could not open vault: {}", e));
                }
            }
        }
    }
}

impl eframe::App for AegisApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll background worker messages
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                BackgroundMsg::ScanProgress { scanned, total, current_path } => {
                    self.scan_scanned = scanned;
                    self.scan_total = total;
                    self.scan_current_file = current_path;
                }
                BackgroundMsg::ScanFileDone { path, detection } => {
                    if let Some(det) = detection {
                        self.scan_findings.push((path, det));
                    }
                }
                BackgroundMsg::ScanFinished { scanned, threats, duration_ms } => {
                    self.is_scanning = false;
                    self.scan_summary = Some(format!(
                        "Completed in {:.2}s · Scanned {} files · {} threat(s) convicted",
                        duration_ms as f64 / 1000.0,
                        scanned,
                        threats
                    ));
                    self.set_status("Scan completed.");
                }
                BackgroundMsg::MemoryAuditResult { alerts } => {
                    self.is_auditing_memory = false;
                    self.memory_alerts = alerts;
                    self.set_status("Memory & Evasion audit complete.");
                }
                BackgroundMsg::ActionStatus(s) => {
                    self.set_status(&s);
                }
            }
        }

        // Top Header
        egui::TopBottomPanel::top("top_panel")
            .frame(egui::Frame::none().fill(SIDEBAR_COLOR).stroke(egui::Stroke::new(1.0_f32, BORDER_COLOR)))
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.add_space(16.0);
                    ui.label(RichText::new("AEGIS").size(18.0).strong().color(ACCENT_ORANGE));
                    ui.label(RichText::new("TOTAL SECURITY").size(14.0).color(TEXT_SECONDARY));
                    ui.add_space(8.0);
                    ui.label(RichText::new("v0.1.0 (Pure-Rust)").size(11.0).monospace().color(TEXT_MUTED));

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.add_space(16.0);
                        if let Some((ref msg, instant)) = self.status_message {
                            if instant.elapsed().as_secs() < 5 {
                                ui.label(RichText::new(msg).size(12.0).color(STATUS_GREEN));
                            }
                        }
                    });
                });
                ui.add_space(8.0);
            });

        // Left Navigation Rail
        egui::SidePanel::left("nav_rail")
            .exact_width(220.0)
            .frame(egui::Frame::none().fill(SIDEBAR_COLOR).stroke(egui::Stroke::new(1.0_f32, BORDER_COLOR)))
            .show(ctx, |ui| {
                ui.add_space(16.0);

                let nav_item = |ui: &mut egui::Ui, current: Tab, target: Tab, label: &str, icon: &str| -> bool {
                    let is_active = current == target;
                    let bg = if is_active { CARD_BG } else { egui::Color32::TRANSPARENT };
                    let text_color = if is_active { ACCENT_ORANGE } else { TEXT_SECONDARY };

                    let frame = egui::Frame::none()
                        .fill(bg)
                        .stroke(if is_active { egui::Stroke::new(1.0_f32, BORDER_COLOR) } else { egui::Stroke::NONE })
                        .rounding(egui::Rounding::same(6.0))
                        .inner_margin(egui::Margin::symmetric(14.0, 10.0));

                    let resp = frame.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(icon).size(14.0).color(text_color));
                            ui.add_space(8.0);
                            ui.label(RichText::new(label).size(13.0).strong().color(text_color));
                        });
                    });
                    resp.response.interact(egui::Sense::click()).clicked()
                };

                ui.vertical(|ui| {
                    ui.add_space(4.0);
                    if nav_item(ui, self.current_tab, Tab::Dashboard, "Dashboard", "🛡") {
                        self.current_tab = Tab::Dashboard;
                    }
                    ui.add_space(6.0);
                    if nav_item(ui, self.current_tab, Tab::Scan, "Malware Scan", "🔍") {
                        self.current_tab = Tab::Scan;
                    }
                    ui.add_space(6.0);
                    if nav_item(ui, self.current_tab, Tab::Quarantine, "Quarantine Vault", "☣") {
                        self.current_tab = Tab::Quarantine;
                        self.refresh_quarantine();
                    }
                    ui.add_space(6.0);
                    if nav_item(ui, self.current_tab, Tab::Behavior, "Behavior & Memory", "🧠") {
                        self.current_tab = Tab::Behavior;
                    }
                    ui.add_space(6.0);
                    if nav_item(ui, self.current_tab, Tab::Network, "Network & Telemetry", "🌐") {
                        self.current_tab = Tab::Network;
                    }
                    ui.add_space(6.0);
                    if nav_item(ui, self.current_tab, Tab::Settings, "Settings & Shields", "⚙") {
                        self.current_tab = Tab::Settings;
                    }
                });

                ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
                    ui.add_space(16.0);
                    ui.label(RichText::new("100% Pure-Rust · No Electron").size(10.0).monospace().color(TEXT_MUTED));
                    ui.label(RichText::new("Aegis Native EDR Engine").size(11.0).strong().color(TEXT_SECONDARY));
                });
            });

        // Main Content Area
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(BG_COLOR))
            .show(ctx, |ui| {
                ui.add_space(20.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add_space(4.0);
                    match self.current_tab {
                        Tab::Dashboard => self.view_dashboard(ui),
                        Tab::Scan => self.view_scan(ui),
                        Tab::Quarantine => self.view_quarantine(ui),
                        Tab::Behavior => self.view_behavior(ui),
                        Tab::Network => self.view_network(ui),
                        Tab::Settings => self.view_settings(ui),
                    }
                    ui.add_space(20.0);
                });
            });

        // Continuous redraw during active scans
        if self.is_scanning || self.is_auditing_memory {
            ctx.request_repaint();
        }
    }
}
