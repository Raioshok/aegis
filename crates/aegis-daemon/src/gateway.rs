//! Aegis Telemetry & Training Gateway Server
//!
//! Exposes an HTTP API on port 9090 (listening on 0.0.0.0 and VMnet1) allowing isolated
//! guest virtual machines (Windows 11 and Ubuntu detonation labs) to transmit live
//! execution telemetry, countermeasure validation signals, and missed sample feedback.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryReport {
    pub guest_os: String,
    pub test_id: String,
    pub sample_name: String,
    pub sample_sha256: String,
    pub detected: bool,
    pub detections: Vec<String>,
    pub countermeasures_triggered: Vec<String>,
    pub missed_evasion_indicators: Vec<String>,
    #[serde(default = "current_timestamp")]
    pub timestamp: i64,
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrainingStats {
    pub total_reports: u64,
    pub detected_count: u64,
    pub missed_count: u64,
    pub detection_rate_pct: f64,
    pub recent_threats: Vec<String>,
    pub auto_trained_hashes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingFeedback {
    pub sample_name: String,
    pub sample_sha256: String,
    pub extracted_strings: Vec<String>,
    pub candidate_yara_rule: Option<String>,
}

#[derive(Clone)]
pub struct GatewayState {
    pub stats: Arc<RwLock<TrainingStats>>,
    pub log_path: PathBuf,
    /// Shared secret (`AEGIS_GATEWAY_TOKEN`) guests must send as `X-Aegis-Token`
    /// to write; unset means every write is refused, since writes feed the hash list.
    pub token: Option<String>,
    /// (engine name, status) of the detection engines this host loads, computed once at start.
    pub engines: Arc<Vec<(String, String)>>,
}

impl GatewayState {
    pub fn new() -> Self {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        let log_dir = home.join(".config").join("aegis").join("training-telemetry");
        let _ = std::fs::create_dir_all(&log_dir);
        let log_path = log_dir.join("reports.jsonl");

        Self {
            stats: Arc::new(RwLock::new(TrainingStats::default())),
            log_path,
            token: std::env::var("AEGIS_GATEWAY_TOKEN").ok().filter(|t| !t.is_empty()),
            engines: Arc::new(
                aegis_engine::default_engines(&aegis_core::Config::load(), &aegis_core::paths::user_rules_dir())
                    .iter()
                    .map(|e| (e.name().to_string(), e.status()))
                    .collect(),
            ),
        }
    }

    pub async fn record_report(&self, report: TelemetryReport) {
        let mut stats = self.stats.write().await;
        stats.total_reports += 1;
        if report.detected {
            stats.detected_count += 1;
            for d in &report.detections {
                if !stats.recent_threats.contains(d) {
                    if stats.recent_threats.len() >= 10 {
                        stats.recent_threats.remove(0);
                    }
                    stats.recent_threats.push(d.clone());
                }
            }
        } else {
            stats.missed_count += 1;
            // Auto-train: if missed, add hash to auto-trained feed
            stats.auto_trained_hashes += 1;
            self.auto_ingest_hash(&report.sample_sha256);
        }

        if stats.total_reports > 0 {
            stats.detection_rate_pct =
                (stats.detected_count as f64 / stats.total_reports as f64) * 100.0;
        }

        // Append report to JSONL log
        if let Ok(line) = serde_json::to_string(&report) {
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_path)
            {
                let _ = writeln!(f, "{line}");
            }
        }
    }

    fn auto_ingest_hash(&self, sha256: &str) {
        let clean = sha256.trim().to_lowercase();
        if clean.len() == 64 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
            let home = std::env::var("USERPROFILE")
                .or_else(|_| std::env::var("HOME"))
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."));
            let hash_file = home.join(".config").join("aegis").join("threat-intel").join("hashes.txt");
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&hash_file) {
                let _ = writeln!(f, "{clean}");
            }
        }
    }
}

pub struct GatewayServer {
    pub port: u16,
    pub state: GatewayState,
}

impl GatewayServer {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            state: GatewayState::new(),
        }
    }

    /// Run the HTTP telemetry and training listener.
    pub async fn run(&self) -> std::io::Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = TcpListener::bind(addr).await?;
        tracing::info!("Aegis Telemetry & Training Gateway listening on {addr}");
        if self.state.token.is_none() {
            tracing::warn!("AEGIS_GATEWAY_TOKEN is not set; report and feedback uploads will be refused");
        }

        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        let _ = handle_connection(stream, peer, state).await;
                    });
                }
                Err(e) => {
                    tracing::warn!("Gateway accept error: {e}");
                }
            }
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn handle_connection(
    mut stream: TcpStream,
    _peer: SocketAddr,
    state: GatewayState,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 65536];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let mut lines = request.lines();
    let first_line = lines.next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    // Split headers and body
    let body = if let Some(pos) = request.find("\r\n\r\n") {
        request[pos + 4..].trim()
    } else {
        ""
    };

    let token_ok = state.token.as_deref().is_some_and(|want| {
        lines
            .clone()
            .take_while(|l| !l.is_empty())
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("x-aegis-token")))
            .is_some_and(|(_, got)| constant_time_eq(got.trim().as_bytes(), want.as_bytes()))
    });

    let (status, resp_body) = match (method, path) {
        ("POST", _) if !token_ok => ("403 Forbidden", r#"{"error":"missing or bad X-Aegis-Token"}"#.into()),
        ("POST", "/api/v1/telemetry/report") => {
            if let Ok(report) = serde_json::from_str::<TelemetryReport>(body) {
                state.record_report(report).await;
                (
                    "200 OK",
                    serde_json::json!({
                        "status": "recorded",
                        "training_status": "synced"
                    })
                    .to_string(),
                )
            } else {
                ("400 Bad Request", r#"{"error":"invalid report json"}"#.into())
            }
        }
        ("GET", "/api/v1/telemetry/stats") => {
            let stats = state.stats.read().await.clone();
            ("200 OK", serde_json::to_string(&stats).unwrap_or("{}".into()))
        }
        ("GET", "/train.py") | ("GET", "/api/v1/train.py") => {
            let candidate_paths = [
                std::path::PathBuf::from(r"scripts\training\aegis-guest-train.py"),
                std::path::PathBuf::from(r"..\scripts\training\aegis-guest-train.py"),
                std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join(r"scripts\training\aegis-guest-train.py"))).unwrap_or_default(),
                std::path::PathBuf::from(r"C:\Users\raio\Downloads\Telegram Desktop\Projects\aegis\scripts\training\aegis-guest-train.py"),
            ];
            let content = candidate_paths.iter().find(|p| p.exists())
                .and_then(|p| std::fs::read_to_string(p).ok())
                .unwrap_or_else(|| "print('Aegis Gateway Live')".to_string());
            ("200 OK", content)
        }
        ("GET", "/train.sh") => {
            let host_header = lines.find(|l| l.to_ascii_lowercase().starts_with("host:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("172.31.0.1:9090");
            let content = format!("#!/usr/bin/env bash\ncurl -sSL http://{host_header}/train.py | python3\n");
            ("200 OK", content)
        }
        ("GET", "/api/v1/signatures") => (
            "200 OK",
            serde_json::json!({
                "engine": "Aegis",
                "version": env!("CARGO_PKG_VERSION"),
                "engines": state.engines.iter().map(|(n, s)| serde_json::json!({"name": n, "status": s})).collect::<Vec<_>>(),
                "status": "ready"
            })
            .to_string(),
        ),
        ("POST", "/api/v1/train/feedback") => {
            if let Ok(feedback) = serde_json::from_str::<TrainingFeedback>(body) {
                state.auto_ingest_hash(&feedback.sample_sha256);
                (
                    "200 OK",
                    serde_json::json!({
                        "status": "feedback_ingested",
                        "sample": feedback.sample_name,
                        "auto_trained": true
                    })
                    .to_string(),
                )
            } else {
                ("400 Bad Request", r#"{"error":"invalid feedback json"}"#.into())
            }
        }
        _ => ("404 Not Found", r#"{"error":"not found"}"#.into()),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Connection: close\r\n\r\n\
         {resp_body}",
        resp_body.len()
    );

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}
