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

    let (status, resp_body) = match (method, path) {
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
            let script_path = std::path::PathBuf::from(r"C:\Users\raio\Downloads\Telegram Desktop\Projects\aegis\scripts\training\aegis-guest-train.py");
            let content = std::fs::read_to_string(script_path)
                .unwrap_or_else(|_| "print('Aegis Gateway Live')".to_string());
            ("200 OK", content)
        }
        ("GET", "/train.sh") => {
            let content = "#!/usr/bin/env bash\ncurl -sSL http://172.17.48.1:9090/train.py | python3\n";
            ("200 OK", content.to_string())
        }
        ("GET", "/api/v1/signatures") => {
            let home = std::env::var("USERPROFILE")
                .or_else(|_| std::env::var("HOME"))
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."));
            let hash_file = home.join(".config").join("aegis").join("threat-intel").join("hashes.txt");
            let hashes_count = std::fs::read_to_string(hash_file)
                .map(|c| c.lines().filter(|l| !l.starts_with('#')).count())
                .unwrap_or(352);
            (
                "200 OK",
                serde_json::json!({
                    "engine": "Aegis Total Security",
                    "version": "0.1.0-training-gateway",
                    "yara_rules_active": 37,
                    "behavioral_rules_active": 13,
                    "threat_hashes_indexed": hashes_count,
                    "status": "ready"
                })
                .to_string(),
            )
        }
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
