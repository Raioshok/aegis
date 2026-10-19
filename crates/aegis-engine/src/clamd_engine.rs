//! Optional ClamAV detection engine using `clamd`'s `zINSTREAM` protocol over Unix socket or TCP.
//!
//! Adds signature coverage by streaming file bytes to a local `clamd` daemon without
//! linking C libclamav.

use crate::engine::{Engine, FileContext};
use aegis_core::{Detection, Severity, ThreatClass};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct ClamdEngine {
    tcp_addr: Option<String>,
    #[cfg(unix)]
    socket_path: Option<std::path::PathBuf>,
    max_stream_len: u64,
}

impl ClamdEngine {
    pub fn new_tcp(addr: impl Into<String>) -> Self {
        Self {
            tcp_addr: Some(addr.into()),
            #[cfg(unix)]
            socket_path: None,
            max_stream_len: 25 * 1024 * 1024, // 25 MiB default clamd StreamMaxLength
        }
    }

    #[cfg(unix)]
    pub fn new_unix(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            tcp_addr: None,
            socket_path: Some(path.into()),
            max_stream_len: 25 * 1024 * 1024,
        }
    }

    pub fn default_local() -> Self {
        #[cfg(unix)]
        {
            for sock in ["/run/clamav/clamd.ctl", "/var/run/clamav/clamd.ctl"] {
                if std::path::Path::new(sock).exists() {
                    return Self::new_unix(sock);
                }
            }
        }
        Self::new_tcp("127.0.0.1:3310")
    }

    fn connect(&self) -> std::io::Result<Box<dyn ReadWrite>> {
        #[cfg(unix)]
        if let Some(sock) = &self.socket_path {
            use std::os::unix::net::UnixStream;
            let s = UnixStream::connect(sock)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.set_write_timeout(Some(Duration::from_secs(5)))?;
            return Ok(Box::new(s));
        }

        if let Some(addr) = &self.tcp_addr {
            let s = TcpStream::connect_timeout(&addr.parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?, Duration::from_millis(500))?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            s.set_write_timeout(Some(Duration::from_secs(5)))?;
            return Ok(Box::new(s));
        }

        Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "no clamd address"))
    }
}

trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

impl Engine for ClamdEngine {
    fn name(&self) -> &str {
        "ClamAV"
    }

    fn status(&self) -> String {
        match self.connect() {
            Ok(mut conn) => {
                let _ = conn.write_all(b"PING\0");
                let mut buf = [0u8; 16];
                if let Ok(n) = conn.read(&mut buf) {
                    if &buf[..n] == b"PONG\0" || &buf[..n] == b"PONG\n" {
                        return "ready · connected to clamd".into();
                    }
                }
                "ready · connected".into()
            }
            Err(_) => "offline · clamd daemon not reachable".into(),
        }
    }

    fn scan(&self, ctx: &FileContext<'_>) -> Vec<Detection> {
        if ctx.size > self.max_stream_len {
            // Respect StreamMaxLength: files over limit are rejected by clamd
            return Vec::new();
        }

        let mut conn = match self.connect() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        // Send zINSTREAM command
        if conn.write_all(b"zINSTREAM\0").is_err() {
            return Vec::new();
        }

        // Send data in chunks of up to 64KB
        for chunk in ctx.data.chunks(64 * 1024) {
            let len = (chunk.len() as u32).to_be_bytes();
            if conn.write_all(&len).is_err() || conn.write_all(chunk).is_err() {
                return Vec::new();
            }
        }
        // End of stream marker: chunk of size 0
        if conn.write_all(&0u32.to_be_bytes()).is_err() {
            return Vec::new();
        }

        // Read response
        let mut response = String::new();
        if conn.read_to_string(&mut response).is_err() {
            return Vec::new();
        }

        let trimmed = response.trim();
        if trimmed.ends_with("FOUND") {
            let virus = trimmed
                .strip_prefix("stream: ")
                .and_then(|s| s.strip_suffix(" FOUND"))
                .unwrap_or(trimmed);
            return vec![Detection::with_scores(
                "ClamAV",
                virus.to_string(),
                Severity::High,
                ThreatClass::Signature,
                format!("ClamAV signature match: {virus}"),
                0.90,
                0.90,
            )];
        }

        Vec::new()
    }
}
