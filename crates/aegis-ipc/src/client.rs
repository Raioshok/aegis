//! Async client for the daemon control socket.

use crate::codec::{self, CodecError};
use crate::protocol::{Request, Response};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(windows)]
use tokio::net::windows::named_pipe::ClientOptions;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cannot reach the Aegis daemon at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("daemon error: {0}")]
    Daemon(String),
}

/// A one-shot client: connect, send a request, read a response.
#[derive(Debug)]
pub struct Client {
    socket: PathBuf,
}

impl Client {
    /// Use the default daemon socket path.
    pub fn new() -> Self {
        Self {
            socket: aegis_core::paths::socket_path(),
        }
    }

    /// Use an explicit socket path (tests, non-default installs).
    pub fn with_socket(path: impl AsRef<Path>) -> Self {
        Self {
            socket: path.as_ref().to_path_buf(),
        }
    }

    /// Send one request and await the daemon's response.
    pub async fn request(&self, req: &Request) -> Result<Response, ClientError> {
        #[cfg(unix)]
        let mut stream =
            UnixStream::connect(&self.socket)
                .await
                .map_err(|source| ClientError::Connect {
                    path: self.socket.clone(),
                    source,
                })?;

        #[cfg(windows)]
        let pipe_name = if self.socket.to_string_lossy().starts_with(r"\\.\pipe\") {
            self.socket.to_string_lossy().into_owned()
        } else {
            r"\\.\pipe\aegisd".to_string()
        };
        #[cfg(windows)]
        let mut stream = {
            let mut attempts = 0;
            loop {
                match ClientOptions::new().open(&pipe_name) {
                    Ok(s) => break s,
                    Err(e) => {
                        attempts += 1;
                        if attempts >= 25 {
                            return Err(ClientError::Connect {
                                path: PathBuf::from(&pipe_name),
                                source: e,
                            });
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                    }
                }
            }
        };

        codec::write_frame(&mut stream, req).await?;
        let resp: Response = codec::read_frame(&mut stream).await?;
        Ok(resp)
    }

    /// Whether a daemon appears to be listening (a successful `Ping`).
    pub async fn is_running(&self) -> bool {
        matches!(
            self.request(&Request::Ping).await,
            Ok(Response::Pong { .. })
        )
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}
