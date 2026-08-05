//! Unified error type for the Aegis platform.

use std::path::PathBuf;

/// The canonical error type shared across every Aegis crate.
///
/// Crates convert their local failures into this enum so that higher layers
/// (CLI, daemon, UI IPC) have a single, exhaustive surface to match on.
#[derive(Debug, thiserror::Error)]
pub enum AegisError {
    #[error("I/O error at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("engine `{engine}` failed: {reason}")]
    Engine { engine: String, reason: String },

    #[error("storage error: {0}")]
    Storage(String),

    #[error("quarantine error: {0}")]
    Quarantine(String),

    #[error("cryptography error: {0}")]
    Crypto(String),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("resource not found: {0}")]
    NotFound(String),

    #[error("operation not permitted: {0}")]
    Permission(String),
}

impl AegisError {
    /// Convenience constructor attaching a path to an [`std::io::Error`].
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, AegisError>;
