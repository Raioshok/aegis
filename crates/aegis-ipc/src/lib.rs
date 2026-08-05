//! # aegis-ipc
//!
//! The IPC contract between the Aegis daemon and its clients (CLI today, Tauri
//! UI later). A deliberately small, framed-JSON-over-Unix-socket protocol:
//! local, low-attack-surface, and trivially testable. All three consumers share
//! these exact [`protocol`] types.

#![forbid(unsafe_code)]

pub mod client;
pub mod codec;
pub mod protocol;

pub use client::{Client, ClientError};
pub use codec::{read_frame, write_frame, CodecError};
pub use protocol::*;
