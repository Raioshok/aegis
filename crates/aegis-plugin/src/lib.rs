//! # aegis-plugin
//!
//! A signed, permissioned plugin SDK. Plugins are distributed as a directory
//! with a `plugin.json` manifest and a `plugin.sig` ed25519 signature; the host
//! enables a plugin only when its signature verifies against a trusted publisher
//! key and its API version matches. Tampering with the manifest (e.g. adding a
//! permission) invalidates the signature.
//!
//! Execution model: plugins run as external processes the host invokes — and can
//! be confined with the [`aegis-behavior`](../aegis_behavior) Landlock sandbox —
//! so a plugin never shares the host's address space. This SDK owns the
//! trust/permission core; the host wires execution.

#![forbid(unsafe_code)]

pub mod manifest;
pub mod registry;
pub mod runner;
pub mod signature;

pub use manifest::{Permission, PluginManifest, TargetFile, API_VERSION};
pub use registry::{discover, evaluate, DiscoveredPlugin, PluginStatus, TrustStore};
pub use runner::{run, PluginDetection, PluginRequest, PluginResponse, RunError};
pub use signature::{verify, KeyPair};
