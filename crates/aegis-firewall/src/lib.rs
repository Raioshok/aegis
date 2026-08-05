//! # aegis-firewall
//!
//! An nftables-backed firewall manager plus a live connection inspector.
//!
//! * [`model`] — rule/ruleset types and pure `nft`-script generation.
//! * [`connections`] — parse `/proc/net/*` into structured [`connections::Connection`]s.
//! * [`apply`] — apply/flush the Aegis nftables table (privileged; shells out to `nft`).
//!
//! Aegis owns a dedicated `inet aegis` table so it never disturbs a system
//! firewall. Rule→script translation is pure and tested; applying is isolated
//! because it needs root.

#![forbid(unsafe_code)]

pub mod apply;
pub mod connections;
pub mod model;

pub use connections::Connection;
pub use model::{Action, Direction, Protocol, Rule, Ruleset, TABLE};
