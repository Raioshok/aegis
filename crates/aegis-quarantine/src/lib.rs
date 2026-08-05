//! # aegis-quarantine
//!
//! A **real** encrypted quarantine vault. When a threat is quarantined its
//! bytes are encrypted with **AES-256-GCM** (authenticated encryption) under a
//! per-install key, written to the vault directory, and the original is
//! removed. Restore decrypts and verifies the GCM tag, guaranteeing the file
//! comes back byte-identical or not at all.
//!
//! Unlike naive XOR "obfuscation", GCM provides confidentiality *and*
//! tamper-detection, and the sample cannot be executed in place.

#![forbid(unsafe_code)]

mod vault;

pub use vault::Quarantine;
