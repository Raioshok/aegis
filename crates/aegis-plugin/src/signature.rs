//! Ed25519 signing and verification for plugin manifests.
//!
//! A plugin is trusted only if its manifest carries a valid signature from a
//! key in the host's trust store. Signing keys never leave the developer;
//! Aegis ships only public verifying keys.

use crate::manifest::PluginManifest;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;

#[derive(Debug, thiserror::Error)]
pub enum SigError {
    #[error("invalid key length (want 32 bytes)")]
    KeyLen,
    #[error("invalid signature length (want 64 bytes)")]
    SigLen,
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("signature verification failed")]
    BadSignature,
}

/// A developer key pair (private + public).
pub struct KeyPair {
    signing: SigningKey,
}

impl KeyPair {
    /// Generate a fresh key pair from the OS RNG.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// Public (verifying) key as hex — safe to distribute.
    pub fn public_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    /// Private (signing) key as hex — keep secret.
    pub fn private_hex(&self) -> String {
        hex::encode(self.signing.to_bytes())
    }

    /// Load a signing key from hex.
    pub fn from_private_hex(h: &str) -> Result<Self, SigError> {
        let bytes = hex::decode(h)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| SigError::KeyLen)?;
        Ok(Self {
            signing: SigningKey::from_bytes(&arr),
        })
    }

    /// Sign a manifest, returning the signature as hex.
    pub fn sign(&self, manifest: &PluginManifest) -> String {
        let sig = self.signing.sign(&manifest.signing_bytes());
        hex::encode(sig.to_bytes())
    }
}

/// Verify a manifest's signature against a public key (both hex).
pub fn verify(
    manifest: &PluginManifest,
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<(), SigError> {
    let pk_bytes: [u8; 32] = hex::decode(public_key_hex)?
        .try_into()
        .map_err(|_| SigError::KeyLen)?;
    let sig_bytes: [u8; 64] = hex::decode(signature_hex)?
        .try_into()
        .map_err(|_| SigError::SigLen)?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| SigError::BadSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(&manifest.signing_bytes(), &sig)
        .map_err(|_| SigError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Permission, API_VERSION};

    fn manifest() -> PluginManifest {
        PluginManifest {
            name: "p".into(),
            version: "1.0.0".into(),
            description: String::new(),
            author: "a".into(),
            entrypoint: "run".into(),
            api_version: API_VERSION,
            permissions: vec![Permission::Scan],
        }
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let kp = KeyPair::generate();
        let m = manifest();
        let sig = kp.sign(&m);
        assert!(verify(&m, &sig, &kp.public_hex()).is_ok());
    }

    #[test]
    fn tampered_manifest_fails() {
        let kp = KeyPair::generate();
        let m = manifest();
        let sig = kp.sign(&m);
        let mut m2 = m.clone();
        m2.permissions.push(Permission::Network); // privilege escalation attempt
        assert!(verify(&m2, &sig, &kp.public_hex()).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let kp = KeyPair::generate();
        let other = KeyPair::generate();
        let m = manifest();
        let sig = kp.sign(&m);
        assert!(verify(&m, &sig, &other.public_hex()).is_err());
    }

    #[test]
    fn key_hex_roundtrip() {
        let kp = KeyPair::generate();
        let priv_hex = kp.private_hex();
        let kp2 = KeyPair::from_private_hex(&priv_hex).unwrap();
        assert_eq!(kp.public_hex(), kp2.public_hex());
    }
}
