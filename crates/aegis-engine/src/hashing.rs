//! Streaming multi-digest hashing (SHA-256, SHA-1, MD5).

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

const CHUNK: usize = 1024 * 1024;

/// All three digests of a file, computed in a single streaming pass.
#[derive(Debug, Clone, Default)]
pub struct Digests {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub size: u64,
}

/// Compute SHA-256/SHA-1/MD5 and size for a file in one pass.
pub fn digest_file(path: &Path) -> std::io::Result<Digests> {
    let mut file = std::fs::File::open(path)?;
    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    let mut md5 = Md5::new();
    let mut buf = vec![0u8; CHUNK];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha256.update(&buf[..n]);
        sha1.update(&buf[..n]);
        md5.update(&buf[..n]);
        size += n as u64;
    }
    Ok(Digests {
        sha256: hex(&sha256.finalize()),
        sha1: hex(&sha1.finalize()),
        md5: hex(&md5.finalize()),
        size,
    })
}

/// SHA-256 of an in-memory buffer (lowercase hex).
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_and_abc() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
