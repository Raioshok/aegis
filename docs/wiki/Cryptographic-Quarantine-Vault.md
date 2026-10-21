# Cryptographic Quarantine Vault (`aegis-quarantine`)

Aegis isolates convicted threat payloads using an encrypted, authenticated storage vault backed by **ChaCha20-Poly1305 AEAD** (`AEGIS_CHACHA_V1`).

---

## 1. Vault Security Design & Data Format

When a file is neutralized, Aegis does not merely rename the extension; it securely unlinks the original file from the host filesystem, encrypts its contents with a unique per-file nonce, and writes a self-describing authenticated binary blob into the quarantine vault directory (`~/.local/share/aegis/quarantine/` or `%LOCALAPPDATA%\aegis\quarantine\`).

### Blob Binary Format (`AEGIS_CHACHA_V1`)

```text
+-----------------------+-----------------------+-----------------------+
|  Magic Identifier     |     12-Byte Nonce     |    Header Length      |
|  "AEGIS_CHACHA_V1\0"  |     (CSPRNG OsRng)    |     (u32 little-endian)
|      (16 Bytes)       |       (12 Bytes)      |       (4 Bytes)       |
+-----------------------+-----------------------+-----------------------+
|                 Encrypted Metadata JSON Header                        |
|  (original_path, sha256, size, threat, engine, severity, quarantined_at)|
|                 Authenticated with Poly1305 Tag                       |
+-----------------------------------------------------------------------+
|                 Encrypted Payload Ciphertext Bytes                    |
|                 Authenticated with Poly1305 Tag                       |
+-----------------------------------------------------------------------+
```

1. **Magic Header**: Identifies the vault format and cipher version.
2. **Per-File Nonce**: 12 random bytes generated via CSPRNG `OsRng`. Nonce reuse is cryptographically impossible.
3. **Associated Authenticated Data (AAD)**: Authenticates the metadata JSON header so that any tampering with stored file paths or severity attributes invalidates the decryption verification tag.
4. **Key Management**: Symmetric 256-bit key protected by Windows DPAPI (`CryptProtectData`) or Linux file permissions (`0600`), and zeroized from RAM (`Zeroizing<[u8; 32]>`) immediately following vault operations.

---

## 2. Lossless Disinfection & Roundtrip Proof

Disinfection and lossless recovery were verified live in testing:

```text
$ ~/bin/aegis quarantine add /tmp/quarantine_test/xpaj.exe
Original file hash: 9db7ef2d1495dba921f3084b05d95e418a16f4c5e8de93738abef2479ad5b0da
Quarantined /tmp/quarantine_test/xpaj.exe (Malware.PE.GBDT)

✓ Disinfection SUCCESS: Original malware binary removed from host filesystem.

$ ~/bin/aegis quarantine list
WHEN                 THREAT                   ORIGINAL PATH
2026-10-21 09:36     Malware.PE.GBDT          /tmp/quarantine_test/xpaj.exe
  sha256=9db7ef2d1495dba921f3084b05d95e418a16f4c5e8de93738abef2479ad5b0da size=219.0 KB

$ ~/bin/aegis quarantine restore 9db7ef2d1495dba921f3084b05d95e418a16f4c5e8de93738abef2479ad5b0da
Restored /tmp/quarantine_test/xpaj.exe
Restored file hash: 9db7ef2d1495dba921f3084b05d95e418a16f4c5e8de93738abef2479ad5b0da

✓ Disinfection & Vault Roundtrip PROVEN: Byte-identical ChaCha20-Poly1305 authenticated restore verified.
```
