# CLI Command & API Reference

The Aegis command-line executable (`aegis` / `Aegis.exe`) exposes full headless scanning, quarantine management, and sandbox execution controls.

---

## 1. CLI Commands

### `aegis scan`
Scan a file or directory recursively across all detection engines.
```bash
# Scan a directory recursively
aegis scan /path/to/target

# Scan a single executable
aegis scan C:\Windows\System32\notepad.exe

# Output machine-readable JSON
aegis scan /opt/app --json
```

### `aegis quarantine`
Manage the ChaCha20-Poly1305 encrypted quarantine vault.
```bash
# List all quarantined items
aegis quarantine list

# Manually isolate a suspicious payload
aegis quarantine add /tmp/malware.exe

# Restore a quarantined file by its SHA-256 digest
aegis quarantine restore 9db7ef2d1495dba921f3084b05d95e418a16f4c5e8de93738abef2479ad5b0da

# Permanently purge an item from the vault
aegis quarantine delete 9db7ef2d1495dba921f3084b05d95e418a16f4c5e8de93738abef2479ad5b0da
```

### `aegis sandbox` (Linux / WSL2)
Execute arbitrary commands inside a Landlock LSM + seccomp-bpf isolated sandbox with CPU and memory limits.
```bash
# Execute a command in fully isolated Landlock sandbox
aegis sandbox -- echo "Testing sandbox"

# Detonate a suspicious binary inside the sandbox
aegis sandbox -- /tmp/sample_binary
```

### `aegis gateway`
Run the HTTP Telemetry & Training Gateway daemon.
```bash
# Launch gateway on custom port
aegis gateway start --port 9090

# Stop active gateway
aegis gateway stop
```

---

## 2. Exit Codes

| Exit Code | Meaning |
|---|---|
| **`0`** | Clean scan (No threats detected). |
| **`1`** | Threats detected and convicted by one or more engines. |
| **`2`** | Invalid command usage or non-existent path. |
| **`101`** | Critical initialization error. |
