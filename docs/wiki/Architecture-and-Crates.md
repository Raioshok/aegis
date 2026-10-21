# Aegis System Architecture & Workspace Crates

The Aegis workspace is organized into **13 modular, decoupled Rust crates** following strict Clean Architecture and Domain-Driven Design (DDD) principles. Business domain types, error primitives, and event streaming interfaces have zero external operating system or framework dependencies, making them effortlessly testable, mockable, and portable across platforms.

---

## Workspace Crate Matrix

| Crate | Path | Responsibility & Boundary | Key Dependencies |
|---|---|---|---|
| **`aegis-core`** | `crates/aegis-core` | Domain model types (`Detection`, `Severity`, `ThreatClass`, `Config`, `AccessEvent`, `ProcessEvent`), lock-free bus, error types, and path resolution. | `serde`, `thiserror`, `zeroize` |
| **`aegis-engine`** | `crates/aegis-engine` | Multi-engine scan orchestrator (`Scanner`), YARA-X rule compiler, SHA-256 binary search table, Shannon entropy analyzer, Goblin PE/ELF parser, and on-device GBDT ML classifier. | `yara-x`, `goblin`, `sha2`, `hex`, `rayon` |
| **`aegis-behavior`** | `crates/aegis-behavior` | In-memory evasion shields (Module Stomping, FunctionPeekaboo TEB inspection, unbacked execution hunting, Early Cascade injection, and Process Execution DAG lineage scoring). | `aegis-core`, `aegis-platform`, `windows-sys` |
| **`aegis-platform`** | `crates/aegis-platform` | Operating system abstractions for Windows NT (P/Invoke, WinVerifyTrust, USN Journal, DPAPI, LOLDrivers blocklist) and Linux (fanotify, landlock, seccomp). | `windows-sys`, `nix`, `landlock`, `seccompiler` |
| **`aegis-quarantine`** | `crates/aegis-quarantine` | Cryptographic rest storage using ChaCha20-Poly1305 AEAD (`AEGIS_CHACHA_V1`) authenticated nonces, DPAPI master keys, and lossless byte-identical restoration. | `chacha20poly1305`, `aes-gcm`, `aegis-storage` |
| **`aegis-storage`** | `crates/aegis-storage` | High-throughput SQLite persistence in WAL mode for scan audit trails, quarantine index records, and telemetry stats. | `rusqlite`, `aegis-core` |
| **`aegis-android`** | `crates/aegis-android` | Android APK archive unpacker, AndroidManifest permission security scoring, and Dalvik Executable (DEX) bytecode opcode scanner. | `zip`, `sha2`, `serde_json` |
| **`aegis-daemon`** | `crates/aegis-daemon` | Real-time monitoring daemon, system tray integration, named pipes / IPC server, and HTTP Telemetry & Training Gateway on port 9090. | `tokio` (v1), `aegis-engine`, `aegis-quarantine` |
| **`aegis-network`** | `crates/aegis-network` | TCP/UDP extended connection auditor, DNS tunneling entropy evaluator, and network egress telemetry. | `aegis-core`, `tokio` |
| **`aegis-firewall`** | `crates/aegis-firewall` | Windows Filtering Platform (WFP) policy coordinator, LOLBin network blocker, and malicious IP/domain enforcement. | `aegis-core`, `windows-sys` |
| **`aegis-optimize`** | `crates/aegis-optimize` | System privacy cleaner, temporary junk shredder, and network socket TCP/IP tune-up. | `aegis-core`, `walkdir` |
| **`aegis-plugin`** | `crates/aegis-plugin` | Ed25519 cryptographically signed third-party plugin SDK with permission-scoped sandboxes. | `ed25519-dalek`, `aegis-core` |
| **`aegis-cli`** | `crates/aegis-cli` | Command-line interface (`aegis scan`, `aegis quarantine`, `aegis sandbox`, `aegis gateway`). | `clap`, `aegis-engine`, `aegis-daemon` |

---

## Clean Architecture Domain Layer

```text
  ┌─────────────────────────────────────────────────────────────┐
  │                 aegis-cli / aegis-gui / app                 │ (Presentation & IPC)
  └──────────────────────────────┬──────────────────────────────┘
                                 │
  ┌──────────────────────────────v──────────────────────────────┐
  │         aegis-daemon / aegis-engine / aegis-behavior        │ (Use Cases & Core Services)
  └──────────────────────────────┬──────────────────────────────┘
                                 │
  ┌──────────────────────────────v──────────────────────────────┐
  │             aegis-storage / aegis-quarantine                │ (Infrastructure & Persistence)
  └──────────────────────────────┬──────────────────────────────┘
                                 │
  ┌──────────────────────────────v──────────────────────────────┐
  │                  aegis-core / aegis-platform                │ (Domain Primitives & OS Layer)
  └─────────────────────────────────────────────────────────────┘
```

1. **Inner Entities**: `aegis-core` defines entities (`Detection`, `Severity`, `ThreatClass`) that have zero dependencies on storage, UI, or specific scanners.
2. **Strategy Pattern**: The `Engine` trait in `aegis-engine` defines a clean interface implemented by `HashEngine`, `YaraEngine`, `HeuristicEngine`, and `MlEngine`.
3. **Pluggable Orchestration**: The `Scanner` aggregates all active engines and executes concurrent multi-threaded inspection using `rayon`, ensuring high throughput without blocking the calling thread.
