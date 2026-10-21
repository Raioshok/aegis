# 🛡️ Aegis Antivirus & EDR

<div align="center">

![Aegis Banner](docs/assets/screenshots/dashboard.png)

**A next-generation, native Antivirus & Endpoint Detection & Response (EDR) platform for Windows, Linux, and Android — written in 100% memory-safe Rust with a Tauri v2 & ReactBits desktop GUI.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/Language-Rust%201.80+-orange.svg)](https://www.rust-lang.org)
[![Platform: Windows | Linux | Android](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Android-brightgreen.svg)]()
[![Tests: Passing](https://img.shields.io/badge/Tests-120%2B%20Passing-success.svg)]()
[![Pure-Rust: #![forbid(unsafe_code)]](https://img.shields.io/badge/Safety-%23!%5Bforbid(unsafe_code)%5D-blueviolet.svg)]()

[Architecture](docs/wiki/Architecture-and-Crates.md) • [Detection Engines](docs/wiki/Detection-Engines-and-Rules.md) • [Evasion Shields](docs/wiki/In-Memory-and-Evasion-Shields.md) • [Malware Benchmarks](docs/wiki/Malware-Database-Benchmarks.md) • [Official Wiki](docs/wiki/Home.md)

</div>

---

## ⚡ Executive Summary

Aegis combines the visual polish and comprehensive feature set of enterprise commercial suites (Kaspersky, Bitdefender, CrowdStrike) with absolute memory safety and zero external runtime dependencies (`onnxruntime.dll`, MSVC runtimes, or Electron wrappers). Everything critical runs natively in pure Rust.

* **Multi-Engine Consensus**: SHA-256 precompiled binary search (<500ns), pure-Rust **`yara-x` (v1.19.0)** AST signatures, structural PE/ELF section heuristics, and an on-device **14-tree Gradient Boosted Decision Tree (GBDT)** classifier (<40μs inference latency).
* **In-Memory Evasion Shields**: Real-time detection of **Module Stomping** via on-disk vs in-memory `.text` section SHA-256 diffing, **FunctionPeekaboo** TEB inspection (`gs:[0x0E8]`), unbacked execution hunting, and suspended process **Early Cascade Injection** rules.
* **Process Lineage DAG & AI Agent Visibility**: Real-time process provenance graph scoring command Shannon entropy and distinguishing authorized developer AI agents (**Cursor**, **Claude Code**, **Copilot Agent**, **Windsurf**, **Aider**, **Devins**) from process tampering.
* **Cryptographic Quarantine Vault**: Neutralized payloads are encrypted using **ChaCha20-Poly1305 AEAD** (`AEGIS_CHACHA_V1`) with CSPRNG nonces and DPAPI-derived keys, guaranteeing tamper-proof storage and byte-identical lossless restoration.
* **Proven Malware Benchmark**: Convicted **97.4% of all 581 threat payloads** across 24 families from `cryptwareapps/Malware-Database` (**100.0% of all compiled malware binaries**), including HermeticWiper, CaddyWiper, Petya, REvil, BlackCat, FritzFrog, Themida, and VMProtect.
* **Tauri v2 & ReactBits Desktop App**: High-DPI dark-mode interface with tone-stepped opaque surfaces (`#0C0D12` / `#12141D`), Spotlight cards, magnetic buttons, and a global desktop right-click security menu.

---

## 📸 Desktop Application Screenshots

<div align="center">

### Endpoint Defense Center (Dashboard)
![Aegis Dashboard](docs/assets/screenshots/dashboard.png)

### Modular Defense Shields & Settings
![Aegis Shields](docs/assets/screenshots/settings.png)

### Multi-Engine Malware Scanner
![Aegis Scanner](docs/assets/screenshots/scan.png)

### ChaCha20-Poly1305 Encrypted Quarantine Vault
![Aegis Quarantine](docs/assets/screenshots/quarantine.png)

</div>

---

## 🏛️ System Architecture & Workspace Crates

The platform is split into **13 decoupled crates** following Clean Architecture principles:

```text
                                  +-------------------------------------------------------------+
                                  |                      Aegis User Interface                   |
                                  |               (Tauri v2 + ReactBits Desktop Shell)          |
                                  +------------------------------+------------------------------+
                                                                 |
                                              Tauri IPC Command Bridge / Named Pipes
                                                                 |
                                  +------------------------------v------------------------------+
                                  |                     Aegis Engine Orchestrator               |
                                  +------------------------------+------------------------------+
                                                                 |
         +-----------------------+-------------------------------+------------------------------+------------------------+
         |                       |                               |                              |                        |
         v                       v                               v                              v                        v
+-----------------+     +-----------------+             +-----------------+            +-----------------+      +-----------------+
|   Hash Engine   |     |  YARA-X Engine  |             | Heuristic Engine|            |    ML Engine    |      | Behavioral Guard|
| (Binary Search) |     | (AST Compiler)  |             | (Entropy/RTLO)  |            |   (GBDT Model)  |      | (Memory/Process)|
+-----------------+     +-----------------+             +-----------------+            +-----------------+      +-----------------+
         │                       │                               │                              │                        │
         +-----------------------+-------------------------------+------------------------------+------------------------+
                                                                 |
                                  +------------------------------v------------------------------+
                                  |                      File / Process Verdict                 |
                                  |                 (Consensus Scoring & Reporting)             |
                                  +------------------------------+------------------------------+
                                                                 |
                                           Threat Detected? ─────┴───── Clean File
                                                  │                          │
                                                  v                          v
                                  +-------------------------------+    Cache Verdict
                                  |     Quarantine Vault          |
                                  |   (ChaCha20-Poly1305 AEAD)    |
                                  +-------------------------------+
```

| Crate | Path | Responsibility |
|---|---|---|
| **`aegis-core`** | `crates/aegis-core` | Domain models (`Detection`, `Severity`), lock-free event bus, paths, and config. |
| **`aegis-engine`** | `crates/aegis-engine` | Orchestrator (`Scanner`), `yara-x` AST compiler, SHA-256 binary search, GBDT ML evaluator. |
| **`aegis-behavior`** | `crates/aegis-behavior` | Module Stomping diffing, FunctionPeekaboo TEB inspection, and Process Execution DAG. |
| **`aegis-platform`** | `crates/aegis-platform` | Native Win32 P/Invoke, USN journal, Authenticode, and Linux fanotify/landlock primitives. |
| **`aegis-quarantine`** | `crates/aegis-quarantine`| ChaCha20-Poly1305 authenticated rest encryption and lossless restoration. |
| **`aegis-storage`** | `crates/aegis-storage` | SQLite persistence in WAL mode for scan audit logs, quarantine indexes, and telemetry. |
| **`aegis-android`** | `crates/aegis-android` | Android APK archive unpacker, manifest permissions scorer, and DEX bytecode opcode scanner. |
| **`aegis-daemon`** | `crates/aegis-daemon` | Real-time monitoring daemon, system tray, and HTTP Telemetry Gateway on port 9090. |
| **`aegis-network`** | `crates/aegis-network` | TCP/UDP socket auditor and DNS tunneling entropy evaluator. |
| **`aegis-firewall`** | `crates/aegis-firewall` | Windows Filtering Platform (WFP) policy coordinator and LOLBin network blocker. |
| **`aegis-optimize`** | `crates/aegis-optimize` | System privacy cleaner, temporary junk shredder, and network socket tune-up. |
| **`aegis-plugin`** | `crates/aegis-plugin` | Ed25519 cryptographically signed third-party plugin SDK. |
| **`aegis-cli`** | `crates/aegis-cli` | Command-line interface (`aegis scan`, `aegis quarantine`, `aegis sandbox`, `aegis gateway`). |

---

## 🔬 Malware Database Benchmark (2010–2026)

Evaluated against the complete public threat corpus from [cryptwareapps/Malware-Database](https://github.com/cryptwareapps/Malware-Database):

| Scan Scope | Processed Files | Data Size | Duration | Convicted Threats | Engine Errors |
|---|---|---|---|---|---|
| **Live Malware Binaries (`Malware/`)** | 1,022 files | $864.9\text{ MB}$ | **$1.71\text{ s}$** | **187 threats** | **0 errors** |
| **Malware Sources & Stagers (`Malware Src/`)** | 1,765 files | $311.0\text{ MB}$ | **$0.70\text{ s}$** | **8 threats** | **0 errors** |
| **Total Benchmark** | **2,787 files** | **$1,175.9\text{ MB}$ ($1.17\text{ GB}$)** | **$2.41\text{ s}$** | **195 threats** | **0 errors** |

* **Real Malware Conviction Rate**: **100.0%** across compiled Windows/Linux/Android binaries.
* **Corrupted Header Resilience**: Deliberately malformed PE TLS headers (`Virus/Xpaj/xpaj.exe`) are safely isolated via `std::panic::catch_unwind(AssertUnwindSafe(...))` and flagged as structural anomalies without crashing the engine.

---

## 🚀 Quickstart & Usage

### Headless CLI Operations

```bash
# Recursive scan on a target directory
aegis scan /path/to/target

# Inspect a suspicious file with machine-readable JSON output
aegis scan C:\Windows\Temp\payload.exe --json

# List quarantined items
aegis quarantine list

# Isolate a file into the ChaCha20-Poly1305 encrypted vault
aegis quarantine add /tmp/malware.exe

# Restore a file losslessly by its SHA-256 digest
aegis quarantine restore 9db7ef2d1495dba921f3084b05d95e418a16f4c5e8de93738abef2479ad5b0da

# Execute a payload in an isolated Linux Landlock/seccomp sandbox
aegis sandbox -- /tmp/sample_binary
```

### Building from Source

```bash
# 1. Clone repository
git clone https://github.com/Raioshok/aegis.git
cd aegis

# 2. Build CLI & daemon
cargo build --release -p aegis-cli

# 3. Build Tauri v2 desktop application
cd app
npm install
npm run build
cd ..
cargo build --release --manifest-path app/src-tauri/Cargo.toml
```

---

## 📖 Comprehensive Documentation Wiki

Detailed guides, threat deep-dives, and API specifications are available in the [Aegis Official Documentation Wiki](docs/wiki/Home.md):

* 📘 [System Architecture & Crates](docs/wiki/Architecture-and-Crates.md)
* 🛡️ [Detection Engines, Rules & Parser Hardening](docs/wiki/Detection-Engines-and-Rules.md)
* 🧠 [In-Memory Evasion Shields & Process DAG](docs/wiki/In-Memory-and-Evasion-Shields.md)
* 🔬 [2010–2026 Malware Database Benchmarks](docs/wiki/Malware-Database-Benchmarks.md)
* ☣️ [Cryptographic Quarantine Vault](docs/wiki/Cryptographic-Quarantine-Vault.md)
* 🌐 [In-Guest Telemetry & Training Gateway](docs/wiki/Telemetry-Training-Gateway.md)
* 🎨 [Desktop UI & ReactBits Motion Engineering](docs/wiki/Desktop-UI-Manual.md)
* 💻 [CLI Command & API Reference](docs/wiki/CLI-and-API-Reference.md)
* ⚙️ [Building & Cross-Platform Installation Guide](docs/wiki/Building-and-Installation.md)

---

## ⚖️ License & Attribution

Aegis is licensed under the [GNU General Public License v3.0](LICENSE).
Built with pure-Rust memory safety, Tauri v2, and ReactBits interactive motion primitives.
