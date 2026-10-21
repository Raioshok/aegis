# Aegis Antivirus & EDR — System Architecture, Technology Stack & Roadmap

Aegis is an ultra-modern hybrid Windows, Linux, and Android Next-Generation Antivirus (NGAV) and Endpoint Detection & Response (EDR) platform written in pure, memory-safe Rust with a Tauri v2 desktop GUI.

---

## 1. Project Overview & Philosophy

* **Zero-Compromise Memory Safety**: 100% Rust workspace. `#![forbid(unsafe_code)]` enforced across domain, behavioral, rule, and ML layers. Low-level Win32/NTFS P/Invoke and kernel FFI are strictly encapsulated inside the platform abstraction layer (`aegis-platform`).
* **Zero C++ Runtime Bloat**: Runs without bulky external runtimes (`onnxruntime.dll`, MSVC runtimes, or C++ wrappers). Static compilation produces lightweight, high-performance binaries.
* **Anti-Slop Design Taste**: User interface adheres strictly to clean, modern desktop engineering principles (inspired by VirtualShield and Kaspersky): tone-stepped opaque surfaces, no fake rainbow glows or gradient text, honest action-first copy, tactile micro-interactions (`scale(0.97)`), and tabular figures for all metrics.

---

## 2. Technology Stack

| Layer | Technologies & Crates | Purpose |
|---|---|---|
| **Core & Domain** | `aegis-core`, `serde`, `thiserror`, `zeroize` | Pure business logic, unified error handling, configuration management, path resolution, and lock-free event bus. |
| **Static & ML Engines** | `aegis-engine`, `yara-x`, `goblin`, `sha2`, `md5` | AST-compiled YARA signatures, binary search hash matching, PE/ELF structural analysis, and pure-Rust GBDT machine learning inference. |
| **In-Memory & Behavioral**| `aegis-behavior`, `windows-sys` | Virtual memory inspection, direct syscall detection, sleep obfuscation trapping, Module Stomping diffing, FunctionPeekaboo hunter, and ransomware entropy guard. |
| **Quarantine Storage** | `aegis-quarantine`, `chacha20poly1305` | 256-bit ChaCha20 stream cipher with Poly1305 AEAD authenticated rest encryption (`AEGIS_CHACHA_V1`), zeroized memory keys, and legacy AES-GCM fallback. |
| **Persistence & Indexing** | `aegis-storage`, `rusqlite` | High-throughput SQLite database in WAL mode recording historical scans, quarantine vaults, and telemetry logs. |
| **Network & Firewall** | `aegis-network`, `aegis-firewall` | Windows Filtering Platform (WFP) tracking, Linux `nftables` manager, DNS-tunnel entropy analysis, and LOLBin network egress trapping. |
| **Platform Abstractions** | `aegis-platform` | Native Win32 P/Invoke, Authenticode verification (`WinVerifyTrust`), NTFS USN Journal (`FSCTL_QUERY_USN_JOURNAL`), DPAPI, and LOLDrivers BYOVD blocklist. |
| **Daemon & Microservices** | `aegis-daemon`, `tokio` (v1) | Real-time file monitoring (`fanotify` on Linux, `ReadDirectoryChangesW` on Windows), IPC server, and HTTP Gateway (port 9090) for lab VM orchestration. |
| **Android Antivirus** | `aegis-android`, `zip` | Static APK manifest parsing, dangerous permissions auditing, and Dalvik Executable (DEX) bytecode opcode heuristic analyzer. |
| **System Tune-Up** | `aegis-optimize` | System privacy scrubbing, disk junk purging, and network socket optimization. |
| **Plugin Architecture** | `aegis-plugin`, `ed25519-dalek` | Cryptographically signed third-party plugin runner with permission-scoped sandboxing. |
| **Desktop Application** | Tauri v2, React 18, Vite 5, Tailwind CSS | High-DPI hardware-accelerated desktop interface with live IPC command bindings. |

---

## 3. How the Subsystems Work

```text
                                  +-------------------------------------------------------------+
                                  |                      Aegis User Interface                   |
                                  |                  (Tauri v2 Desktop Application)             |
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

### 3.1 Static & Machine Learning Detection Pipeline (`aegis-engine`)
* **SHA-256 Binary Search**: 353+ precompiled binary digests queried via in-memory binary search in $< 500\text{ ns}$.
* **YARA-X Signature Matching**: 37 compiled production rules targeting Cobalt Strike, Lumma, Stealc, DarkGate, webshells, and droppers.
* **Structural PE/ELF Heuristics**: Calculates Shannon entropy per section, detects entrypoint section misalignments, sectionless ELFs, double extensions (`.pdf.exe`), and Right-to-Left Override (`\u{202E}`) spoofing.
* **Pure-Rust On-Device ML Classifier (`ml_engine.rs`)**:
  * Extracts an **EMBER 2024 / SOREL-20M compatible 576-dimensional feature vector**:
    * `0..256`: Normalized byte frequency histogram.
    * `256..512`: 2D Byte-Entropy joint distribution matrix (16 byte bins $\times$ 16 local entropy bins).
    * `512..544`: Section characteristics (rwx sections, raw-to-virtual size ratios, unmapped overlay, unusual section names).
    * `544..576`: Imports categorization (injection, evasion, network, crypto, persistence APIs) and FireEye/pefile MD5 `imphash`.
  * **Inference**: Evaluates an expert-calibrated **14-tree Gradient Boosted Decision Tree (GBDT)** ensemble using contiguous 16-byte `FlatNode` arrays in **$< 40\text{ }\mu\text{s}$** with $< 1.5\text{ MB}$ RAM overhead.

### 3.2 In-Memory Evasion & Behavioral Defense (`aegis-behavior`)
* **W+X & Reflective PE Detection**: Traverses virtual address spaces (`VirtualQueryEx`). Flags unbacked `PAGE_EXECUTE_READWRITE` allocations and hidden in-memory `MZ`/`PE\0\0` headers while honoring JIT allowlists (v8, node, jvm).
* **Direct Syscall Stubs**: Scans executable private regions for Hell's Gate / SysWhispers patterns (`4c 8b d1 b8 ... 0f 05 c3`).
* **AMSI & ETW Patch Traps**: Scans `amsi.dll` and `ntdll.dll` function prologues for patching hooks (`0xC3` `ret`, `0xC2` `ret imm16`, `0xB8 57 00 07 80 0xC3`).
* **Process Hollowing**: Compares on-disk image headers (`e_lfanew` and PE signatures) against in-memory base headers via `ReadProcessMemory`.
* **Module Stomping / Overloading Hunter**:
  * Inspects mapped `MEM_IMAGE` DLLs using `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`.
  * Computes the SHA-256 digest of the on-disk `.text` section and diffs it against the live in-memory `.text` section bytes. Significant divergence flags code overwriting inside legitimately signed DLLs.
* **FunctionPeekaboo TEB Hunter (MDSec 2024/2025)**:
  * Resolves thread TEB addresses via `NtQueryInformationThread(ThreadBasicInformation)`.
  * Audits `TEB.UserReserved[0..4]` (`gs:[0x0E8]`). Detects status constant `0x80000001` and hidden `VirtualProtect` pointers used for per-function sleep unmasking.
* **Thread Hijacking & PoolParty Guard**:
  * Detects threads whose instruction pointer (`RIP` via `GetThreadContext`) or start address resides in unbacked private memory.
* **Behavioral Rule Engine (Sigma/Falco Style)**:
  * **Early Cascade Injection**: Detects process creation in a suspended state targeting host binaries (`werfault.exe`, `conhost.exe`, `notepad.exe`) with Application Compatibility Shim engine tampering.
  * **Process Lineage DAG Anomaly**: Traps document readers (`winword.exe`, `excel.exe`, `acrobat.exe`, `outlook.exe`) spawning interactive interpreters or LOLBins (`powershell.exe`, `cmd.exe`, `wscript.exe`, `certutil.exe`).
  * **Credential Extraction & Tampering**: Traps LSASS minidumps via `comsvcs.dll`, `reg save HKLM\SAM`, StickyKeys accessibility replacement (`sethc.exe`), and Defender exclusion tampering.

### 3.3 Platform Security & BYOVD Shield (`aegis-platform`)
* **LOLDrivers Cryptographic Blocklist**: Built-in SHA-256 hash database blocking notorious signed vulnerable kernel drivers:
  * `RTCore64.sys` (MSI Afterburner arbitrary kernel RW)
  * `gdrv.sys` (GIGABYTE arbitrary physical memory mapping)
  * `dbutil_2_3.sys` (Dell DBUtil privilege escalation)
  * `mhyprot2.sys` (anti-cheat driver abused to terminate security processes)
  * `procexp.sys`, `asrdrv.sys`, `winring0x64.sys`, `cpuz141.sys`, `zam64.sys`, `kprocesshacker.sys`, `echo.sys`
* **Driver Load Verification**: Enforces `PlatformSecurity::verify_driver_load` before service registration, preventing kernel privilege escalation.
* **USN Journal Auditing**: Direct NTFS volume queries (`FSCTL_QUERY_USN_JOURNAL`) for forensic change tracking.
* **Authenticode Verification**: Native `WinVerifyTrust` validation for system images and drivers.

### 3.4 Cryptographic Quarantine Vault (`aegis-quarantine`)
* Encrypts quarantined artifacts using **ChaCha20-Poly1305 AEAD** (`AEGIS_CHACHA_V1`).
* Headers store 12-byte random nonces and encrypted metadata (original path, file size, epoch timestamp) authenticated via Associated Authenticated Data (AAD).
* Master keys are generated using CSPRNG, protected via Windows DPAPI (`CryptProtectData`), and zeroized from RAM upon operation completion.

### 3.5 Telemetry & Training Gateway (`aegis-daemon`)
* Asynchronous HTTP daemon listening on port `9090` (`http://192.168.18.166:9090` and `172.31.0.1:9090` across Hyper-V virtual switches).
* Endpoints:
  * `GET /train.py` / `GET /train.sh`: Delivers the complete in-guest automated detonation and audit runner.
  * `GET /api/v1/signatures`: Serves live YARA-X rules and hash databases.
  * `POST /api/v1/telemetry/report`: Ingests in-guest scan verdicts and evasion telemetry.
  * `POST /api/v1/train/feedback`: Ingests missed sample features directly into threat intelligence databases.

---

## 4. User Interface Architecture & Design Philosophy

The Aegis desktop application (`app/`) is built on **Tauri v2** with a focus on high technical density and clean aesthetics.

### 4.1 Anti-Slop Design Principles
* **Tone-Stepped Opaque Surfaces**: High-contrast, clean dark/light surfaces (`#0C0D12` dark background, `#10121A` sidebar, `#F6F8FB` light background) instead of excessive, illegible frosted blurs.
* **Tactile Interactions**: Buttons and selectable rows feature a subtle `active:scale-[0.98]` physical depression feel.
* **Tabular Figures (`tab-nums`)**: Quantitative numbers, timestamps, percentages, and memory addresses use fixed-width figures to prevent visual layout jitter.
* **Honest Technical Copy**: Action-first labels without buzzwords or vague status indicators.

### 4.2 Color System & Design Tokens
* **Background Light**: `#F6F8FB` | **Background Dark**: `#0C0D12`
* **Card Surface Light**: `#FFFFFF` | **Card Surface Dark**: `#161922`
* **Primary Accent**: `#FF7222` (Kaspersky / Industrial Orange)
* **Status Success**: `#10B981` (Emerald Green)
* **Status Warning**: `#F59E0B` (Amber)
* **Status Critical / Danger**: `#DC2626` (Crimson Red)
* **Primary Interactive**: `#2563EB` (Cobalt Blue)

### 4.3 UI Viewport Matrix (All 12 Pages)

```text
+-----------------------------------------------------------------------------------------------+
|                                      AEGIS DESKTOP SUITE                                      |
+-------------------+---------------------------------------------------------------------------+
| [Overview]        | DASHBOARD VIEW                                                            |
| [Smart Scan]      | • Security Posture Radial Gauge (100% Armed)                              |
| [Android AV]      | • Subsystem Status: Local Host, File Mmap, Behavioral, GBDT ML, BYOVD     |
| [Threat Events]   | • 10-Day Threat Event History Column Chart                                |
| [Processes]       | • Active Telemetry & Training Gateway Status (Port 9090)                  |
| [Allowlist]       +---------------------------------------------------------------------------+
| [Quarantine]      | REAL-TIME CONTROLS                                                        |
| [Behavior Guard]  | • Game Mode (Direct3D / Fullscreen Detection & Idle Priority Throttling)  |
| [Network Firewall]| • Instant One-Click Deep Scan Trigger                                     |
| [Hardening/BYOVD] | • Recent Security Alerts Log                                              |
| [System Tune-Up]  |                                                                           |
| [Settings]        |                                                                           |
+-------------------+---------------------------------------------------------------------------+
```

1. **Overview (`Dashboard.tsx`)**:
   * Security posture radial status gauge (100% Protected).
   * Subsystem health list (Local Host, Zero-Copy Mmap, Behavioral Engine, On-Device GBDT ML, BYOVD Driver Shield, Gateway).
   * 10-day historical activity column chart and recent alerts log.
2. **Smart Scan (`Scan.tsx`)**:
   * Multi-target file scanner with live progress reporting (file path, files/sec rate, elapsed time).
   * Displays consensus detections across Hash, YARA-X, Heuristic, and MachineLearning engines.
3. **Android Antivirus (`AndroidScanner.tsx`)**:
   * APK archive parser inspecting Android manifests, permissions, and DEX bytecode opcode streams.
4. **Threat Events (`Threats.tsx`)**:
   * Historical log of blocked threats with severity badges, SHA-256 hashes, and quarantine status.
5. **Process Inspector (`Processes.tsx`)**:
   * Live process list with Authenticode signature status, memory risk score, and one-click termination.
6. **Allowlist (`Whitelist.tsx`)**:
   * Management for whitelisted cryptographic hashes and recursive directory paths.
7. **Quarantine Vault (`Quarantine.tsx`)**:
   * Inspects ChaCha20-Poly1305 encrypted artifacts with options to securely restore or permanently shred.
8. **Behavior Guard (`Behavior.tsx`)**:
   * Dedicated controls for Kernel & Rootkit audit and live Process Memory inspection.
   * Telemetry cards for Sleep Obfuscation Guard, Thread Pool Guard (PoolParty), and BYOVD Driver Blocklist.
9. **Network Firewall (`Network.tsx`)**:
   * Live socket monitor (TCP/UDP extended table), DNS-tunneling entropy scorer, and LOLBin egress blocker.
10. **Hardening & BYOVD (`Vulnerabilities.tsx`)**:
    * System configuration auditor (UAC, SMBv1, USB AutoRun, LOLDrivers blocklist enforcement).
    * Ransomware canary honeypot deployment trigger (`deploy_ransomware_honeypot`).
11. **System Tune-Up (`Optimize.tsx`)**:
    * Kaspersky-style disk cleanup, privacy history scrubbing, and network optimization.
12. **Shields & Settings (`Settings.tsx`)**:
    * Master Real-Time Protection switch.
    * Kaspersky-style Gaming Mode (resource throttling to `IDLE_PRIORITY_CLASS` during Direct3D fullscreen games).
    * Individual modular switches: File System, Memory & Thread, Network Firewall, Ransomware Watchdog, On-Device Machine Learning (GBDT), BYOVD Driver Blocklist, In-Memory Evasion Shield.
    * Shannon entropy packer sensitivity slider (7.00 – 7.90).

---

## 5. Forward Engineering Roadmap (2024–2026)

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              AEGIS FORWARD IMPLEMENTATION ROADMAP                      │
├──────────────────────────┬──────────────────────────┬──────────────────────────────────┤
│ Phase 1: In-Memory SOTA  │ Phase 2: Behavioral DAG  │ Phase 3: Hardware & Kernel PPL   │
│ (COMPLETED)              │ (ACTIVE DEVELOPMENT)     │ (PLANNED)                        │
├──────────────────────────┼──────────────────────────┼──────────────────────────────────┤
│ ✓ ChaCha20-Poly1305 Vault│ • Process Execution DAG  │ • Intel CET / Shadow Stack Check │
│ ✓ 14-Tree GBDT ML Engine │   Lineage Scoring Engine │ • Hardware LBR ETW Telemetry     │
│ ✓ BYOVD LOLDrivers Shield│ • ThreatFox / Bazaar API │ • Windows Minifilter Driver      │
│ ✓ Module Stomping Diff   │   Streaming Ingestion    │   (aegis_flt.sys Altitude 320000)│
│ ✓ FunctionPeekaboo Hunter│ • Automated YARA-X Rule  │ • ELAM Boot Driver for Protected │
│ ✓ Early Cascade Rules    │   Synthesis in Sandbox   │   Process Light (PPL) Status     │
└──────────────────────────┴──────────────────────────┴──────────────────────────────────┘
```

### Phase 1: Completed SOTA Enhancements (Current Master)
* [x] **ChaCha20-Poly1305 Quarantine Vault**: Rest data authenticated encryption with DPAPI keys.
* [x] **On-Device GBDT PE Engine**: Pure-Rust flat-array decision tree runner ($< 40\text{ }\mu\text{s}$ latency).
* [x] **BYOVD LOLDrivers Shield**: Cryptographic hash blocklist for vulnerable kernel drivers.
* [x] **Module Stomping Hunter**: In-memory `.text` section hash diffing against on-disk signed DLLs.
* [x] **FunctionPeekaboo Hunter**: TEB `UserReserved` slot inspection for on-demand function masking.
* [x] **Early Cascade Injection Trap**: Process creation rules catching Shim engine hijacking before EDR loads.
* [x] **116 / 116 Tests Passing**: Full unit and integration coverage across all crates.

### Phase 2: Behavioral Provenance Graph & Dynamic Intel (Next Up)
* [ ] **Process Execution DAG Engine**: Model process trees as Directed Acyclic Graphs with anomaly scoring (e.g. `WINWORD.EXE` $\rightarrow$ `cmd.exe` $\rightarrow$ `powershell.exe`).
* [ ] **ThreatFox & MalwareBazaar Live Feeds**: Automated real-time streaming ingestion into local threat intelligence cache.
* [ ] **Automated In-Guest Detonation Runner**: Autonomous execution inside Hyper-V guest lab (`172.31.0.1:9090`) with automated IoC extraction.

### Phase 3: Hardware & Kernel Driver Telemetry (Final Frontier)
* [ ] **Hardware Last Branch Record (LBR)**: Win32 `TraceConfigureLastBranchRecord` integration over ETW to hardware-verify synthetic call stack frames (`SilentMoonwalk`).
* [ ] **Windows File System Minifilter (`aegis_flt.sys`)**: Kernel driver at Altitude `320000` (`FSFilter Anti-Virus`) for zero-race pre-write sector buffering and true ransomware rollback.
* [ ] **Early Launch Anti-Malware (ELAM) & PPL**: Attestation driver elevating the Aegis daemon into `PsProtectedSignerAntimalware`, preventing termination by ring-0 rootkits and BYOVD tools.
