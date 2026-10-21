# Detection Engines, Rule Compilers & Parser Hardening

Aegis implements a layered multi-engine scanning pipeline that evaluates every binary and script payload across cryptographic hash matching, Abstract Syntax Tree (AST) compiled YARA rules, structural heuristic checks, and on-device machine learning inference.

---

## 1. Multi-Engine Orchestration Pipeline

```text
File Payload
     │
     ├── 1. SHA-256 Binary Search ───────────► Matches Known-Bad Hash? (Exit Early in < 500ns)
     │
     ├── 2. YARA-X AST Compiler ──────────────► Matches Behavioral / Weaponization Signatures?
     │
     ├── 3. Goblin PE/ELF Heuristics ────────► RWX Sections / High Entropy / Malformed Headers?
     │
     ├── 4. On-Device GBDT ML Classifier ────► Structural PE Vector Exceeds 85% Threshold?
     │
     └── 5. Android APK/DEX Engine ──────────► Dangerous Permissions / Opcode Heuristics?
```

---

## 2. Precompiled Hash Search Engine (`hash_engine.rs`)

* **Data Structure**: Contiguous array of 32-byte cryptographic hashes sorted unstably (`hashes.sort_unstable()`).
* **Lookup Algorithm**: Standard library binary search (`hashes.binary_search(&digest)`).
* **Performance**: $< 500\text{ ns}$ lookup latency per file. Zero heap allocations during lookup turns.
* **Precompiled Signatures**: Includes $309+$ verified threat digests from the 2010–2026 Malware-Database (`MEMZ`, `HawkEye`, `Cerber5`, `AnteFrigus`, `CryptoWall`, `Melissa.doc`, etc.).

---

## 3. Pure-Rust YARA-X Engine (`yara_engine.rs`)

Aegis compiles all rules using **`yara-x` (v1.19.0)**, VirusTotal's next-generation pure-Rust YARA engine. Unlike legacy C `libyara`, `yara-x` provides:
* **Zero C library bindings**: Pure Rust memory safety and zero risk of memory corruption in the scanner itself.
* **Thread-Local Scanners**: Scanners are reused across threads with zero mutex contention using `thread_local!` cells.
* **Production Rule Sets**:
  1. `rules/aegis_base.yar`: Core Linux/Windows baseline rules (Cobalt Strike, reverse shells, miners, persistence).
  2. `rules/droppers_and_cradles.yar`: High-fidelity dropper rules (Emotet, GandCrab swarms, PowerShell download cradles, WScript.Shell, obfuscated VBS/JS).
  3. `rules/ransomware_and_rats.yar`: Deep byte signatures for 2010–2026 ransomware, wipers, and RATs (Petya MBR, REvil, BlackCat Rust, Maze, TeslaCrypt, Thanos, CaddyWiper, NetWire, Remcos, WarzoneRAT, CrimsonRAT, DCRat, Nanocore, AlienSpy).

---

## 4. Parser Resilience & Anti-Crash Hardening

Antivirus parsers are frequent targets for crafted malware payloads featuring out-of-bounds pointers, corrupt headers, or truncated section tables designed to crash the security scanner.

### The Problem
During evaluation against the 2,795 samples in `cryptwareapps/Malware-Database`, samples with weaponized TLS directories (e.g. `Virus/Xpaj/xpaj.exe`) triggered an unhandled slice index out-of-range panic in the third-party `goblin` parser:
```text
thread panicked at goblin-0.9.3/src/pe/tls.rs:228:35:
range start index 140288 out of range for slice of length 75269
```

### The Aegis Defense
1. **Unwind Safety**: Enabled `panic = "unwind"` in root `Cargo.toml` so panics in release builds do not abort the process.
2. **Panic Boundary**: Wrapped all PE and ELF parsing calls in `std::panic::catch_unwind(AssertUnwindSafe(...))` across `heuristic_engine.rs` and `ml_engine.rs`:
   ```rust
   let parsed_pe = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
       goblin::pe::PE::parse(data)
   }));
   ```
3. **Anomaly Reporting**: If a parser panics on a malformed binary, the scanner catches the unwinding panic, records a `Heuristic.CorruptPEHeader` anomaly, and continues scanning subsequent files uninterrupted.

---

## 5. Android APK & DEX Engine (`crates/aegis-android`)

Aegis integrates a native Android scanner directly into the file evaluation pipeline:
* **Archive Unpacking**: Directly extracts `AndroidManifest.xml` and `classes.dex` without external Java/Android SDK tools.
* **Manifest Analysis**: Parses binary XML to extract requested permissions, exported activities, and broadcast receivers. Flags dangerous permission combos (`SEND_SMS`, `RECEIVE_SMS`, `SYSTEM_ALERT_WINDOW`, `BIND_ACCESSIBILITY_SERVICE`).
* **DEX Bytecode Heuristics**: Scans opcode streams for SMS stealers, banking overlays, and dynamic dex loading (`DexClassLoader`).
