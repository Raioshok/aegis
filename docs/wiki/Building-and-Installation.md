# Building & Installation Guide

Aegis supports native compilation across **Windows**, **Linux**, **WSL2**, and **Android**.

---

## 1. Prerequisites

* **Rust Toolchain**: `rustc` 1.80+ (`stable-x86_64-pc-windows-msvc` / `gnu` or `stable-x86_64-unknown-linux-gnu`).
* **Node.js**: Node 18+ and `npm` (for the Tauri v2 desktop frontend in `app/`).
* **Platform Dependencies**:
  * **Windows**: Visual Studio C++ Build Tools or MinGW-w64.
  * **Linux (Ubuntu/Debian)**: `build-essential`, `libssl-dev`, `libgtk-3-dev`, `libwebkit2gtk-4.1-dev`.

---

## 2. Windows Build Instructions

### Building the CLI & Daemon
```powershell
# Build release CLI binary
cargo build --release -p aegis-cli

# Binary output:
target\release\aegis.exe
```

### Building the Desktop Application (Tauri v2)
```powershell
cd app
npm install
npm run build
cd ..

cargo build --release --manifest-path app/src-tauri/Cargo.toml

# Binary output:
app\src-tauri\target\release\aegis-ui.exe
```

---

## 3. Linux & WSL2 Build Instructions

```bash
# Install system packages (Ubuntu/Debian)
sudo apt-get update && sudo apt-get install -y build-essential curl git

# Install Rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Compile Aegis CLI & Sandbox engine
cargo build --release -p aegis-cli

# Binary output:
target/release/aegis
```

---

## 4. Running the Test Suite

```bash
# Run all workspace unit and integration tests (120+ tests)
cargo test --workspace

# Run multi-engine YARA & GBDT benchmarks
cargo test -p aegis-engine test_all_bundled_rules_compile_cleanly -- --exact
```
