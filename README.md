# 🛡️ Aegis

**A next-generation, native antivirus platform for Linux — written in Rust.**

Aegis aims for the polish of commercial suites (Kaspersky/Bitdefender/ESET)
while respecting Linux philosophy: fast, memory-safe, least-privilege, no
Electron, everything critical in Rust.

> **Status: Milestone 5 — Firewall, Network IDS & Plugins.** All five milestones
> are complete. On top of the engine, daemon, behavioural and UI layers, Aegis
> now has an **nftables firewall manager**, a **network intrusion-detection**
> engine (C2 / DNS-tunnel / Tor / exposed-listener detection), and a
> **cryptographically-signed plugin SDK**. Nothing here is a placeholder — every
> feature below runs, with 70 passing tests across the workspace.

---

## What works today (Milestone 1)

| Capability | Detail |
|---|---|
| **Multi-engine scanning** | Hash (SHA-256/1/MD5), YARA (`yara-x`, pure Rust), and signature-less Heuristics run together with severity consensus. |
| **Project whitelist** | Trust a folder subtree or an exact file hash so your own code never false-positives. Checked *before* any engine runs — zero cost, zero false positives. |
| **Parallel engine** | rayon work-stealing across all cores; each file read once and fanned out to every engine (zero-copy). |
| **Encrypted quarantine** | Threats are sealed with **AES-256-GCM** (authenticated), the original removed, and restored byte-identical with tamper detection. |
| **SQLite history** | Every scan and detection is recorded and queryable. |
| **CLI** | `scan`, `quick`, `full`, `engines`, `history`, `whitelist`, `quarantine` — with `--json` for automation. |

### Real-time protection (Milestone 2)

| Capability | Detail |
|---|---|
| **Background daemon** | Tokio service: real-time monitor + IPC server + scheduler, with systemd `Type=notify` readiness and clean SIGTERM/SIGINT shutdown. |
| **On-access scanning** | Files are scanned the moment they land in a watched folder. **inotify** backend runs unprivileged (default); **fanotify** backend (`--features fanotify`) covers whole mounts with `CAP_SYS_ADMIN`. |
| **Auto-quarantine** | Optionally neutralize real-time threats instantly (encrypted vault). |
| **IPC control** | `aegis status`, `aegis realtime status`, `aegis reload`, `aegis stop` talk to the daemon over a framed-JSON Unix socket. |
| **Scheduler** | Periodic scans on a configurable interval, recorded to history. |

### Firewall, network IDS & plugins (Milestone 5)

| Capability | Detail |
|---|---|
| **Firewall** | Manages its own `inet aegis` nftables table (never clashes with ufw/firewalld). Block/unblock IPs & CIDRs, live connection viewer. `aegis firewall block <ip>` / `connections` / `apply`. |
| **Network IDS** | Classifies live `/proc/net` connections: blocklisted C2 IPs (CIDR threat intel), backdoor/reverse-shell/Tor ports, exposed `0.0.0.0` listeners. DNS-tunnel/DGA scoring. `aegis network`. |
| **Signed plugins** | ed25519-signed, permissioned plugin SDK. A plugin runs **only** if its manifest signature verifies against a trusted key and its API matches — tampering (even adding a permission) breaks trust. Plugins execute out-of-process, sandboxable via the M3 Landlock sandbox. `aegis plugins list/verify/keygen`. |

> **On eBPF/pcap:** connection- and DNS-level analysis (via `/proc/net`) covers
> C2, reverse shells, DNS tunneling, malicious IPs and Tor without a
> packet-capture pipeline. Packet-level eBPF/pcap inspection is the natural next
> deepening of this layer.

### Desktop UI (Milestone 4)

A native **Tauri v2** app in [`app/`](app) — no Electron, no Node backend. The
Rust bridge (`app/src-tauri`) exposes typed commands that call the Aegis engine
crates directly (scans, history, quarantine, whitelist, rootkit/memory) and the
daemon over `aegis-ipc` (live status + real-time counters).

- **Stack:** React 18 + TypeScript (strict) + Vite + TailwindCSS + Framer Motion + lucide icons; shadcn-style hand-built components.
- **Design:** glassmorphism, dark theme, animated page transitions, live-updating dashboard.
- **Pages:** Dashboard (protection status, engine health, stats), Scan, Threats & History, Whitelist, Quarantine (restore/delete), Behavior (rootkit + memory scans).

```bash
cd app && npm install && npm run tauri dev   # run the desktop app
npm run tauri build                          # bundle an AppImage / .deb
```

### Behavioural engine (Milestone 3)

| Capability | Detail |
|---|---|
| **Ransomware guard** | Sliding-window detection of mass-encryption (write burst + high entropy) and rename storms. Records the threat and — with the fanotify backend for process attribution — **kills** the offending process. Runs inside the daemon's real-time monitor. |
| **Rootkit scanner** | Cross-view `/proc`⇄`/sys` integrity checks: hidden processes (task-aware, race-hardened), hidden kernel modules, `/etc/ld.so.preload`, kernel taint. `aegis rootkit`. |
| **Memory scanner** | `/proc/<pid>/maps` analysis for W^X regions, anonymous executable memory, and executables running from a deleted file (fileless malware). `aegis memory [pid]`. |
| **Sandbox** | Run a suspicious command confined by **Landlock** (filesystem allow-list) + rlimits (CPU/memory/file-size). `aegis sandbox -- <cmd>`. Verified: reads outside the allow-list are denied by the kernel. |

> **On eBPF:** these behaviours are delivered through `/proc`, `/sys` and the
> file-event stream (how several production Linux AVs work). eBPF-based kernel
> syscall tracing is a planned deepening — it needs a loaded BPF program and
> root — and layers onto the same `aegis-behavior` engine.

### Verified detections
EICAR (hash **and** YARA), Linux reverse shells (bash `/dev/tcp`, Python,
netcat), `curl|bash` droppers, base64/`eval` obfuscation, cryptominers, and
persistence writes — with clean files passing untouched. The daemon was
verified live: dropping a reverse-shell script into a watched folder was
detected and auto-quarantined in real time.

---

## Install

### From source
```bash
git clone https://github.com/raio/aegis && cd aegis
cargo build --release
sudo install -Dm755 target/release/aegis /usr/local/bin/aegis
```

### Arch package
```bash
cd packaging && makepkg -si
```

Requires the Rust toolchain (`pacman -S rust`). No system libyara needed —
Aegis uses pure-Rust `yara-x`.

---

## Usage

```bash
aegis engines                       # engine status + config
aegis scan ~/Downloads              # scan a path
aegis quick                         # scan high-risk areas of $HOME
aegis full                          # scan from / (use sudo for full coverage)
aegis scan /tmp --json              # machine-readable output

# Trust your projects (the headline feature)
aegis whitelist add ~/Projects/myapp --label myapp
aegis whitelist list

# Quarantine workflow
aegis quarantine add /tmp/malware.bin
aegis quarantine list
aegis quarantine restore <sha256>
aegis quarantine delete  <sha256>

aegis history                       # recent scans

# Daemon + real-time protection
aegis daemon                        # run in foreground (systemd uses this)
aegis status                        # daemon health + realtime counters
aegis realtime status               # watched paths, events, blocks
aegis reload                        # re-read config + whitelist
aegis stop                          # graceful shutdown

# Behavioural engine (run in-process; no daemon needed)
aegis rootkit                       # cross-view rootkit / integrity scan
aegis memory [PID]                  # scan process memory for injected code
aegis sandbox --allow-read /usr -- /bin/somebinary   # run confined
```

Enable the ransomware guard in `~/.config/aegis/config.json`:
```json
"ransomware": { "enabled": true, "auto_kill": false }
```
(`auto_kill` needs the fanotify backend so the process can be attributed.)

Enable real-time protection in `~/.config/aegis/config.json`:
```json
"realtime": {
  "enabled": true,
  "paths": ["/home/you/Downloads"],
  "backend": "inotify",
  "auto_quarantine": true
}
```
Then `aegis daemon` (or `systemctl --user start aegis-daemon`). For mount-wide
prevention build with `--features fanotify` and grant `CAP_SYS_ADMIN`.

Exit codes: `0` clean · `1` threats found · `2` error. (CI-friendly.)

Try it safely with the EICAR test string:
```bash
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
aegis scan /tmp/eicar.com
```

Custom YARA rules go in `~/.config/aegis/yara-rules/*.yar` (metadata:
`severity = "low|medium|high|critical"`, `description`).

---

## Architecture

A Cargo workspace of focused crates (Clean Architecture — the domain has no I/O
or framework dependencies). Full detail in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```
aegis-core        domain model, errors, config, whitelist, event bus  (no deps)
   ▲
aegis-engine      Engine trait + Hash/YARA/Heuristic + parallel Scanner
aegis-storage     SQLite repositories (scans, threats, quarantine index)
aegis-quarantine  AES-256-GCM vault
aegis-behavior    ransomware guard, rootkit & memory scan, sandbox (M3)
aegis-firewall    nftables manager + connection inspector        (M5)
aegis-network     network IDS (C2/DNS-tunnel/Tor/listeners)      (M5)
aegis-plugin      ed25519-signed plugin SDK                      (M5)
aegis-ipc         framed-JSON IPC protocol + async client        (M2)
aegis-daemon      real-time monitor + IPC server + scheduler     (M2)
   ▲
aegis-cli         the `aegis` binary
app/              Tauri v2 desktop UI (React/TS)                 (M4)
```

## Data locations (XDG)

| What | Path |
|---|---|
| Config | `~/.config/aegis/config.json` |
| Whitelist | `~/.config/aegis/whitelist.json` |
| Your YARA rules | `~/.config/aegis/yara-rules/` |
| History DB | `~/.local/share/aegis/aegis.db` |
| Encrypted quarantine | `~/.local/share/aegis/quarantine/` |

---

## Roadmap

- [x] **M1 — Core engine + CLI**
- [x] **M2 — Daemon + real-time**: Tokio daemon, inotify/fanotify on-access scanning, framed-JSON IPC over UDS, scheduler
- [x] **M3 — Behavioural engine**: ransomware guard (+ process kill), rootkit scanner, memory scanner, Landlock sandbox
- [x] **M4 — Tauri UI**: React/TS/Tailwind/Framer-Motion desktop app over the Rust bridge + daemon IPC
- [x] **M5 — Firewall / network / plugins** (this release): nftables manager, network IDS, ed25519-signed plugin SDK

**All five milestones complete.** Natural next deepenings: eBPF syscall tracing
(behavioural), eBPF/pcap packet inspection (network), a WASM plugin runtime, and
Windows/macOS bundling of the UI.

### Post-milestone hardening pass

A follow-up pass tightened every rough edge flagged during the milestones:

- **Heuristic precision** — behavioural string patterns are now script-aware
  (a `/etc/cron` or `LD_PRELOAD=` string inside a compiled binary no longer
  fires), the YARA rules exclude ELF for script-intent detections, and the
  persistence/LD_PRELOAD rules require actual malicious intent. This cut
  `/usr/bin` false positives from **34 → 9** while keeping every real detection.
- **Sandbox seccomp** — the Landlock+rlimit sandbox now also installs a
  **seccomp-BPF** denylist (ptrace, mount, kexec, `init_module`, `bpf`, `setns`,
  `unshare`, …), completing the isolation triad.
- **Plugins actually run** — the SDK gained an out-of-process **runner** (JSON
  over stdin/stdout, trust + permission enforced, timeout) and `aegis plugins
  sign` / `run`, so the full keygen → sign → trust → run flow works end-to-end;
  tampering the manifest breaks the signature and execution is refused.
- **DNS analysis reachable** — the DNS-tunnel/DGA scorer is now exposed via
  `aegis dns <domain>…`.

Genuinely root/kernel-blocked items remain honestly deferred: live fanotify
verification, eBPF, and write-interception ransomware rollback all require
privileges/kernel programs that can't be exercised unprivileged.

---

## Quality

- `#![forbid(unsafe_code)]` in every crate.
- Unit tests in every module; `cargo test` green.
- Criterion benchmarks for hot paths (`cargo bench -p aegis-engine`).
- CI runs fmt + clippy (`-D warnings`) + tests + `cargo-deny`.

## License

GPL-3.0-or-later.
