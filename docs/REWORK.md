# Aegis Rework Proposal

This proposal comes from a full read of the source and a pass over current tooling and research. For each subsystem it covers how the code works today, what is wrong with it, and what it should become. §9 adds Windows support through a shared platform layer, so one engine and one UI serve both operating systems. The last section orders the work into phases, with separate Linux and Windows tracks. Every claim about the code cites a file and line. Claims about external tools cite the source listed at the end.

---

## 1. How detection works today

```
walkdir ─▶ whitelist(path) ─▶ lstat/size gate ─▶ SHA-256/1/MD5 (full read #1)
        ─▶ whitelist(hash) ─▶ read first 8 MiB (read #2) ─▶ for each engine:
              Hash      : sha256 ∈ HashSet (1 built-in hash: EICAR)
              YARA      : yara-x over the 8 MiB buffer, new Scanner per file
              Heuristic : packer bytes, entropy (ELF/PE), 10 regexes
        ─▶ severity = max(detections)   ─▶ is_threat = any detection
```

Problems with this pipeline:

| Area | Issue | Where |
|---|---|---|
| I/O | Each file is read twice, and only the first 8 MiB reach YARA and the heuristics. A malicious tail past 8 MiB is never seen. | `orchestrator.rs:128,145` |
| Hashing | SHA-1 and MD5 are computed but never matched. | `hash_engine.rs:67` |
| Signatures | There is effectively no signature database: the hash set holds only EICAR, and the bundled YARA rules are 7 hand-written rules. | `hash_engine.rs:42`, `rules/aegis_base.yar` |
| YARA | One bad user rule file disables all YARA, bundled rules included. A new `Scanner` is built for every file. | `lib.rs:72`, `yara_engine.rs:136` |
| Heuristics | Packer markers are matched in *every* file, text included. "Is text" means there is no NUL byte in the first 512 bytes, so roughly 13% of random or compressed blobs count as text. | `heuristic_engine.rs:204-222` |
| Scoring | Severity is simply the maximum across engines. The docs call this consensus, but no engine's agreement raises confidence, and a single LOW match marks the file as a threat. | `model.rs:139` |
| Whitelist | Every rule calls `canonicalize()` on every file, which costs about two syscalls each time. A path rule overrides even a known-bad hash. | `whitelist.rs:46` |
| Config | `threads` is never used. `skipped` is always 0. | `orchestrator.rs:182` |

## 2. Detection rework

### 2.1 Scan pipeline
- **Read each file once.** Use `memmap2`, which is already a dependency but unused. If mmap fails, read in streaming chunks. Hash and scan the same bytes. Give YARA the whole file up to `max_file_size`, not just 8 MiB. Heuristics can keep a window, but it should cover the head and the tail.
- **Verdict cache.** Key verdicts by `(dev, ino, size, mtime_ns, ctime_ns)` together with the engine/rule-set version. An unchanged file then skips hashing entirely. With fanotify, a kernel ignore mask can serve as this cache (see §3).
- **Reuse one YARA scanner per thread.** The yara-x docs say compiled `Rules` can be shared by many `Scanner`s, and that a `Scanner` can be reused across files. Use rayon `map_init` or a `thread_local!` to keep one scanner per worker.
- **Honour `threads`** by running scans in a dedicated `rayon::ThreadPool`. Stream results instead of keeping every clean `FileVerdict` in memory.

### 2.2 Engines

| Engine | Rework |
|---|---|
| **Hash** | Load SHA-256 lists from MalwareBazaar (abuse.ch) exports into a sorted `Vec<[u8;32]>` searched by binary search, or into an `fst`. Drop SHA-1 and MD5 unless a feed needs them. |
| **YARA** | Ship and auto-update the **YARA Forge** packages, which come in core, extended and full tiers that trade false positives against coverage. Default to **core**. Test-compile each user rule file on its own and skip the ones that fail, reporting them in `status()`, so one bad file never disables the engine. Version the rule set so it can invalidate the verdict cache. |
| **ClamAV** *(new, optional)* | Talk to `clamd` over its Unix socket using `zINSTREAM`, as other mature clients do instead of linking libclamav. This adds millions of signatures at almost no cost. Respect `StreamMaxLength`: files over the limit are rejected and the connection closed, so record them as *unscanned*, never as clean. |
| **Heuristic** | Parse binaries with `goblin` and look at structure: per-section entropy instead of whole-file entropy, RWX segments, a missing or odd `PT_INTERP`, a binary that is both stripped and packed, packer section names. Run packer-marker checks only on executables. Run script patterns only on files with a shebang or a known script extension. |

### 2.3 Scoring
Replace "max severity" with a confidence score. Each detection should carry a weight and a confidence, and agreement between engines should raise the score. The verdict levels become **Malware**, **PUA/Suspicious** and **Clean**. A single low-confidence heuristic hit produces *Suspicious*: it is reported but never auto-quarantined. Engine errors become `error`, never detections.

### 2.4 Whitelist
Canonicalize each rule once, when it loads. Matching then becomes a prefix-trie lookup with no syscalls. **A known-bad hash should win over a trusted path**, so a project folder that malware writes into still gets caught. Warn when someone whitelists a writable download folder or `/`.

## 3. Real-time protection

Today:
- **inotify** reports `CREATE`, `CLOSE_WRITE` and `MOVED_TO`. Each new file is scanned twice, recursion into folders follows symlinks, and queue overflow (`IN_Q_OVERFLOW`) is ignored.
- **fanotify** is notify-only. It reports `FAN_MODIFY` across the whole mount, with no path filtering and no filtering of the daemon's own process, so every `write()` triggers a full rescan.
- **Monitor** handles events serially.

Rework:
1. **fanotify as the primary backend**, as the system daemon:
   - Use `FAN_CLASS_CONTENT` and mark the filesystems or mounts that hold the configured roots.
   - Request `FAN_CLOSE_WRITE` (scan after write) and `FAN_OPEN_EXEC_PERM`, which is raised for `execve`/`execveat`, to block a malicious binary before it runs. Optionally add `FAN_OPEN_PERM` for full on-open prevention.
   - Answer with `FAN_ALLOW` or `FAN_DENY`. Since 6.13, a group created with `FAN_CLASS_PRE_CONTENT` can choose the errno with `FAN_DENY_ERRNO`. Closing the fanotify fd allows every pending event.
   - Use the **ignore mask as a kernel verdict cache**: after a clean verdict, set `FAN_MARK_IGNORED_MASK` on the inode. The kernel clears it on modify unless `FAN_MARK_IGNORED_SURV_MODIFY` is set, which gives "rescan only when the file changed" for free.
   - Filter by root paths in userspace, and ignore events where `pid == getpid()`.
   - Handle `FAN_Q_OVERFLOW` by scheduling a rescan of the roots. Each permission event is answered within a time budget, falling back to allow on timeout (configurable, and recorded in the audit log).
   - Note that `FAN_REPORT_FID` groups get `FAN_NOFD`, so they cannot be used for permission responses.
   - ClamAV's on-access tool `clamonacc` makes the same split: a small privileged fanotify front end hands fds to a scanner. One critique of it is worth avoiding: no verdict cache, and file identity by path.
2. **inotify fallback** for unprivileged use. Check the entry type with `file_type()`, which does not follow symlinks. Drop `CREATE` for regular files. Handle `IN_Q_OVERFLOW` and `IN_IGNORED`. Coalesce repeated events for the same path over about 250 ms.
3. **Bounded concurrency.** A worker pool, for example a `Semaphore` of N `spawn_blocking` jobs. Ransomware observation runs on the event thread using the event's own timestamp, not the time it is processed.
4. **Later: BPF LSM.** Attach to `lsm/bprm_check_security` and `lsm/file_open`, deny with `-EPERM`, and keep the deny cache in a BPF map. Needs Linux 5.7+ with BPF LSM enabled, plus `CAP_SYS_ADMIN` and `CAP_MAC_ADMIN`.

## 4. Behavioural engine

### 4.1 Event source
Turn `aegis-ebpf` from a standalone printer into a library behind the daemon's `ebpf` feature. It would supply exec, connect and file-write events, each with process context: tgid, parent chain, exe, cmdline and cgroup. This is the model Falco, Tetragon and Tracee use. Falco matches the kernel event stream against YAML rules in userspace, while Tetragon enforces inside the kernel. Start Falco-style with a small YAML rule DSL, for example:
- a shell spawned by a network service;
- exec from `/tmp`, `/dev/shm` or a `memfd`;
- `curl`/`wget` piped into an interpreter;
- writes to `authorized_keys`, cron or systemd unit paths.

### 4.2 Ransomware guard v2
Today all processes share one window. The guard kills whichever PID appears most often, alerts on absolute entropy, and counts the daemon's own writes. Rework it so that:
- Windows are **per process (tgid)**, not global.
- The signal is a **change** in entropy or file type, such as a low-entropy document overwritten with random bytes, plus extension renames. Known compressed formats are excluded by magic bytes. Research shows entropy alone is weak: archives score about 7.98–8.0 and entropy can be deliberately spoofed.
- **Canary or honey files** are placed in user folders. Small decoy files whose entropy visibly changes, such as PNG and RTF, give a low-false-positive tripwire.
- The response is **SIGSTOP, then decide**. Kill only on multiple signals, and never PID 1, the daemon itself, or allowlisted executables.
- **Rollback** keeps the `rollback_guard` approach, with these fixes:
  - Name snapshots by a hash of the path; `sanitize()` produces collisions.
  - Snapshot only the files touched by the suspect process.
  - Cap the snapshot space.
  - Prefer btrfs or snapper snapshots where they are available.

### 4.3 Rootkit scanner
- Fix the taint bit labels (`rootkit.rs:198`). Bit 5 is BAD_PAGE, bit 12 is out-of-tree (O) and bit 13 is unsigned (E).
- Add eBPF integrity checks: confirm that syscall-table and `/proc` `file_operations` pointers fall inside kernel text, as Tracee's `hooked_proc_fops` does.
- Enumerate loaded BPF programs and maps, since eBPF rootkits evade tools that only look at kernel modules, such as rkhunter and chkrootkit.

### 4.4 Memory scanner
Allowlist known JIT runtimes (browsers, JVM, node) by exe path. Run YARA over flagged regions through `/proc/<pid>/mem` instead of reporting the region layout alone.

### 4.5 Sandbox
- Negotiate the Landlock ABI up to v6 instead of pinning v1. Network rules arrived in **v4**; abstract-Unix-socket and signal scoping arrived in **v6**.
- **Fail closed** when Landlock is not enforced.
- Add user, PID, network and mount namespaces (bubblewrap-style).
- Change seccomp to an allowlist, or at least filter on `clone`/`clone3` namespace flags, since `unshare` alone is blocked today and `clone` gets around it.

## 5. Firewall

Today the code writes nft script text by string concatenation. A newline in a comment injects arbitrary nft commands. `block_ip` only blocks outbound traffic. Rules live in the user's `~/.config` while `apply` runs under sudo, which reads root's ruleset instead.

Rework:
- **No more script strings.** Build rules with the `nftables` crate, a typed JSON API over libnftables (MIT/Apache, 0.5.x), or with `rustables` over netlink (GPLv3, which the authors call rough).
- **Use named sets** inside the `inet aegis` table:
  - `block4` (`ipv4_addr`, `flags interval`, `auto-merge`) and `block6` (`ipv6_addr`), because a set holds a single address type.
  - Separate `timeout` sets for temporary bans. Test flag combinations on the target nft version: `dynamic` with `interval` has failed in the past.
  - Rules match `saddr` in input and `daddr` in output (and forward), so a block is truly bidirectional.
  - Updating a feed changes only the set contents and never rebuilds the ruleset.
- **The daemon owns firewall state.** It lives in `/var/lib/aegis/firewall.json`, and the CLI sends IPC requests (see §8). This removes the sudo/`$HOME` split.
- **Threat feeds.** Load Feodo Tracker and ThreatFox C2 IPs into a `feed4`/`feed6` set on a schedule, using ETag/If-Modified-Since. abuse.ch APIs need a free Auth-Key, and expired IOCs drop out of the live API after about 6 months.
- **Optional per-application outbound control** (OpenSnitch-style): match by `meta skuid` or `socket cgroupv2`, or with eBPF connect hooks. OpenSnitch moved from NFQUEUE to eBPF in 1.4 and keeps a bypass list for VPNs.

## 6. Network IDS

- **Normalize addresses.** Convert IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to IPv4 before any check. Add ULA (`fc00::/7`) and link-local (`fe80::/10`) to the private-range test (`analyze.rs:33`).
- **Attribute every socket to a process.** Map the socket inode to a PID through `/proc/*/fd`, or move to eBPF `tcp_connect` events for real-time attribution.
- **Feed DNS with real data.** Today `aegis dns` only scores names the user types in. Use `resolvectl monitor` (systemd-resolved) or AF_PACKET capture on port 53.
- **Score per parent domain over time:** unique-subdomain count, query volume and payload size, plus lexical features. Allowlist popular domains and CDNs: CDN and telemetry traffic is a known major source of false positives for tunnel detectors.
- **Narrow the suspicious-port list.** Ports 5555 and 9001 are also common development ports. Downgrade them to *info* unless the process is unexpected.

## 7. Plugins

Today the signature covers only `plugin.json`, so the code the plugin runs can be swapped freely. The entrypoint can escape the plugin folder, permissions are never enforced, and the private key is passed on the command line.

Rework:
- **Sign a targets manifest**, TUF-style: name, size and SHA-256 for every file in the plugin, plus the entrypoint.
  - At run time, check all hashes.
  - Reject symlinks, and any entrypoint that resolves outside the plugin folder.
  - Run a verified copy, so the files cannot change between verification and execution.
  - Consider minisign or Sigstore/Rekor for distribution.
- **Enforce permissions**, choosing one of two runtimes:
  - **WASM (preferred):** wasmtime with WASI. The guest gets exactly the imports it is granted, so each permission maps to one host import. Fuel or epoch interruption limits CPU time.
  - **Process:** apply Landlock, seccomp and namespaces derived from the permissions. For example, network access is denied by Landlock v4 unless the `Network` permission is granted.
- **Keys:** read the private key from a 0600 file or from stdin, never from argv.

## 8. Daemon, IPC, storage, deployment

- **One authority.** The root system daemon owns `/etc/aegis` (config), `/var/lib/aegis` (database, quarantine, firewall, feeds) and `/run/aegis` (socket). The CLI and UI become thin IPC clients, with in-process fallbacks only for read-only commands.
- **Authorization.** The socket is `0660 root:aegis`. Each request is checked with `SO_PEERCRED`: members of the `aegis` group get read and scan operations, while quarantine restore, whitelist, firewall and shutdown need uid 0 or an admin policy, possibly through polkit.
- **Reload properly.** Reload restarts the watcher and the scheduler. Status reports the monitor's real start error.
- **Quarantine:**
  - Make blobs self-describing: a versioned header holding the nonce, the original metadata and the AES-GCM AAD.
  - Mark the database record *pending* before deleting the original.
  - **Never regenerate an existing key.** Keep it in a credential store: `systemd-creds` or a TPM-sealed key.
  - Open files with `O_NOFOLLOW` and `openat` relative to the parent directory.
  - Restore with `O_CREAT|O_EXCL`, as the file's original owner, and keep the original mode.
- **SQLite:** set `busy_timeout`, and make the daemon the only writer.
- **systemd unit:**
  - Use the `StateDirectory`/`RuntimeDirectory` paths that code actually reads.
  - Grant `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_KILL` and `CAP_SYS_ADMIN` (for fanotify).
  - Replace `ProtectHome=read-only`: quarantine needs to unlink files under `/home`.
  - Re-check `MemoryDenyWriteExecute=`. It rejects `mprotect(PROT_EXEC)`, which breaks JIT runtimes, and yara-x compiles rules through wasmtime. I found no source that confirms the conflict, so test it before keeping the setting.
- **Build:**
  - Take `aegis-ebpf` out of `default-members` and put it behind a feature.
  - Give it its own CI job that installs clang, bpftool and libelf.
  - Fix the dead-field warning that `-D warnings` turns into an error.
  - Add `GPL-3.0-or-later` to `deny.toml`.
- **Updater:** one signed update channel for YARA Forge rules, hash lists and IP feeds. Content is versioned and stored in the database, and each update invalidates the verdict cache.

## 9. Cross-platform: Linux and Windows

### 9.1 How portable the code is today

| Crate | Portable? | What ties it to Linux |
|---|---|---|
| `aegis-core` | Mostly | `paths.rs` is XDG and `$HOME` only, and `ensure_dirs` uses unix permissions |
| `aegis-engine` | **Yes** | Nothing. yara-x, walkdir, regex and sha2 all build on Windows |
| `aegis-storage` | **Yes** | Nothing (bundled SQLite) |
| `aegis-quarantine` | Mostly | Owner-only permissions are applied only under `cfg(unix)`, so Windows gets no protection |
| `aegis-ipc` | No | `tokio::net::UnixStream` |
| `aegis-daemon` | No | inotify and fanotify, `signal::unix`, `sd-notify`, the Unix socket |
| `aegis-behavior` | No | `/proc`, `/sys`, Landlock, seccomp, `nix` signals |
| `aegis-firewall` / `aegis-network` | No | `nft`, `/proc/net/*` |
| `aegis-optimize` | No | pacman, journalctl, sysctl |
| `aegis-plugin` | Mostly | The runner hard-codes `PATH=/usr/bin:/bin` and executes a shell script |
| `aegis-ebpf` | No | Linux only by nature |
| `app/` (Tauri) | **Yes** | Tauri v2 runs on Windows (WebView2). The bridge inherits the crate issues above |

The detection core already builds on Windows. Most of the porting work is in the platform edges.

### 9.2 Target architecture: a platform layer

Add an **`aegis-platform`** crate that defines traits, with `linux/` and `windows/` modules chosen by `cfg(target_os)`. Every crate above it becomes OS-agnostic:

```rust
pub trait FileEventSource  { fn start(&self, roots: &[PathBuf]) -> Result<EventStream>; fn can_block(&self) -> bool; }
pub trait AccessGate       { fn respond(&self, ev: &AccessEvent, verdict: Verdict) -> Result<()>; } // fanotify PERM / minifilter
pub trait ProcessEventSource { fn start(&self) -> Result<ProcStream>; }      // eBPF / ETW
pub trait ProcessControl   { fn suspend(&self, pid: u32) -> Result<()>; fn kill(&self, pid: u32) -> Result<()>; fn image_path(&self, pid: u32) -> Option<PathBuf>; }
pub trait MemoryInspector  { fn regions(&self, pid: u32) -> Result<Vec<MapRegion>>; fn read(&self, pid: u32, r: &MapRegion) -> Result<Vec<u8>>; }
pub trait NetFilter        { fn apply(&self, sets: &BlockSets) -> Result<()>; fn connections(&self) -> Vec<Connection>; }
pub trait Sandbox          { fn spawn_confined(&self, cmd: &Command, policy: &SandboxPolicy) -> Result<Child>; }
pub trait SecretStore      { fn load_or_create_vault_key(&self) -> Result<Zeroizing<[u8; 32]>>; }
pub trait ServiceHost      { fn run(&self, main: impl FnOnce(Shutdown)) -> Result<()>; } // systemd / Windows SCM
pub trait IpcTransport     { /* UDS + SO_PEERCRED  |  named pipe + ACL + client token */ }
pub trait SystemPaths      { fn config(&self) -> PathBuf; fn data(&self) -> PathBuf; fn runtime(&self) -> PathBuf; }
pub trait IntegrityChecks  { fn scan(&self) -> Vec<Detection>; }              // rootkit (Linux) / tamper and persistence (Windows)
```

Domain types such as `MapRegion`, `Connection`, `AccessEvent` and `Verdict` move into `aegis-core`. The daemon, CLI and UI code against these traits only.

### 9.3 How each subsystem maps to Windows

| Subsystem | Linux (from the sections above) | Windows |
|---|---|---|
| **Paths** | `/etc/aegis`, `/var/lib/aegis`, `/run/aegis` | `%ProgramData%\Aegis\{config,data,quarantine}`, with per-user settings under `%LOCALAPPDATA%\Aegis`. Folders ACL'd to SYSTEM and Administrators (`windows` crate security APIs) |
| **Service** | systemd `Type=notify` | A Windows service through the `windows-service` crate (SCM start, stop and shutdown handlers), running as LocalSystem |
| **IPC** | UDS, `0660 root:aegis`, `SO_PEERCRED` | A named pipe (`tokio::net::windows::named_pipe`) with a DACL that admits Administrators and an `Aegis Users` group. Each request is authorized with `GetNamedPipeClientProcessId` and the client's impersonation token. Only admins get mutating operations |
| **Scan engines** | Unchanged | Unchanged (yara-x, hash, ClamAV through `clamd` over TCP or a pipe, since ClamAV has Windows builds). Heuristics gain a **PE path**: `goblin` PE parsing for section entropy, writable-and-executable sections, odd entry points, import-table anomalies, and overlay size. Use **Authenticode** (`WinVerifyTrust`) as a strong negative signal: a valid signature from a trusted publisher lowers the score but never whitelists on its own |
| **Real-time, tier 1 (no driver)** | inotify | `ReadDirectoryChangesW`/`ReadDirectoryChangesExW` on the configured roots. Notification only, like inotify. On buffer overflow the call succeeds with zero bytes, or `ERROR_NOTIFY_ENUM_DIR` is returned, so the code must **re-enumerate** the folder (same as `IN_Q_OVERFLOW`). Over SMB shares the buffer is limited to 64 KB. Optionally read the NTFS USN change journal for volume-wide catch-up after downtime |
| **Real-time, tier 2 (prevention)** | fanotify `*_PERM` | A **file-system minifilter driver**. Its pre-`IRP_MJ_CREATE` and post-cleanup callbacks send messages over `FltCreateCommunicationPort` to the service. The service connects with `FilterConnectCommunicationPort` and answers through `FilterGetMessage`/`FilterReplyMessage`. Honour `FILE_COMPLETE_IF_OPLOCKED`: never block such a create; return `STATUS_SHARING_VIOLATION` if it can't be honoured. Keep the verdict cache in the driver (file ID plus USN), which mirrors the fanotify ignore mask |
| **AMSI** | — | An **AMSI provider**: an in-process COM DLL implementing `IAntimalwareProvider`, registered under `HKLM\SOFTWARE\Microsoft\AMSI\Providers`. It forwards PowerShell, VBScript, JScript and Office macro buffers to the service's YARA engine. Load dependencies by full path (a requirement since 1709). Registration alone doesn't guarantee calls (there is a known sample issue), so it needs an end-to-end test |
| **Process telemetry** | eBPF exec, connect and write events | ETW, through the `ferrisetw` crate or raw `windows` crate calls: **Microsoft-Windows-Kernel-Process** (ProcessStart and ImageLoad, events 1 and 5; needs SYSTEM or admin), Kernel-File, Kernel-Network and DNS-Client. **Threat-Intelligence ETW** requires Antimalware-PPL, which in turn requires an **ELAM** driver and Microsoft's vetting, so it is out of scope until Aegis joins the Microsoft Virus Initiative. Behaviour rules (§4.1) stay identical because they run on the normalized event schema |
| **Ransomware guard** | fanotify, canaries, per-process windows | ETW file-write events plus canary files in Documents, Desktop and Pictures. Per-process windows as on Linux. Add a Windows-specific high-confidence signal: **shadow-copy deletion** (`vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, `bcdedit /set recoveryenabled no`), seen through process-creation command lines. Respond with `NtSuspendProcess` or suspending all threads, then `TerminateProcess`. Roll back by taking a **VSS snapshot** when the guard arms; the minifilter tier can later do copy-on-first-write |
| **Memory scanner** | `/proc/<pid>/maps` | `VirtualQueryEx` (needs `SeDebugPrivilege`) to find `PAGE_EXECUTE_READWRITE` regions, private executable `MEM_PRIVATE` regions (shellcode or injection), and image regions whose bytes differ from the file on disk (process hollowing). `ReadProcessMemory` feeds flagged regions to YARA |
| **Integrity ("rootkit")** | `/proc`⇄`/sys` cross-view | User mode can't check kernel hooks reliably. Check things that are visible instead: <ul><li>**persistence**: Run keys, services, scheduled tasks, WMI event subscriptions, IFEO debuggers, AppInit_DLLs</li><li>**unsigned drivers** loaded</li><li>**Defender tampering**: exclusions and disabled real-time protection</li><li>the **AMSI providers** list</li></ul> |
| **Firewall** | nftables named sets | **Windows Filtering Platform** in user mode: `FwpmEngineOpen0`, a dedicated Aegis provider and sublayer, and `FwpmFilterAdd0` with `FWP_ACTION_BLOCK` at `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` (outbound) and `ALE_AUTH_RECV_ACCEPT_V4/V6` (inbound). Filters can be persistent or boot-time. Plain block filters need **no kernel driver**; only callouts (deep inspection) do. Add a per-application allow/deny condition with `FWPM_CONDITION_ALE_APP_ID`, which gives OpenSnitch-style control natively. Run filter additions inside a read-write transaction to stay atomic |
| **Connections / IDS** | `/proc/net/*` | `GetExtendedTcpTable`/`GetExtendedUdpTable` (IPv4 and IPv6, owning PID included). Use the DNS-Client ETW provider for live DNS-tunnel scoring (§6) |
| **Sandbox** | Landlock, seccomp, namespaces | An **AppContainer**, or LPAC for stricter isolation, plus a **job object** (memory, CPU, UI and child-process limits) plus a restricted token. Create the child suspended, attach the job, then resume, so it is confined from its first instruction. Network access is granted only by the `internetClient` capability, which maps cleanly onto the plugin `Network` permission |
| **Quarantine key** | `systemd-creds` / TPM | DPAPI machine scope (`CryptProtectData` with `CRYPTPROTECT_LOCAL_MACHINE`), or CNG/TPM through the Platform Crypto Provider. Quarantined files stay AES-GCM blobs. Restore writes with `CREATE_NEW` and reapplies the original owner and DACL |
| **Plugins** | WASM preferred | Identical. WASM is the main reason to prefer it, since the same plugin then runs on both OSes. The process runner falls back to the AppContainer sandbox |
| **Optimizer** | pacman, journal, sysctl | Either a separate Windows module (temp folders, Delivery Optimization cache, `DISM /StartComponentCleanup`) or Linux-only. It is not core AV, so it is lower priority |
| **eBPF tracer** | `aegis-ebpf` | Not ported. ETW fills the role |

### 9.4 Windows-specific constraints and decisions

- **Driver signing is gating work.** A minifilter has to be Microsoft-signed. That means a Partner Center (Hardware Dev Center) account, an **EV certificate** registered to it, and **attestation signing**, which covers Windows 10 and later. Rust drivers are possible through `windows-drivers-rs`, but Microsoft labels it early stage and not production-ready. Write the minifilter in C/C++ from the WDK `scanner` sample and keep it as small as possible, holding only policy and cache. All scanning stays in the Rust service. Until the driver ships, Windows runs **tier 1** (detect and quarantine after write), the same as Linux with inotify.
- **Windows Security Center and Defender.** Registering as the system antivirus with WSC is an undocumented, NDA-gated API, and in practice it requires an **ELAM** driver and **Microsoft Virus Initiative** membership. Until then, Aegis runs **alongside Microsoft Defender**: Defender stays active, and Aegis must not fight it. Exclude Aegis's quarantine and data folders from Defender, document the overlap, and never try to switch Defender off. Defender's passive mode needs Defender for Endpoint onboarding, so it isn't available to us anyway.
- **Self-protection.** Without PPL, an administrator can kill the service. That is acceptable at first. Watch for tampering instead: service stopped, Aegis files altered, Defender exclusions that point at Aegis.
- **File locking.** A file that is open in another process can't be quarantined. Retry, then fall back to `MoveFileEx(..., MOVEFILE_DELAY_UNTIL_REBOOT)` and record the quarantine as *pending reboot*.
- **Paths.** Normalize long paths (the `\\?\` prefix), handle case-insensitive comparison in the whitelist trie, and treat 8.3 short names and NTFS alternate data streams (`file.txt:stream`) as scan targets.
- **Install.** Ship an MSI or MSIX built with WiX, or the Tauri bundler for the UI. The installer registers the service, the AMSI provider and the WFP provider and sublayer, and removes them cleanly on uninstall, so no WFP filters are left behind.

### 9.5 Build and CI
- **Gate dependencies by platform** in each `Cargo.toml`: `[target.'cfg(target_os = "linux")'.dependencies]` for nix, inotify, landlock, seccompiler, sd-notify and libbpf; `[target.'cfg(windows)'.dependencies]` for `windows`, `windows-service` and `ferrisetw`.
- **CI matrix**: `ubuntu-latest` and `windows-latest` for fmt, clippy, test and release. Linux-only and Windows-only tests are marked with `#[cfg]`. The minifilter gets its own job using an EWDK on `windows-latest`.
- **Tauri** builds `.deb` and AppImage on Linux and MSI/NSIS on Windows. Shared React code stays unchanged; pages hide what the platform can't do (for example "eBPF trace" on Windows), based on a `capabilities()` command.

## 10. Phased roadmap

Phases 0–4 are the Linux track. **W0–W3** are the Windows track. W0 can start as soon as phase 0 lands.

| Phase | Scope | Outcome |
|---|---|---|
| **0: Safety and correctness** | Quarantine data-loss and symlink fixes; plugin manifest hashing; nft JSON API; working systemd unit; build/CI fixes; inotify symlink loop; real reload and status | Nothing in the current design can lose data or be abused |
| **1: Detection quality** | Single mmap read with the whole file scanned; verdict cache; per-thread YARA; YARA Forge and updater; clamd engine; goblin heuristics; confidence scoring | Real signature coverage, fewer false positives, faster rescans |
| **2: Prevention** | fanotify `FAN_OPEN_EXEC_PERM`/`FAN_OPEN_PERM`, ignore-mask cache, overflow rescans, worker pool | Malicious binaries are blocked before they run |
| **3: Behaviour** | eBPF event pipeline with process tree; YAML behaviour rules; ransomware v2 (per process, canaries, SIGSTOP); eBPF rootkit checks; sandbox v2 | Signature-less detection with low false positives |
| **4: Network and plugins** | nft sets with feeds; bidirectional blocks; socket→process attribution; live DNS scoring; WASM plugin runtime; optional per-app firewall | Network layer and extensibility at production quality |
| **W0: Platform layer** | `aegis-platform` traits; move Linux code behind them; platform-gated dependencies; Windows CI job building engine, storage, quarantine and CLI scan | `aegis scan` and the Tauri UI run on Windows (on-demand scanning) |
| **W1: Windows service (no driver)** | Windows service, named-pipe IPC with ACLs, `%ProgramData%` paths, DPAPI vault key, `ReadDirectoryChangesW` real-time, PE heuristics and Authenticode, WFP block filters and connection table, persistence and integrity checks, MSI installer | Feature parity with the Linux inotify tier, running alongside Defender |
| **W2: Behaviour and AMSI** | ETW process, file, network and DNS telemetry feeding the shared rule engine; ransomware v2 with shadow-copy signals and VSS rollback; memory scanner; AppContainer sandbox; AMSI provider | Script and fileless coverage, plus behavioural detection |
| **W3: Prevention driver** | Partner Center account and EV certificate; minifilter from the WDK scanner sample with an in-driver verdict cache; attestation signing; *(optional, long term)* ELAM and MVI for WSC registration and Threat-Intelligence ETW | Block-before-open on Windows, matching Linux phase 2 |

---

## Sources

- ClamAV On-Access docs: https://docs.clamav.net/manual/OnAccess.html ; clamonacc man page: https://manpages.ubuntu.com/manpages/jammy/man8/clamonacc.8.html ; ClamAV blog (clamonacc split): https://blog.clamav.net/2019/09/
- ferronacc (critique of clamonacc caching): https://awesome.ecosyste.ms/projects/github.com%2Fnning%2Fferronacc
- fanotify(7): https://man7.org/linux/man-pages/man7/fanotify.7.html ; fanotify_mark(2): https://manpages.karlosoft.com/5.02/man2/FANOTIFY_MARK/ ; FAN_OPEN_EXEC tests: https://lists.linux.it/pipermail/ltp/2019-January/010604.html
- yara-x crate: https://www.lib.rs/crates/yara-x ; YARA Forge: https://cyb3rops.medium.com/introducing-yara-forge-a77cbb77dcab , https://thor-util-manual.nextron-systems.com/en/latest/usage/yara-forge.html , https://www.nextron-systems.com/2025/04/30/yara-forge-rule-sets-now-available-in-thor-cloud-and-thor-cloud-lite/
- abuse.ch feeds: https://docs.spamhaus.com/real-time-feeds/docs/source/01-intro/what-is-the-real-time-feed.html , https://echo.archivarix.net/ru/archive/threatfox
- clamd(8): https://man.archlinux.org/man/clamd.8.en.txt ; ClamAV 0.105 notes: https://blog.clamav.net/2022/05/clamav-01050-01043-01036-released.html ; go-clamav: https://pkg.go.dev/github.com/PyYoshi/go-clamav
- systemd MemoryDenyWriteExecute: https://linux-audit.com/systemd/settings/units/memorydenywriteexecute/ ; MDWE kernel thread: https://lkml.iu.edu/2204.2/05883.html
- BPF LSM: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/ , https://howtech.substack.com/p/enforcing-security-policy-at-the , https://kernsec.org/pipermail/linux-security-module-archive/2020-January/018050.html
- Falco / Tetragon / Tracee: https://www.decryptiondigest.com/blog/ebpf-runtime-security-tools-falco-tetragon , https://devopsboys.com/blog/falco-vs-tetragon-runtime-security-comparison-2026 , https://arxiv.org/pdf/2609.13930
- Ransomware detection: https://arxiv.org/pdf/2306.12008 , https://researchers.mq.edu.au/en/publications/the-inadequacy-of-entropy-based-ransomware-detection/ , https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/10990675 , https://joiv.org/index.php/joiv/article/download/1265/569
- Rootkits: https://www.aquasec.com/blog/linux-syscall-hooking-using-tracee/ , https://github.com/pathtofile/bpf-hookdetect , https://www.virusbulletin.com/uploads/pdf/conference/vb2025/papers/Unmasking-the-unseen-a-deep-dive-into-modern-Linux-rootkits-and-their-detection.pdf
- Landlock ABI v4/v6: https://lkml.iu.edu/hypermail/linux/kernel/2409.1/08657.html , https://kernsec.org/pipermail/linux-security-module-archive/2025-January/048710.html , https://docs.curiosity.ai/landlock-sharp/guides/scopes
- nftables sets: https://wiki.nftables.org/wiki-nftables/index.php/Sets , https://lists.netfilter.org/pipermail/netfilter-buglog/2023-October/005560.html ; Rust crates: https://lib.rs/crates/nftables , https://docs.rs/rustables
- OpenSnitch: https://linuxuprising.com/2021/09/opensnitch-application-firewall-140.html , https://techearl.com/opensnitch-application-firewall-linux
- DNS tunnel/DGA: https://www.elastic.co/blog/plight-end-tunnel , https://arxiv.org/pdf/2006.06122
- TUF / Sigstore: https://blog.sigstore.dev/sigstore-bring-your-own-stuf-with-tuf-40febfd2badd/ , https://docs.sigstore.dev/rekor/sign-upload
- Wasmtime plugin sandboxing: https://agentpatterns.ai/security/wasm-sandbox-agent-code-execution/ , https://www.buildmvpfast.com/blog/webassembly-server-plugins-wasi-component-model-2026

**Windows**
- Minifilter communication ports: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcreatecommunicationport , https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filterconnectcommunicationport ; IRP_MJ_CREATE and oplock rules for scanners: https://learn.microsoft.com/en-sg/WINDOWS-HARDWARE/DRIVERS/ifs/irp-mj-create
- Driver signing: https://learn.microsoft.com/pl-pl/windows-hardware/drivers/dashboard/code-signing-reqs , https://entrust.com/knowledgebase/ssl/windows-kernel-mode-signing-changes-and-customer-requirements-for-kernel-signing , https://www.ssl.com/?p=34158
- Rust drivers: https://docs.rs/wdk , https://itdaily.com/news/workplace/rust-for-windows-drivers/ , https://heise.de/-10634235
- AMSI: https://learn.microsoft.com/en-us/windows/desktop/amsi/dev-audience , https://blogs.blackberry.com/en/2018/04/how-to-implement-anti-malware-scanning-interface-provider , https://github.com/microsoft/windows-classic-samples/issues/40
- WSC / ELAM / MVI: https://en.wikipedia.org/wiki/Security_and_Maintenance , https://cybersecuritynews.com/defendnot-disables-windows-defender , https://www.wilderssecurity.com/goto/post?id=2949926
- Defender coexistence: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows , https://www.preludesecurity.com/blog/microsoft-defender-passive-mode
- ETW: https://docs.velociraptor.app/artifact_references/pages/windows.etw.kernelprocess , https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/etw-event-tracing-for-windows-101 , https://www.originhq.com/research/securitytrace-etw-ppl
- ReadDirectoryChangesW: https://learn.microsoft.com/nl-nl/windows/win32/api/winbase/nf-winbase-readdirectorychangesw , https://msdn.microsoft.com/en-us/library/Mt843499.aspx
- WFP: https://learn.microsoft.com/en-us/windows/win32/api/Fwpmu/nf-fwpmu-fwpmfilteradd0 , https://scorpiosoftware.net/2022/12/25/introduction-to-the-windows-filtering-platform/ , https://sandboxie-plus.com/?p=2497
- AppContainer / LPAC / job objects: https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer , https://devblogs.microsoft.com/oldnewthing/20220502-00/?p=106550 , https://chromium.googlesource.com/git/chromium/+/trunk/sandbox/win/src/sandbox_policy.h , https://www.originhq.com/research/mxc-execution-containers-internals
