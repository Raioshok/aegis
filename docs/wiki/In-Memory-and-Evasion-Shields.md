# In-Memory Evasion Shields & Process Lineage DAG

Aegis incorporates state-of-the-art defenses against modern 2024–2026 evasion techniques, including sleep obfuscation, module stomping, unbacked thread execution, and lineage spoofing.

---

## 1. Module Stomping Diffing Engine (`crates/aegis-behavior`)

**Technique (T1055.012)**: Malware loads a legitimately signed Windows DLL into a target process, marks its `.text` section as writable, and overwrites (stomps) the clean instructions with malicious shellcode to evade unbacked memory scanners.

### How Aegis Detects It
1. Uses `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)` to enumerate all mapped `MEM_IMAGE` DLL modules.
2. Reads the original PE file from disk (`C:\Windows\System32\<module>.dll`) and parses the `.text` section virtual bounds.
3. Computes the SHA-256 digest of the on-disk `.text` section bytes.
4. Reads the live in-memory `.text` section via `ReadProcessMemory`.
5. Diffs the hashes. If the in-memory hash diverges from the signed on-disk image, Aegis flags the module as stomped and alerts the EDR pipeline:
   ```text
   [Alert] ModuleStomping: DLL 'amsi.dll' in PID 4820 has diverged from on-disk signed image.
   ```

---

## 2. FunctionPeekaboo TEB Hunter (MDSec 2024–2025)

**Technique**: To evade memory scanners that inspect call stacks during sleep (`WaitForSingleObject`, `SleepEx`), modern loaders use per-function sleep masking. The loader hooks the Thread Environment Block (TEB) to swap protection rights (`PAGE_NOACCESS`) during sleep and restore them on wake.

### How Aegis Detects It
1. Resolves thread TEB addresses using native NT API `NtQueryInformationThread(ThreadBasicInformation)`.
2. Inspects the undocumented `TEB.UserReserved` array (`UserReserved[0..4]`, offset `gs:[0x0E8]`).
3. Flags status constant `0x80000001` or anomalous `VirtualProtect` pointer tables stored inside thread-local structures.

---

## 3. Early Cascade Injection (Outflank 2024)

**Technique**: Malware spawns a trusted target process (e.g. `werfault.exe`, `conhost.exe`) in a suspended state. Before EDR DLLs or user-mode hooks are initialized, the loader hijacks the Application Compatibility (Shim) engine structures (`apphelp.dll`, `.sdb` indexes) to achieve code execution before main entry.

### How Aegis Detects It
1. Intercepts process creation events via kernel callbacks / ETW.
2. Detects processes created with `CREATE_SUSPENDED` flag.
3. Audits cross-process memory allocations targeting the initial thread's loader data (`LdrpInitializeProcess`) or Shim engine data structures before the entry point runs.

---

## 4. Process Execution DAG & Lineage Anomaly Engine (`dag.rs`)

Aegis constructs an in-memory directed acyclic graph (DAG) representing the complete process tree hierarchy across the endpoint:

```text
explorer.exe (PID 1420)
    │
    ├── Cursor.exe [AI Agent: Cursor IDE]
    │       │
    │       └── cursor-agent (PID 8812) ──► cargo build (Risk Score: 12 · Clean)
    │
    └── winword.exe (PID 9104) [Document Reader]
            │
            └── powershell.exe (PID 9452) [LOLBin Spawn]
                    │
                    └── Invoke-Expression (T1059.001 · Command Entropy 7.82 · Risk Score: 95 · CRITICAL)
```

### Shannon Command Entropy
* Malicious droppers, obfuscated batch scripts, and base64-encoded PowerShell payloads display unusually high entropy.
* Aegis calculates the Shannon entropy $H(X)$ of process command lines:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
* Command lines exceeding entropy thresholds ($H > 6.8$) with LOLBin parentage trigger immediate lineage alerts.

### AI Agent Visibility
* Identifies coding agent tool execution environments: **Cursor**, **Claude Code**, **Copilot Agent**, **Windsurf**, **Aider**, **Devins**.
* Differentiates legitimate developer agent tool calls from unauthorized process injection and system tampering (`Agent.SecurityTampering`).
