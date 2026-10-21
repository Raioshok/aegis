# Desktop UI Manual & ReactBits Motion Engineering

The Aegis desktop application (`app/`) is built on **Tauri v2** with a React 18 / TypeScript frontend adhering to **anti-slop design-taste principles** (inspired by VirtualShield, Kaspersky, and Leonxlnx/taste-skill) and interactive motion primitives inspired by **[reactbits.dev](https://reactbits.dev/)**.

---

## 1. Visual Aesthetics & Design Invariants

* **Tone-Stepped Opaque Surfaces**: High-contrast, clean dark/light surfaces (`#0C0D12` background, `#10121A` sidebar, `#12141D` card background) instead of excessive, illegible blurred glass.
* **No AI Slop Tells**: Strictly no fake rainbow glows, gradient text, decorative pill badges, eyebrow micro-labels, or buzzwords.
* **Tactile Interactions**: Buttons and selectable rows feature a subtle `active:scale-[0.98]` physical depression feel.
* **Tabular Figures (`tab-nums`)**: Quantitative numbers, timestamps, percentages, and memory addresses use fixed-width figures to prevent layout jitter.

---

## 2. ReactBits Interactive Components (`components/reactbits/`)

### 1. `SpotlightCard`
Interactive card that tracks the mouse pointer, illuminating surface borders and displaying a localized radial gradient:
```tsx
<SpotlightCard
  spotlightColor="rgba(255, 114, 34, 0.12)"
  className="p-5 bg-[#12141D] border-[#1E2230]"
>
  <h3>Total Files Inspected</h3>
  <CountUp to={1842} />
</SpotlightCard>
```

### 2. `ShinyText`
High-performance linear gradient specular reflection sweep (`animate-shine`, $120^\circ$) applied to brand headers and primary protection badges:
```tsx
<ShinyText text="aegis" speed={4} />
```

### 3. `DecryptedText`
Cybernetic character matrix unscrambling animation that cycles randomized glyphs on hover or mount before settling on clean text:
```tsx
<DecryptedText text="Ransom_BlackCat_ALPHV" speed={40} maxIterations={8} />
```

### 4. `Magnet`
Physics-based magnetic button pull that attracts action buttons toward the cursor within a proximity threshold:
```tsx
<Magnet padding={50} magnetStrength={3}>
  <Button variant="primary">Start Smart Scan</Button>
</Magnet>
```

### 5. `CountUp`
Tabular figure counter utilizing an `easeOutExpo` curve to transition quantitative telemetry metrics without visual jumping:
```tsx
<CountUp to={threatCount} from={0} duration={1.2} />
```

---

## 3. Global Desktop Right-Click Context Menu

Right-clicking anywhere inside the application triggers a dark glass context menu with contextual desktop security operations:

| Context Scope | Available Quick Actions |
|---|---|
| **Global / Workspace Click** | • 🔍 **Run Smart Scan** (`Ctrl+S`)<br/>• 🛡️ **Memory Evasion Audit**<br/>• ☣️ **Open Quarantine Vault**<br/>• 📱 **Android APK Inspector**<br/>• ⚙️ **Shields & Protection Settings**<br/>• 📋 **Copy Version & Diagnostics** |
| **Scan Findings Table Row** | • ⚡ **Quarantine Threat** (Invokes backend `quarantine_file`)<br/>• 📋 **Copy File Path**<br/>• 🛡️ **Add Path to Allowlist** |
| **Quarantine Vault Row** | • 🔄 **Restore to Original Location**<br/>• 🗑️ **Permanently Purge from Vault**<br/>• 📋 **Copy SHA-256 Digest**<br/>• 📁 **Copy Original Path**<br/>• 🛡️ **Add Path to Allowlist** |
| **Process DAG Lineage Alert** | • ⚡ **Terminate Process** (by PID)<br/>• 📋 **Copy Commandline**<br/>• 📋 **Copy Parent Process Context** |

---

## 4. UI Viewport Matrix (All 12 Pages)

1. **Endpoint Defense Center (`Dashboard.tsx`)**: Security posture status, active defense subsystem status, and live telemetry metric cards.
2. **Smart Scan (`Scan.tsx`)**: Multi-target file scanner with live progress reporting (file path, files/sec rate, elapsed time) and findings table.
3. **Android Antivirus (`AndroidScanner.tsx`)**: APK archive parser inspecting Android manifests, permissions, and DEX bytecode opcode streams.
4. **Threat Events (`Threats.tsx`)**: Historical log of blocked threats with severity badges, SHA-256 hashes, and quarantine status.
5. **Process Inspector (`Processes.tsx`)**: Live process list with Authenticode signature status, memory risk score, and one-click termination.
6. **Allowlist (`Whitelist.tsx`)**: Management for whitelisted cryptographic hashes and recursive directory paths.
7. **Quarantine Vault (`Quarantine.tsx`)**: Inspects ChaCha20-Poly1305 encrypted artifacts with options to securely restore or permanently purge.
8. **Behavior Guard (`Behavior.tsx`)**: Controls for Kernel & Rootkit audit and live Process Memory inspection.
9. **Network Firewall (`Network.tsx`)**: Live socket monitor (TCP/UDP extended table), DNS-tunneling entropy scorer, and LOLBin egress blocker.
10. **Hardening & BYOVD (`Vulnerabilities.tsx`)**: System configuration auditor (UAC, SMBv1, USB AutoRun, LOLDrivers blocklist enforcement) and ransomware honeypot deployment.
11. **System Tune-Up (`Optimize.tsx`)**: Disk cleanup, privacy history scrubbing, and network optimization.
12. **Shields & Settings (`Settings.tsx`)**: Real-Time Protection switches, Gaming Mode resource throttling, and Shannon entropy packer sensitivity slider.
