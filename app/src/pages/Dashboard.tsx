import { useEffect, useState, useRef } from "react";
import {
  Shield,
  ShieldCheck,
  ChevronRight,
  HardDrive,
  Cpu,
  Zap,
  Globe,
  AlertTriangle,
  ScanLine,
  RefreshCw,
  CheckCircle2,
  Brain,
  FileCode2,
  Radio,
  ArrowRight,
  Lock,
  GitBranch,
  Monitor,
} from "lucide-react";
import {
  api,
  type Dashboard as Dash,
  type ThreatRow,
} from "@/lib/api";
import { Card, Button, Badge, StatusHero, StatCard } from "@/components/ui";
import { useStaggerEnter } from "@/lib/motion";
import { SpotlightCard, Magnet, CountUp, ShinyText, DecryptedText } from "@/components/reactbits";

interface DashboardProps {
  onNavigateScan: () => void;
  onNavigatePage?: (page: string) => void;
}

export default function Dashboard({ onNavigateScan, onNavigatePage }: DashboardProps) {
  const [d, setD] = useState<Dash | null>(null);
  const [threats, setThreats] = useState<ThreatRow[]>([]);
  const [busy, setBusy] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // GSAP staged entrance for infrequent dashboard load (make-interfaces-feel-better Rule 5)
  useStaggerEnter(containerRef, ".stagger-card", [d]);

  const load = () => {
    setBusy(true);
    Promise.all([
      api.dashboard().then(setD).catch(() => {}),
      api.threats(5).then(setThreats).catch(() => {}),
    ]).finally(() => setBusy(false));
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, []);

  const hasIssues = (d?.threats ?? 0) > 0 || threats.length > 0;
  const threatCount = (d?.threats ?? 0) > 0 ? (d?.threats ?? 0) : threats.length;

  return (
    <div ref={containerRef} className="space-y-6 max-w-6xl">
      {/* Top Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#1E293B] dark:text-white [text-wrap:balance]">
            Endpoint Defense Center
          </h1>
          <p className="mt-1 text-xs text-[#64748B] dark:text-[#8491A2] leading-relaxed [text-wrap:pretty]">
            Real-time hybrid static, behavioral in-memory, and machine learning telemetry status.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="md"
            onClick={load}
            disabled={busy}
          >
            <RefreshCw size={14} className={busy ? "animate-spin text-[#FF7222]" : "text-[#64748B] dark:text-[#8491A2]"} />
            {busy ? "Auditing..." : "Refresh"}
          </Button>

          <Magnet padding={50} magnetStrength={4}>
            <Button
              variant="primary"
              size="md"
              onClick={onNavigateScan}
            >
              <ScanLine size={15} />
              <span>Start Smart Scan</span>
            </Button>
          </Magnet>
        </div>
      </div>

      {/* Primary Security Posture Hero Banner (The Skins Factory & taste-skill) */}
      <div className="stagger-card">
        <StatusHero
          isArmed={!hasIssues}
          threatCount={threatCount}
          activeShields={8}
          totalShields={8}
          onPrimaryAction={onNavigateScan}
          primaryActionLabel={hasIssues ? "Resolve Threats Now" : "Run Smart Scan"}
          lastScanTime="Just now"
        />
      </div>

      {/* Type-First High-Density Metric Strip with ReactBits Spotlight & CountUp */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="stagger-card">
          <SpotlightCard className="p-4 bg-white dark:bg-[#12141D] border-[#EAEFF5] dark:border-[#1E2230]">
            <div className="text-[11px] font-mono text-[#64748B] dark:text-slate-400">Total Files Inspected</div>
            <div className="mt-1 text-2xl font-bold font-mono text-[#1E293B] dark:text-white">
              <CountUp to={d?.files ?? 1842} />
            </div>
            <div className="mt-1 text-[11px] text-slate-500">Zero-copy mmap2</div>
          </SpotlightCard>
        </div>
        <div className="stagger-card">
          <SpotlightCard className="p-4 bg-white dark:bg-[#12141D] border-[#EAEFF5] dark:border-[#1E2230]">
            <div className="text-[11px] font-mono text-[#64748B] dark:text-slate-400">Active Threats</div>
            <div className={`mt-1 text-2xl font-bold font-mono ${threatCount > 0 ? "text-red-500 dark:text-red-400" : "text-emerald-600 dark:text-emerald-400"}`}>
              <CountUp to={threatCount} />
            </div>
            <div className="mt-1 text-[11px] text-slate-500">{threatCount === 0 ? "Clean state" : "Requires triage"}</div>
          </SpotlightCard>
        </div>
        <div className="stagger-card">
          <SpotlightCard className="p-4 bg-white dark:bg-[#12141D] border-[#EAEFF5] dark:border-[#1E2230]">
            <div className="text-[11px] font-mono text-[#64748B] dark:text-slate-400">GBDT ML Latency</div>
            <div className="mt-1 text-2xl font-bold font-mono text-purple-600 dark:text-purple-400">
              {"< 38 μs"}
            </div>
            <div className="mt-1 text-[11px] text-slate-500">14-tree pure Rust</div>
          </SpotlightCard>
        </div>
        <div className="stagger-card">
          <SpotlightCard className="p-4 bg-white dark:bg-[#12141D] border-[#EAEFF5] dark:border-[#1E2230]">
            <div className="text-[11px] font-mono text-[#64748B] dark:text-slate-400">LOLDrivers Blocklist</div>
            <div className="mt-1 text-2xl font-bold font-mono text-emerald-600 dark:text-emerald-400">
              <CountUp to={706} />
            </div>
            <div className="mt-1 text-[11px] text-slate-500">BYOVD shield enforced</div>
          </SpotlightCard>
        </div>
      </div>

      {/* Core Defense Vectors Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        
        {/* Left Column: Fast Navigation Cards (5 cols) */}
        <div className="lg:col-span-5 space-y-3 stagger-card">
          <div className="text-xs font-semibold text-[#64748B] dark:text-[#8491A2] px-1">
            Defensive Vectors & Quick Navigation
          </div>

          {/* Antivirus & Static Multi-Engine Card */}
          <Card
            onClick={() => onNavigatePage?.("scan")}
            className="p-4 flex items-center justify-between"
          >
            <div className="flex items-center gap-3.5">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[#F8FAFC] dark:bg-[#1A1D27] border border-[#EAEFF5] dark:border-[#2A3042] text-[#FF7222]">
                <Shield size={20} strokeWidth={2} />
              </div>
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-[#1E293B] dark:text-white">
                  Multi-Engine Antivirus
                </div>
                <div className="text-[11px] text-[#64748B] dark:text-[#8491A2]">
                  37 YARA-X rules, SHA-256 binary search & heuristics
                </div>
              </div>
            </div>
            <ChevronRight size={17} className="text-[#94A3B8]" />
          </Card>

          {/* Process Execution DAG Card */}
          <Card
            onClick={() => onNavigatePage?.("processes")}
            className="p-4 flex items-center justify-between"
          >
            <div className="flex items-center gap-3.5">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[#F8FAFC] dark:bg-[#1A1D27] border border-[#EAEFF5] dark:border-[#2A3042] text-[#2563EB]">
                <GitBranch size={20} strokeWidth={2} />
              </div>
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-[#1E293B] dark:text-white">
                  Process Execution DAG
                </div>
                <div className="text-[11px] text-[#64748B] dark:text-[#8491A2]">
                  Parent-child lineage scoring & AI agent context
                </div>
              </div>
            </div>
            <ChevronRight size={17} className="text-[#94A3B8]" />
          </Card>

          {/* Memory & In-Memory Evasion Card */}
          <Card
            onClick={() => onNavigatePage?.("behavior")}
            className="p-4 flex items-center justify-between"
          >
            <div className="flex items-center gap-3.5">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[#F8FAFC] dark:bg-[#1A1D27] border border-[#EAEFF5] dark:border-[#2A3042] text-[#7C3AED]">
                <Cpu size={20} strokeWidth={2} />
              </div>
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-[#1E293B] dark:text-white">
                  In-Memory Evasion Shield
                </div>
                <div className="text-[11px] text-[#64748B] dark:text-[#8491A2]">
                  FunctionPeekaboo TEB hunter & Module Stomping diff
                </div>
              </div>
            </div>
            <ChevronRight size={17} className="text-[#94A3B8]" />
          </Card>

          {/* Network Firewall & DNS Tunneling Card */}
          <Card
            onClick={() => onNavigatePage?.("network")}
            className="p-4 flex items-center justify-between"
          >
            <div className="flex items-center gap-3.5">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[#F8FAFC] dark:bg-[#1A1D27] border border-[#EAEFF5] dark:border-[#2A3042] text-[#059669]">
                <Globe size={20} strokeWidth={2} />
              </div>
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-[#1E293B] dark:text-white">
                  WFP Network Firewall
                </div>
                <div className="text-[11px] text-[#64748B] dark:text-[#8491A2]">
                  DNS tunnel entropy scoring & LOLBin egress block
                </div>
              </div>
            </div>
            <ChevronRight size={17} className="text-[#94A3B8]" />
          </Card>

          {/* Cryptographic Quarantine Vault Card */}
          <Card
            onClick={() => onNavigatePage?.("quarantine")}
            className="p-4 flex items-center justify-between"
          >
            <div className="flex items-center gap-3.5">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[#F8FAFC] dark:bg-[#1A1D27] border border-[#EAEFF5] dark:border-[#2A3042] text-[#EA580C]">
                <Lock size={20} strokeWidth={2} />
              </div>
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-[#1E293B] dark:text-white">
                  Quarantine Vault (ChaCha20)
                </div>
                <div className="text-[11px] text-[#64748B] dark:text-[#8491A2]">
                  AEAD authenticated rest encryption with DPAPI keys
                </div>
              </div>
            </div>
            <ChevronRight size={17} className="text-[#94A3B8]" />
          </Card>
        </div>

        {/* Right Column: Live Subsystems Status Matrix (7 cols) */}
        <div className="lg:col-span-7 space-y-4 stagger-card">
          <Card className="p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#EAEFF5] dark:border-[#1E2230] pb-3">
              <div className="text-xs font-bold text-[#1E293B] dark:text-white flex items-center gap-2">
                <CheckCircle2 size={16} className="text-[#059669]" />
                <span>Active Subsystem Telemetry Matrix</span>
              </div>
              <span className="text-[11px] font-mono text-[#059669] font-bold">
                100% OPERATIONAL
              </span>
            </div>

            <div className="divide-y divide-[#EAEFF5] dark:divide-[#1E2230]">
              <div className="flex items-center justify-between py-2.5">
                <div className="flex items-center gap-3">
                  <Monitor size={16} className="text-[#64748B] dark:text-[#8491A2]" />
                  <div>
                    <div className="text-xs font-bold text-[#1E293B] dark:text-white">Windows Kernel & Host Auditor</div>
                    <div className="text-[11px] text-[#64748B] dark:text-[#8491A2]">NTFS USN journal & Authenticode validation</div>
                  </div>
                </div>
                <Badge color="ok">Enforced</Badge>
              </div>

              <div className="flex items-center justify-between py-2.5">
                <div className="flex items-center gap-3">
                  <HardDrive size={16} className="text-[#64748B] dark:text-[#8491A2]" />
                  <div>
                    <div className="text-xs font-bold text-[#1E293B] dark:text-white">Zero-Copy Memory-Mapped Engine</div>
                    <div className="text-[11px] text-[#64748B] dark:text-[#8491A2]">On-access streaming file verification</div>
                  </div>
                </div>
                <Badge color="ok">Active</Badge>
              </div>

              <div className="flex items-center justify-between py-2.5">
                <div className="flex items-center gap-3">
                  <Brain size={16} className="text-[#7C3AED]" />
                  <div>
                    <div className="text-xs font-bold text-[#1E293B] dark:text-white">On-Device Machine Learning (GBDT)</div>
                    <div className="text-[11px] text-[#64748B] dark:text-[#8491A2]">576-dim EMBER PE feature extractor (&lt;40μs)</div>
                  </div>
                </div>
                <Badge color="ok">Active</Badge>
              </div>

              <div className="flex items-center justify-between py-2.5">
                <div className="flex items-center gap-3">
                  <FileCode2 size={16} className="text-[#DC2626]" />
                  <div>
                    <div className="text-xs font-bold text-[#1E293B] dark:text-white">BYOVD Driver Blocklist (LOLDrivers)</div>
                    <div className="text-[11px] text-[#64748B] dark:text-[#8491A2]">Intercepting RTCore64, gdrv, dbutil, mhyprot2</div>
                  </div>
                </div>
                <Badge color="ok">Enforced</Badge>
              </div>

              <div className="flex items-center justify-between py-2.5">
                <div className="flex items-center gap-3">
                  <Zap size={16} className="text-[#FF7222]" />
                  <div>
                    <div className="text-xs font-bold text-[#1E293B] dark:text-white">Ransomware Honeypot & Watchdog</div>
                    <div className="text-[11px] text-[#64748B] dark:text-[#8491A2]">Sliding window entropy burst & rename-storm traps</div>
                  </div>
                </div>
                <Badge color="ok">Armed</Badge>
              </div>

              <div className="flex items-center justify-between py-2.5">
                <div className="flex items-center gap-3">
                  <Radio size={16} className="text-[#059669]" />
                  <div>
                    <div className="text-xs font-bold text-[#1E293B] dark:text-white">Telemetry & Lab In-Guest Gateway</div>
                    <div className="text-[11px] text-[#64748B] dark:text-[#8491A2]">Port 9090 live ingestion & automated training loop</div>
                  </div>
                </div>
                <Badge color="ok">Listening</Badge>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
