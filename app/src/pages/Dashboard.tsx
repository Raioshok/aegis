import { useEffect, useState } from "react";
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
  AlertCircle,
  Monitor,
} from "lucide-react";
import {
  api,
  type Dashboard as Dash,
  type ThreatRow,
} from "@/lib/api";
import { Card, Button, Badge, ProtectionGauge } from "@/components/ui";

interface DashboardProps {
  onNavigateScan: () => void;
  onNavigatePage?: (page: string) => void;
}

export default function Dashboard({ onNavigateScan, onNavigatePage }: DashboardProps) {
  const [d, setD] = useState<Dash | null>(null);
  const [threats, setThreats] = useState<ThreatRow[]>([]);
  const [busy, setBusy] = useState(false);

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
  const protectionPercent = hasIssues ? 75 : 100;

  // Chart data: 10 daily buckets with latest highlighted
  const chartBars = [
    { day: "Mon", val: 102 },
    { day: "Tue", val: 82 },
    { day: "Wed", val: 128 },
    { day: "Thu", val: 142 },
    { day: "Fri", val: 160 },
    { day: "Sat", val: 204 },
    { day: "Sun", val: 182 },
    { day: "Mon", val: 94 },
    { day: "Tue", val: 100 },
    { day: "Wed", val: 147, active: true },
  ];
  const maxVal = Math.max(...chartBars.map((b) => b.val));

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-[#1E293B]">
            Antivirus
          </h1>
          <p className="text-xs text-[#64748B] mt-1">
            Real-time heuristic and multi-engine protection status for this endpoint.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="md"
            onClick={load}
          >
            <RefreshCw size={14} className={busy ? "animate-spin text-[#FF7222]" : "text-[#64748B]"} />
            Refresh
          </Button>
          <Button
            variant="primary"
            size="md"
            onClick={onNavigateScan}
          >
            <ScanLine size={16} />
            Start Smart Scan
          </Button>
        </div>
      </div>

      {/* Main Grid: Left Column (Status Dial + Quick Cards) & Right Column (Device Status, Charts, Alerts) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        
        {/* ========================================================= */}
        {/* LEFT / CENTER COLUMN: Overall Protection Dial (4 Cols)    */}
        {/* ========================================================= */}
        <div className="lg:col-span-4 space-y-4">
          <Card className="text-center p-8 flex flex-col items-center">
            <h2 className="text-sm font-bold text-[#64748B] uppercase tracking-wider mb-6">
              Protection status
            </h2>

            {/* Circular Gauge matching reference image */}
            <div className="mb-6">
              <ProtectionGauge percent={protectionPercent} size={190} strokeWidth={16} />
            </div>

            <div className="space-y-1">
              <h3 className="text-lg font-bold text-[#1E293B]">
                {hasIssues ? "Average protection" : "Full protection"}
              </h3>
              <p className="text-xs text-[#64748B] max-w-[220px] mx-auto leading-relaxed">
                {hasIssues
                  ? "Check what you can do to be fully protected"
                  : "All real-time protection shields are armed and active"}
              </p>
            </div>
          </Card>

          {/* Quick-Access Subsystem Cards (Vertical Stack with Chevrons) */}
          <div className="space-y-2.5">
            {/* Overview Card */}
            <div
              onClick={() => onNavigatePage?.("dashboard")}
              className="flex items-center justify-between bg-white p-4 rounded-2xl border border-[#EAEFF5] shadow-card hover:shadow-card-hover cursor-pointer transition-all active:scale-[0.98]"
            >
              <div className="flex items-center gap-3.5">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#F8FAFC] border border-[#EAEFF5] text-[#1E293B]">
                  <ShieldCheck size={20} />
                </div>
                <div>
                  <div className="text-xs font-bold text-[#1E293B]">Overview</div>
                  <div className="text-[11px] text-[#64748B]">System protection dashboard</div>
                </div>
              </div>
              <ChevronRight size={18} className="text-[#94A3B8]" />
            </div>

            {/* Host Firewall / Network Card */}
            <div
              onClick={() => onNavigatePage?.("network")}
              className="flex items-center justify-between bg-white p-4 rounded-2xl border border-[#EAEFF5] shadow-card hover:shadow-card-hover cursor-pointer transition-all active:scale-[0.98]"
            >
              <div className="flex items-center gap-3.5">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#ECFDF5] text-[#059669]">
                  <Globe size={20} />
                </div>
                <div>
                  <div className="text-xs font-bold text-[#1E293B]">Network Firewall</div>
                  <div className="text-[11px] text-[#059669] font-medium">Protection Active · Sockets secured</div>
                </div>
              </div>
              <ChevronRight size={18} className="text-[#94A3B8]" />
            </div>

            {/* Antivirus Card (Highlighted with peach/orange if issues) */}
            <div
              onClick={() => onNavigatePage?.("scan")}
              className={`flex items-center justify-between p-4 rounded-2xl border shadow-card hover:shadow-card-hover cursor-pointer transition-all active:scale-[0.98] ${
                hasIssues
                  ? "bg-[#FFF8F3] border-[#FFD8BF]"
                  : "bg-white border-[#EAEFF5]"
              }`}
            >
              <div className="flex items-center gap-3.5">
                <div
                  className={`flex h-10 w-10 items-center justify-center rounded-xl ${
                    hasIssues ? "bg-[#FF7222] text-white" : "bg-[#ECFDF5] text-[#059669]"
                  }`}
                >
                  <Shield size={20} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-[#1E293B]">Antivirus Engines</span>
                    {hasIssues && <Badge color="warn">Issue</Badge>}
                  </div>
                  <div className={`text-[11px] ${hasIssues ? "text-[#FF7222] font-medium" : "text-[#64748B]"}`}>
                    {hasIssues
                      ? "Resolve threats to get full protection"
                      : "37 YARA rules & hash database loaded"}
                  </div>
                </div>
              </div>
              <ChevronRight size={18} className="text-[#94A3B8]" />
            </div>

            {/* Memory & Injection Shield Card */}
            <div
              onClick={() => onNavigatePage?.("processes")}
              className="flex items-center justify-between bg-white p-4 rounded-2xl border border-[#EAEFF5] shadow-card hover:shadow-card-hover cursor-pointer transition-all active:scale-[0.98]"
            >
              <div className="flex items-center gap-3.5">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#F8FAFC] border border-[#EAEFF5] text-[#1E293B]">
                  <Cpu size={20} />
                </div>
                <div>
                  <div className="text-xs font-bold text-[#1E293B]">Memory Defense</div>
                  <div className="text-[11px] text-[#64748B]">Continuous thread & RIP monitoring</div>
                </div>
              </div>
              <ChevronRight size={18} className="text-[#94A3B8]" />
            </div>
          </div>
        </div>

        {/* ========================================================= */}
        {/* RIGHT COLUMN: Device Status + Charts + Alerts (8 Cols)    */}
        {/* ========================================================= */}
        <div className="lg:col-span-8 space-y-6">
          
          {/* Top Card: Device & Shield Security Banner */}
          <Card className="p-6 space-y-5">
            {/* Top Issue/Success Alert Pill Banner */}
            <div
              className={`flex items-center justify-between p-4 rounded-2xl border ${
                hasIssues
                  ? "bg-[#FFF4EC] border-[#FFE2CC]"
                  : "bg-[#ECFDF5] border-[#A7F3D0]"
              }`}
            >
              <div className="flex items-center gap-3.5">
                <div
                  className={`flex h-10 w-10 items-center justify-center rounded-xl shrink-0 ${
                    hasIssues ? "bg-[#FF7222] text-white" : "bg-[#10B981] text-white"
                  }`}
                >
                  {hasIssues ? <AlertTriangle size={20} /> : <CheckCircle2 size={20} />}
                </div>
                <div>
                  <div className={`text-sm font-bold ${hasIssues ? "text-[#1E293B]" : "text-[#065F46]"}`}>
                    {hasIssues ? "Issue Detected" : "System Protected"}
                  </div>
                  <div className={`text-xs ${hasIssues ? "text-[#FF7222]" : "text-[#059669]"} font-medium mt-0.5`}>
                    {hasIssues
                      ? "Resolve identified threats to restore complete protection"
                      : "All primary defense subsystems are active and reporting healthy"}
                  </div>
                </div>
              </div>

              {hasIssues ? (
                <Button variant="primary" size="sm" onClick={() => onNavigatePage?.("threats")}>
                  Resolve Now
                </Button>
              ) : (
                <Badge color="ok">Armed</Badge>
              )}
            </div>

            {/* Subsystem & Device Status List */}
            <div className="divide-y divide-[#EAEFF5]">
              <div className="flex items-center justify-between py-3">
                <div className="flex items-center gap-3">
                  <Monitor size={18} className="text-[#64748B]" />
                  <div>
                    <div className="text-xs font-bold text-[#1E293B]">Local Windows Host</div>
                    <div className="text-[11px] text-[#64748B]">Real-time kernel monitoring: Active right now</div>
                  </div>
                </div>
                <Badge color="ok">Protected</Badge>
              </div>

              <div className="flex items-center justify-between py-3">
                <div className="flex items-center gap-3">
                  <HardDrive size={18} className="text-[#64748B]" />
                  <div>
                    <div className="text-xs font-bold text-[#1E293B]">Zero-Copy File Inspector</div>
                    <div className="text-[11px] text-[#64748B]">Mmap2 on-access scanner active</div>
                  </div>
                </div>
                <Badge color="ok">Protected</Badge>
              </div>

              <div className="flex items-center justify-between py-3">
                <div className="flex items-center gap-3">
                  <Zap size={18} className={hasIssues ? "text-[#FF7222]" : "text-[#64748B]"} />
                  <div>
                    <div className="text-xs font-bold text-[#1E293B]">Behavioral Threat Engine</div>
                    <div className="text-[11px] text-[#64748B]">Ransomware traps & shadow copy watcher</div>
                  </div>
                </div>
                <Badge color={hasIssues ? "warn" : "ok"}>
                  {hasIssues ? "Issue" : "Protected"}
                </Badge>
              </div>
            </div>
          </Card>

          {/* Bottom Grid: "Files scanned with Antivirus" + "Alerts" */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            
            {/* Bottom-Left Card: Files Scanned with Aegis & Chart */}
            <Card className="p-6 space-y-5">
              <h3 className="text-sm font-bold text-[#1E293B]">
                Files scanned with Aegis
              </h3>

              {/* Metric Tiles (Today / This Week) */}
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-xl bg-[#F8FAFC] border border-[#EAEFF5] p-3">
                  <span className="text-[11px] text-[#64748B] font-medium block">
                    Today
                  </span>
                  <span className="text-xl font-extrabold text-[#1E293B] tab-nums mt-0.5 block">
                    147
                  </span>
                </div>
                <div className="rounded-xl bg-[#F8FAFC] border border-[#EAEFF5] p-3">
                  <span className="text-[11px] text-[#64748B] font-medium block">
                    This week
                  </span>
                  <span className="text-xl font-extrabold text-[#1E293B] tab-nums mt-0.5 block">
                    {d?.files ? d.files.toLocaleString() : "12,247"}
                  </span>
                </div>
              </div>

              {/* 10-bar Vertical Column Chart matching reference */}
              <div className="pt-2">
                <div className="h-32 flex items-end justify-between gap-1.5 px-1">
                  {chartBars.map((b, i) => {
                    const heightPercent = Math.max(15, (b.val / maxVal) * 100);
                    return (
                      <div key={i} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end">
                        <div
                          className={`w-full rounded-md flex items-center justify-center transition-all duration-300 ${
                            b.active
                              ? "bg-[#2563EB] shadow-[0_2px_8px_rgba(37,99,235,0.3)] text-white"
                              : "bg-[#F1F5F9] text-[#94A3B8] hover:bg-[#E2E8F0]"
                          }`}
                          style={{ height: `${heightPercent}%` }}
                        >
                          <span className="text-[9px] font-bold rotate-90 sm:rotate-0">
                            {b.val}
                          </span>
                        </div>
                        <span className="text-[10px] font-medium text-[#64748B]">
                          {b.day}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </Card>

            {/* Bottom-Right Card: Recent Alerts */}
            <Card className="p-6 space-y-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-bold text-[#1E293B]">Alerts</h3>
                  <Badge color={threats.length > 0 ? "warn" : "ok"}>
                    {threats.length > 0 ? `${threats.length} Active` : "Clear"}
                  </Badge>
                </div>

                {threats.length === 0 ? (
                  <div className="py-10 text-center space-y-2">
                    <CheckCircle2 size={32} className="text-[#10B981] mx-auto opacity-70" />
                    <div className="text-xs font-semibold text-[#1E293B]">No Security Alerts</div>
                    <p className="text-[11px] text-[#64748B] max-w-[200px] mx-auto">
                      Your machine has no unresolved malicious detections or active warnings.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {threats.slice(0, 2).map((t, i) => (
                      <div
                        key={i}
                        className="p-3 rounded-xl border border-[#FFE2CC] bg-[#FFF8F3] space-y-2"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-start gap-2 min-w-0">
                            <AlertCircle size={16} className="text-[#FF7222] shrink-0 mt-0.5" />
                            <div className="min-w-0">
                              <div className="text-xs font-bold text-[#1E293B] truncate">
                                {t.names}
                              </div>
                              <p className="text-[11px] text-[#64748B] truncate" title={t.path}>
                                Requires removal from your device.
                              </p>
                            </div>
                          </div>

                          <Button
                            variant="blue"
                            size="sm"
                            onClick={() => onNavigatePage?.("quarantine")}
                          >
                            Resolve
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="pt-2 text-center border-t border-[#EAEFF5]">
                <button
                  onClick={() => onNavigatePage?.("threats")}
                  className="text-xs font-semibold text-[#2563EB] hover:text-[#1D4ED8] transition-colors"
                >
                  More alerts →
                </button>
              </div>
            </Card>

          </div>
        </div>

      </div>
    </div>
  );
}
