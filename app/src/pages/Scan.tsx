import { useState, useEffect } from "react";
import {
  ScanLine,
  FolderSearch,
  Zap,
  HardDrive,
  FolderCog,
  CheckCircle2,
  AlertOctagon,
  ShieldAlert,
  FileCode,
} from "lucide-react";
import { api, severityColor, type ScanReport, type ScanProgress } from "@/lib/api";
import { Button, Card, SectionTitle, Badge, Spinner } from "@/components/ui";

type ScanMode = "smart" | "full" | "custom";

const QUICK_TARGETS = [
  { label: "Downloads", path: "Downloads" },
  { label: "Desktop", path: "Desktop" },
  { label: "Documents", path: "Documents" },
  { label: "Temp", path: "Temp" },
];

export default function Scan() {
  const [mode, setMode] = useState<ScanMode>("smart");
  const [customPath, setCustomPath] = useState("C:\\Users\\raio\\Downloads");
  const [smartTarget, setSmartTarget] = useState("C:\\Users\\raio\\Downloads");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [progress, setProgress] = useState<ScanProgress>({
    is_active: false,
    current_file: "",
    scanned: 0,
    total: 0,
    threats: 0,
    rate: 0,
    elapsed_secs: 0,
    percent: 0,
  });

  useEffect(() => {
    api.getSmartScanTarget()
      .then((target) => {
        setSmartTarget(target);
        setCustomPath(target);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    let interval: any;
    if (busy) {
      interval = setInterval(() => {
        api.getScanProgress()
          .then((p) => {
            setProgress(p);
          })
          .catch(() => {});
      }, 80);
    }
    return () => clearInterval(interval);
  }, [busy]);

  const getTargetPath = () => {
    if (mode === "full") return navigator.userAgent.includes("Windows") ? "C:\\" : "/";
    if (mode === "smart") return smartTarget;
    return customPath;
  };

  const run = async () => {
    setBusy(true);
    setErr(null);
    setReport(null);
    const target = getTargetPath();

    try {
      const res = await api.runScan(target);
      setReport(res);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6 max-w-6xl">
      <SectionTitle
        title="Scan Center"
        subtitle="Zero-copy memory mapped threat analysis with YARA-X, Goblin PE/ELF structure inspection, and live threat feed cross-referencing."
      />

      {/* Mode Selection — Pure white cards, soft pill badges, orange accents */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div
          onClick={() => !busy && setMode("smart")}
          className={`p-5 rounded-2xl border transition-all duration-200 cursor-pointer shadow-card ${
            mode === "smart"
              ? "bg-[#FFF8F3] border-[#FFD8BF] shadow-card-hover"
              : "bg-white border-[#EAEFF5] hover:border-[#CBD5E1]"
          }`}
        >
          <div className="flex items-start gap-3.5">
            <div className={`p-2.5 rounded-xl shrink-0 ${mode === "smart" ? "bg-[#FF7222] text-white" : "bg-[#F8FAFC] text-[#64748B] border border-[#EAEFF5]"}`}>
              <Zap size={18} />
            </div>
            <div>
              <div className="text-sm font-bold text-[#1E293B] flex items-center gap-2">
                Smart Scan
                {mode === "smart" && <Badge color="accent">Selected</Badge>}
              </div>
              <p className="text-xs text-[#64748B] mt-1 leading-relaxed">
                Targets critical infection vectors: User downloads, desktop artifacts, documents, and memory.
              </p>
            </div>
          </div>
        </div>

        <div
          onClick={() => !busy && setMode("full")}
          className={`p-5 rounded-2xl border transition-all duration-200 cursor-pointer shadow-card ${
            mode === "full"
              ? "bg-[#FFF8F3] border-[#FFD8BF] shadow-card-hover"
              : "bg-white border-[#EAEFF5] hover:border-[#CBD5E1]"
          }`}
        >
          <div className="flex items-start gap-3.5">
            <div className={`p-2.5 rounded-xl shrink-0 ${mode === "full" ? "bg-[#FF7222] text-white" : "bg-[#F8FAFC] text-[#64748B] border border-[#EAEFF5]"}`}>
              <HardDrive size={18} />
            </div>
            <div>
              <div className="text-sm font-bold text-[#1E293B] flex items-center gap-2">
                Full System Scan
                {mode === "full" && <Badge color="accent">Selected</Badge>}
              </div>
              <p className="text-xs text-[#64748B] mt-1 leading-relaxed">
                Exhaustively traverses root system storage, checking every byte against all 37 rule families.
              </p>
            </div>
          </div>
        </div>

        <div
          onClick={() => !busy && setMode("custom")}
          className={`p-5 rounded-2xl border transition-all duration-200 cursor-pointer shadow-card ${
            mode === "custom"
              ? "bg-[#FFF8F3] border-[#FFD8BF] shadow-card-hover"
              : "bg-white border-[#EAEFF5] hover:border-[#CBD5E1]"
          }`}
        >
          <div className="flex items-start gap-3.5">
            <div className={`p-2.5 rounded-xl shrink-0 ${mode === "custom" ? "bg-[#FF7222] text-white" : "bg-[#F8FAFC] text-[#64748B] border border-[#EAEFF5]"}`}>
              <FolderCog size={18} />
            </div>
            <div>
              <div className="text-sm font-bold text-[#1E293B] flex items-center gap-2">
                Custom Target
                {mode === "custom" && <Badge color="accent">Selected</Badge>}
              </div>
              <p className="text-xs text-[#64748B] mt-1 leading-relaxed">
                Audit a specific folder, project workspace, USB drive, or build directory on demand.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Target Input & Action Bar */}
      <Card className="p-5">
        <div className="flex flex-col md:flex-row items-center gap-3">
          <div className="flex flex-1 items-center gap-2.5 rounded-xl border border-[#EAEFF5] bg-[#F8FAFC] px-4 py-2.5 w-full">
            <FolderSearch size={18} className="text-[#94A3B8]" />
            <input
              value={mode === "custom" ? customPath : getTargetPath()}
              disabled={mode !== "custom" || busy}
              onChange={(e) => setCustomPath(e.target.value)}
              placeholder="Select folder or drive path..."
              className="flex-1 bg-transparent text-xs text-[#1E293B] outline-none placeholder:text-[#94A3B8] disabled:text-[#64748B] disabled:cursor-not-allowed font-mono font-medium"
            />
            {mode !== "custom" && (
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#94A3B8] bg-white px-2 py-0.5 rounded border border-[#EAEFF5]">
                Auto
              </span>
            )}
          </div>

          <Button
            variant="primary"
            size="md"
            className="w-full md:w-auto min-w-[150px]"
            onClick={run}
            disabled={busy}
          >
            {busy ? <Spinner /> : <ScanLine size={16} />}
            {busy ? "Inspecting..." : "Start Scan"}
          </Button>
        </div>

        {mode === "custom" && (
          <div className="mt-3.5 flex items-center gap-2">
            <span className="text-xs text-[#64748B]">Suggested:</span>
            {QUICK_TARGETS.map((q) => (
              <button
                key={q.label}
                disabled={busy}
                onClick={() => {
                  if (q.path === "Downloads") setCustomPath(smartTarget);
                  else if (q.path === "Temp") setCustomPath("C:\\Windows\\Temp");
                  else setCustomPath(`C:\\Users\\raio\\${q.path}`);
                }}
                className="rounded-lg border border-[#EAEFF5] bg-white px-2.5 py-1 text-xs font-medium text-[#475569] hover:text-[#1E293B] hover:border-[#CBD5E1] transition-all font-mono active:scale-[0.96] shadow-sm"
              >
                {q.label}
              </button>
            ))}
          </div>
        )}
      </Card>

      {/* Real Live Backend Progress Card */}
      {busy && (
        <Card className="p-6 border-[#FFD8BF] bg-[#FFF8F3] space-y-4 shadow-card">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="h-2.5 w-2.5 rounded-full bg-[#FF7222] animate-ping" />
              <div className="text-sm font-bold text-[#1E293B]">Inspecting Filesystem...</div>
              {progress.total > 0 && (
                <span className="text-xs font-mono text-[#FF7222] font-bold tab-nums">
                  ({progress.scanned} / {progress.total} files)
                </span>
              )}
            </div>
            <div className="flex items-center gap-4 text-xs font-mono text-[#64748B] tab-nums font-medium">
              <span>Elapsed: {progress.elapsed_secs}s</span>
              {progress.rate > 0 && <span>Rate: {progress.rate} f/s</span>}
              {progress.threats > 0 && (
                <span className="text-[#DC2626] font-bold">Threats: {progress.threats}</span>
              )}
            </div>
          </div>

          {/* Genuine Dynamic Progress Bar */}
          <div className="h-2.5 w-full bg-[#E2E8F0] rounded-full overflow-hidden">
            <div
              className="h-full bg-[#FF7222] transition-all duration-150 ease-out rounded-full"
              style={{
                width: progress.total > 0
                  ? `${Math.max(3, Math.min(100, progress.percent))}%`
                  : "30%",
              }}
            />
          </div>

          {/* Real Live File Path Ticker */}
          <div className="flex items-center gap-2 text-xs font-mono text-[#64748B] truncate bg-white/70 px-3 py-1.5 rounded-lg border border-[#FFE2CC]">
            <FileCode size={14} className="text-[#FF7222] shrink-0" />
            <span className="truncate text-[#1E293B] font-medium">
              {progress.current_file || "Reading file stream..."}
            </span>
          </div>
        </Card>
      )}

      {/* Error Card */}
      {err && (
        <Card className="p-4 border-[#FECACA] bg-[#FEF2F2] flex items-center gap-3">
          <AlertOctagon size={18} className="text-[#DC2626] shrink-0" />
          <div className="text-xs text-[#DC2626] font-mono">{err}</div>
        </Card>
      )}

      {/* Report Findings Table */}
      {report && (
        <Card className="p-6 space-y-4">
          <div className="flex items-center justify-between pb-4 border-b border-[#EAEFF5]">
            <div className="flex items-center gap-3">
              <div
                className={`flex h-10 w-10 items-center justify-center rounded-xl ${
                  report.threats > 0 ? "bg-[#FEF2F2] text-[#DC2626]" : "bg-[#ECFDF5] text-[#059669]"
                }`}
              >
                {report.threats > 0 ? (
                  <ShieldAlert size={22} />
                ) : (
                  <CheckCircle2 size={22} />
                )}
              </div>
              <div>
                <div className="text-base font-bold text-[#1E293B]">
                  {report.threats > 0
                    ? `Scan Finished: ${report.threats} Threat(s) Identified`
                    : "Scan Finished: Clean (No Threats Found)"}
                </div>
                <div className="text-xs text-[#64748B] mt-0.5">
                  {report.scanned} files inspected in {(report.duration_ms / 1000).toFixed(2)}s
                </div>
              </div>
            </div>

            <Badge color={report.threats > 0 ? "danger" : "ok"}>
              {report.threats > 0 ? "Action Required" : "Protected"}
            </Badge>
          </div>

          {report.results.length === 0 ? (
            <div className="p-10 text-center text-xs text-[#64748B]">
              All inspected files verified clean against YARA-X rules, hash databases, and heuristic analyzers.
            </div>
          ) : (
            <div className="divide-y divide-[#EAEFF5] overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="text-[#64748B] bg-[#F8FAFC] border-b border-[#EAEFF5]">
                  <tr>
                    <th className="px-4 py-3 font-semibold">Threat</th>
                    <th className="px-4 py-3 font-semibold">Path</th>
                    <th className="px-4 py-3 font-semibold">Engine</th>
                    <th className="px-4 py-3 font-semibold">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#EAEFF5]">
                  {report.results.map((r, i) => (
                    <tr key={i} className="hover:bg-[#F8FAFC] transition-colors">
                      <td className="px-4 py-3 font-sans font-bold text-[#DC2626]">{r.names}</td>
                      <td className="px-4 py-3 text-[#475569] truncate max-w-sm" title={r.path}>
                        {r.path}
                      </td>
                      <td className="px-4 py-3 text-[#64748B]">{r.engines}</td>
                      <td className="px-4 py-3">
                        <span className={`font-bold uppercase ${severityColor(r.severity)}`}>
                          {r.severity_label}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
