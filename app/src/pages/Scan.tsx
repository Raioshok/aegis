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
import { SpotlightCard, Magnet, useContextMenu } from "@/components/reactbits";

type ScanMode = "smart" | "full" | "custom";

const QUICK_TARGETS = [
  { label: "Downloads", path: "Downloads" },
  { label: "Desktop", path: "Desktop" },
  { label: "Documents", path: "Documents" },
  { label: "Temp", path: "Temp" },
];

export default function Scan() {
  const { showMenu } = useContextMenu();
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
        subtitle="Checks files with YARA-X rules, PE/ELF heuristics, machine learning and the malware hash databases."
      />

      {/* Mode Selection — Pure white cards, soft pill badges, orange accents */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div
          onClick={() => !busy && setMode("smart")}
          className={`p-5 rounded-2xl border transition-all duration-200 cursor-pointer shadow-card ${
            mode === "smart"
              ? "bg-brand-soft border-brand/30 shadow-card-hover"
              : "bg-surface border-line hover:border-line"
          }`}
        >
          <div className="flex items-start gap-3.5">
            <div className={`p-2.5 rounded-xl shrink-0 ${mode === "smart" ? "bg-brand text-brand-ink" : "bg-surface-2 text-fg-muted border border-line"}`}>
              <Zap size={18} />
            </div>
            <div>
              <div className="text-sm font-bold text-fg flex items-center gap-2">
                Smart Scan
                {mode === "smart" && <Badge color="accent">Selected</Badge>}
              </div>
              <p className="text-xs text-fg-muted mt-1 leading-relaxed">
                Targets critical infection vectors: User downloads, desktop artifacts, documents, and memory.
              </p>
            </div>
          </div>
        </div>

        <div
          onClick={() => !busy && setMode("full")}
          className={`p-5 rounded-2xl border transition-all duration-200 cursor-pointer shadow-card ${
            mode === "full"
              ? "bg-brand-soft border-brand/30 shadow-card-hover"
              : "bg-surface border-line hover:border-line"
          }`}
        >
          <div className="flex items-start gap-3.5">
            <div className={`p-2.5 rounded-xl shrink-0 ${mode === "full" ? "bg-brand text-brand-ink" : "bg-surface-2 text-fg-muted border border-line"}`}>
              <HardDrive size={18} />
            </div>
            <div>
              <div className="text-sm font-bold text-fg flex items-center gap-2">
                Full System Scan
                {mode === "full" && <Badge color="accent">Selected</Badge>}
              </div>
              <p className="text-xs text-fg-muted mt-1 leading-relaxed">
                Exhaustively traverses root system storage, checking every byte against all 37 rule families.
              </p>
            </div>
          </div>
        </div>

        <div
          onClick={() => !busy && setMode("custom")}
          className={`p-5 rounded-2xl border transition-all duration-200 cursor-pointer shadow-card ${
            mode === "custom"
              ? "bg-brand-soft border-brand/30 shadow-card-hover"
              : "bg-surface border-line hover:border-line"
          }`}
        >
          <div className="flex items-start gap-3.5">
            <div className={`p-2.5 rounded-xl shrink-0 ${mode === "custom" ? "bg-brand text-brand-ink" : "bg-surface-2 text-fg-muted border border-line"}`}>
              <FolderCog size={18} />
            </div>
            <div>
              <div className="text-sm font-bold text-fg flex items-center gap-2">
                Custom Target
                {mode === "custom" && <Badge color="accent">Selected</Badge>}
              </div>
              <p className="text-xs text-fg-muted mt-1 leading-relaxed">
                Audit a specific folder, project workspace, USB drive, or build directory on demand.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Target Input & Action Bar */}
      <Card className="p-5">
        <div className="flex flex-col md:flex-row items-center gap-3">
          <div className="flex flex-1 items-center gap-2.5 rounded-xl border border-line bg-surface-2 px-4 py-2.5 w-full">
            <FolderSearch size={18} className="text-fg-subtle" />
            <input
              value={mode === "custom" ? customPath : getTargetPath()}
              disabled={mode !== "custom" || busy}
              onChange={(e) => setCustomPath(e.target.value)}
              placeholder="Select folder or drive path..."
              className="flex-1 bg-transparent text-xs text-fg outline-none placeholder:text-fg-subtle disabled:text-fg-muted disabled:cursor-not-allowed font-mono font-medium"
            />
            {mode !== "custom" && (
              <span className="text-[10px] font-bold uppercase tracking-wider text-fg-subtle bg-surface px-2 py-0.5 rounded border border-line">
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
            <span className="text-xs text-fg-muted">Suggested:</span>
            {QUICK_TARGETS.map((q) => (
              <button
                key={q.label}
                disabled={busy}
                onClick={() => {
                  if (q.path === "Downloads") setCustomPath(smartTarget);
                  else if (q.path === "Temp") setCustomPath("C:\\Windows\\Temp");
                  else setCustomPath(`C:\\Users\\raio\\${q.path}`);
                }}
                className="rounded-lg border border-line bg-surface px-2.5 py-1 text-xs font-medium text-fg-muted hover:text-fg hover:border-line transition-all font-mono active:scale-[0.96] shadow-sm"
              >
                {q.label}
              </button>
            ))}
          </div>
        )}
      </Card>

      {/* Real Live Backend Progress Card */}
      {busy && (
        <Card className="p-6 border-brand/30 bg-brand-soft space-y-4 shadow-card">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="h-2.5 w-2.5 rounded-full bg-brand animate-ping" />
              <div className="text-sm font-bold text-fg">Inspecting Filesystem...</div>
              {progress.total > 0 && (
                <span className="text-xs font-mono text-brand font-bold tab-nums">
                  ({progress.scanned} / {progress.total} files)
                </span>
              )}
            </div>
            <div className="flex items-center gap-4 text-xs font-mono text-fg-muted tab-nums font-medium">
              <span>Elapsed: {progress.elapsed_secs}s</span>
              {progress.rate > 0 && <span>Rate: {progress.rate} f/s</span>}
              {progress.threats > 0 && (
                <span className="text-danger font-bold">Threats: {progress.threats}</span>
              )}
            </div>
          </div>

          {/* Genuine Dynamic Progress Bar */}
          <div className="h-2.5 w-full bg-line rounded-full overflow-hidden">
            <div
              className="h-full bg-brand transition-all duration-150 ease-out rounded-full"
              style={{
                width: progress.total > 0
                  ? `${Math.max(3, Math.min(100, progress.percent))}%`
                  : "30%",
              }}
            />
          </div>

          {/* Real Live File Path Ticker */}
          <div className="flex items-center gap-2 text-xs font-mono text-fg-muted truncate bg-surface/70 px-3 py-1.5 rounded-lg border border-brand/30">
            <FileCode size={14} className="text-brand shrink-0" />
            <span className="truncate text-fg font-medium">
              {progress.current_file || "Reading file stream..."}
            </span>
          </div>
        </Card>
      )}

      {/* Error Card */}
      {err && (
        <Card className="p-4 border-danger/30 bg-danger-soft flex items-center gap-3">
          <AlertOctagon size={18} className="text-danger shrink-0" />
          <div className="text-xs text-danger font-mono">{err}</div>
        </Card>
      )}

      {/* Report Findings Table */}
      {report && (
        <Card className="p-6 space-y-4">
          <div className="flex items-center justify-between pb-4 border-b border-line">
            <div className="flex items-center gap-3">
              <div
                className={`flex h-10 w-10 items-center justify-center rounded-xl ${
                  report.threats > 0 ? "bg-danger-soft text-danger" : "bg-ok-soft text-ok"
                }`}
              >
                {report.threats > 0 ? (
                  <ShieldAlert size={22} />
                ) : (
                  <CheckCircle2 size={22} />
                )}
              </div>
              <div>
                <div className="text-base font-bold text-fg">
                  {report.threats > 0
                    ? `Scan Finished: ${report.threats} Threat(s) Identified`
                    : "Scan Finished: Clean (No Threats Found)"}
                </div>
                <div className="text-xs text-fg-muted mt-0.5">
                  {report.scanned} files inspected in {(report.duration_ms / 1000).toFixed(2)}s
                </div>
              </div>
            </div>

            <Badge color={report.threats > 0 ? "danger" : "ok"}>
              {report.threats > 0 ? "Action Required" : "Protected"}
            </Badge>
          </div>

          {report.results.length === 0 ? (
            <div className="p-10 text-center text-xs text-fg-muted">
              All inspected files verified clean against YARA-X rules, hash databases, and heuristic analyzers.
            </div>
          ) : (
            <div className="divide-y divide-line overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="text-fg-muted bg-surface-2 border-b border-line">
                  <tr>
                    <th className="px-4 py-3 font-semibold">Threat</th>
                    <th className="px-4 py-3 font-semibold">Path</th>
                    <th className="px-4 py-3 font-semibold">Engine</th>
                    <th className="px-4 py-3 font-semibold">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {report.results.map((r, i) => (
                    <tr
                      key={i}
                      onContextMenu={(e) => {
                        showMenu(e, [
                          {
                            label: `Quarantine Threat`,
                            danger: true,
                            action: () => {
                              api.quarantineFile(r.path).catch(() => {});
                            },
                          },
                          {
                            label: "Copy File Path",
                            action: () => {
                              navigator.clipboard.writeText(r.path);
                            },
                          },
                          {
                            label: "Add to Allowlist",
                            action: () => {
                              api.addWhitelist(r.path, `Allowed: ${r.names}`).catch(() => {});
                            },
                          },
                        ]);
                      }}
                      className="hover:bg-surface-2 transition-colors cursor-context-menu"
                    >
                      <td className="px-4 py-3 font-sans font-bold text-danger">{r.names}</td>
                      <td className="px-4 py-3 text-fg-muted truncate max-w-sm" title={r.path}>
                        {r.path}
                      </td>
                      <td className="px-4 py-3 text-fg-muted">{r.engines}</td>
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
