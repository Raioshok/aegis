import { useState } from "react";
import { ScanLine, FolderSearch } from "lucide-react";
import { api, severityColor, type ScanReport } from "@/lib/api";
import { Button, Card, SectionTitle, Spinner } from "@/components/ui";

const QUICK = [
  { label: "/tmp", path: "/tmp" },
  { label: "/usr/bin", path: "/usr/bin" },
  { label: "/home", path: "/home" },
];

export default function Scan() {
  const [path, setPath] = useState("/tmp");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const run = async () => {
    setBusy(true);
    setErr(null);
    setReport(null);
    try {
      setReport(await api.runScan(path));
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <SectionTitle
        title="Scan"
        subtitle="Pick a file or folder. Whitelisted projects are skipped automatically."
      />

      <Card className="mb-5">
        <div className="flex gap-3">
          <div className="flex flex-1 items-center gap-2 rounded-xl border border-border bg-black/30 px-3">
            <FolderSearch size={16} className="text-muted" />
            <input
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="/home/you/Downloads"
              className="flex-1 bg-transparent py-2.5 text-sm outline-none placeholder:text-muted"
            />
          </div>
          <Button variant="primary" onClick={run} disabled={busy}>
            {busy ? <Spinner /> : <ScanLine size={16} />}
            {busy ? "Scanning…" : "Start Scan"}
          </Button>
        </div>
        <div className="mt-3 flex gap-2">
          {QUICK.map((q) => (
            <button
              key={q.label}
              onClick={() => setPath(q.path)}
              className="rounded-lg border border-border bg-white/5 px-3 py-1 text-xs text-muted hover:text-fg"
            >
              {q.label}
            </button>
          ))}
        </div>
      </Card>

      {err && (
        <Card className="mb-5 border-danger/40">
          <span className="text-sm text-danger">{err}</span>
        </Card>
      )}

      {report && (
        <Card>
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-base font-semibold">
              {report.threats > 0 ? (
                <span className="text-danger">
                  ⚠ {report.threats} threat(s) found
                </span>
              ) : (
                <span className="text-ok">✓ Clean</span>
              )}
            </h2>
            <span className="text-sm text-muted">
              {report.scanned} files · {(report.duration_ms / 1000).toFixed(2)}s
            </span>
          </div>
          {report.results.length > 0 ? (
            <div className="overflow-hidden rounded-xl border border-border">
              <table className="w-full text-sm">
                <thead className="bg-white/5 text-left text-muted">
                  <tr>
                    <th className="px-3 py-2 font-medium">File</th>
                    <th className="px-3 py-2 font-medium">Threat</th>
                    <th className="px-3 py-2 font-medium">Engines</th>
                    <th className="px-3 py-2 font-medium">Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {report.results.map((r, i) => (
                    <tr key={i} className="border-t border-border">
                      <td className="max-w-[280px] truncate px-3 py-2" title={r.path}>
                        {r.path}
                      </td>
                      <td className="px-3 py-2">{r.names}</td>
                      <td className="px-3 py-2 text-muted">{r.engines}</td>
                      <td className="px-3 py-2">
                        <span className={severityColor(r.severity)}>
                          {r.severity_label}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-muted">No threats detected in {report.scanned} files.</p>
          )}
        </Card>
      )}
    </div>
  );
}
