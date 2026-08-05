import { useEffect, useState } from "react";
import { api, fmtTime, severityColor, type HistoryRow, type ThreatRow } from "@/lib/api";
import { Badge, Card, SectionTitle } from "@/components/ui";

export default function Threats() {
  const [threats, setThreats] = useState<ThreatRow[]>([]);
  const [history, setHistory] = useState<HistoryRow[]>([]);

  useEffect(() => {
    api.threats(200).then(setThreats).catch(() => {});
    api.history(50).then(setHistory).catch(() => {});
  }, []);

  return (
    <div>
      <SectionTitle title="Threats & History" subtitle="Everything Aegis has detected." />

      <Card className="mb-5">
        <h2 className="mb-3 text-base font-semibold">Detected threats</h2>
        {threats.length === 0 ? (
          <p className="text-sm text-muted">No threats recorded.</p>
        ) : (
          <div className="max-h-[340px] overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-black/40 text-left text-muted backdrop-blur">
                <tr>
                  <th className="px-3 py-2 font-medium">Threat</th>
                  <th className="px-3 py-2 font-medium">Path</th>
                  <th className="px-3 py-2 font-medium">Engine</th>
                  <th className="px-3 py-2 font-medium">Severity</th>
                </tr>
              </thead>
              <tbody>
                {threats.map((t, i) => (
                  <tr key={i} className="border-t border-border">
                    <td className="px-3 py-2">{t.names}</td>
                    <td className="max-w-[260px] truncate px-3 py-2 text-muted" title={t.path}>
                      {t.path}
                    </td>
                    <td className="px-3 py-2 text-muted">{t.engines}</td>
                    <td className="px-3 py-2">
                      <span className={severityColor(t.severity)}>{t.severity_label}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card>
        <h2 className="mb-3 text-base font-semibold">Scan history</h2>
        {history.length === 0 ? (
          <p className="text-sm text-muted">No scans yet.</p>
        ) : (
          <div className="space-y-1">
            {history.map((h, i) => (
              <div
                key={i}
                className="flex items-center justify-between rounded-lg px-3 py-2 text-sm hover:bg-white/5"
              >
                <div className="flex items-center gap-3">
                  <Badge color={h.kind === "realtime" ? "accent" : "muted"}>{h.kind}</Badge>
                  <span className="max-w-[320px] truncate text-muted" title={h.target}>
                    {h.target}
                  </span>
                </div>
                <div className="flex items-center gap-4 text-muted">
                  <span>{h.files} files</span>
                  <span className={h.threats > 0 ? "text-danger" : "text-ok"}>
                    {h.threats} threats
                  </span>
                  <span>{fmtTime(h.finished)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
