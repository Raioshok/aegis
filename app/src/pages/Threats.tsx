import { useEffect, useState } from "react";
import { Bug, History, ShieldCheck, AlertCircle } from "lucide-react";
import { api, fmtTime, severityColor, type HistoryRow, type ThreatRow } from "@/lib/api";
import { Badge, Card, SectionTitle } from "@/components/ui";

export default function Threats() {
  const [threats, setThreats] = useState<ThreatRow[]>([]);
  const [history, setHistory] = useState<HistoryRow[]>([]);
  const [activeTab, setActiveTab] = useState<"threats" | "history">("threats");

  useEffect(() => {
    api.threats(200).then(setThreats).catch(() => {});
    api.history(50).then(setHistory).catch(() => {});
  }, []);

  return (
    <div className="space-y-6 max-w-6xl">
      <SectionTitle
        title="Threat Events & History"
        subtitle="Historical audit log of all identified threat events, real-time file interceptions, and completed scans."
      />

      {/* Clean Tabs */}
      <div className="flex items-center gap-2 border-b border-line pb-3">
        <button
          onClick={() => setActiveTab("threats")}
          className={`px-4 py-2 text-xs font-bold rounded-xl transition-all duration-150 ${
            activeTab === "threats"
              ? "bg-surface text-fg shadow-sm"
              : "text-fg-muted hover:text-fg hover:bg-surface-2"
          }`}
        >
          Threat Log ({threats.length})
        </button>
        <button
          onClick={() => setActiveTab("history")}
          className={`px-4 py-2 text-xs font-bold rounded-xl transition-all duration-150 ${
            activeTab === "history"
              ? "bg-surface text-fg shadow-sm"
              : "text-fg-muted hover:text-fg hover:bg-surface-2"
          }`}
        >
          Scan Sessions ({history.length})
        </button>
      </div>

      {activeTab === "threats" && (
        <Card className="p-0 overflow-hidden">
          <div className="px-6 py-4 border-b border-line flex items-center justify-between bg-surface">
            <h2 className="text-sm font-bold text-fg">Security Event Log</h2>
            <Badge color={threats.length > 0 ? "warn" : "ok"}>
              {threats.length === 0 ? "Protected" : `${threats.length} Events`}
            </Badge>
          </div>

          {threats.length === 0 ? (
            <div className="p-16 text-center space-y-2">
              <ShieldCheck size={36} className="text-ok mx-auto opacity-80" />
              <div className="text-sm font-bold text-fg">Zero Threats Logged</div>
              <p className="text-xs text-fg-muted max-w-sm mx-auto">
                No active threats or malicious binaries have been flagged on this machine.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-surface-2 text-fg-muted border-b border-line">
                  <tr>
                    <th className="px-6 py-3 font-semibold">Classification</th>
                    <th className="px-6 py-3 font-semibold">Object Location</th>
                    <th className="px-6 py-3 font-semibold">Engine</th>
                    <th className="px-6 py-3 font-semibold">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {threats.map((t, i) => (
                    <tr key={i} className="hover:bg-surface-2 transition-colors">
                      <td className="px-6 py-3.5 font-sans font-bold text-danger flex items-center gap-2">
                        <AlertCircle size={15} className="text-brand shrink-0" />
                        {t.names}
                      </td>
                      <td className="max-w-[340px] truncate px-6 py-3.5 text-fg-muted" title={t.path}>
                        {t.path}
                      </td>
                      <td className="px-6 py-3.5 text-fg-muted">{t.engines}</td>
                      <td className="px-6 py-3.5">
                        <Badge color={t.severity >= 3 ? "danger" : "warn"}>
                          {t.severity_label}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {activeTab === "history" && (
        <Card className="p-0 overflow-hidden">
          <div className="px-6 py-4 border-b border-line flex items-center justify-between bg-surface">
            <h2 className="text-sm font-bold text-fg">Completed Scan Sessions</h2>
            <Badge color="neutral">{history.length} Sessions</Badge>
          </div>

          {history.length === 0 ? (
            <div className="p-12 text-center text-xs text-fg-muted">
              No historical scan sessions recorded yet.
            </div>
          ) : (
            <div className="divide-y divide-line text-xs font-mono">
              {history.map((h, i) => (
                <div key={i} className="px-6 py-3.5 flex items-center justify-between hover:bg-surface-2 transition-colors">
                  <div className="flex items-center gap-3 min-w-0">
                    <Badge color={h.kind === "realtime" ? "blue" : "ok"}>{h.kind}</Badge>
                    <span className="text-fg font-medium truncate max-w-md" title={h.target}>
                      {h.target}
                    </span>
                  </div>
                  <div className="flex items-center gap-6 text-fg-muted shrink-0">
                    <span className="tab-nums">{h.files} files</span>
                    <span className={h.threats > 0 ? "text-danger font-bold tab-nums" : "text-ok tab-nums"}>
                      {h.threats} threats
                    </span>
                    <span className="text-fg-subtle">{fmtTime(h.finished)}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
