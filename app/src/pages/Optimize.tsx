import { useEffect, useState } from "react";
import { Rocket, HardDrive, Gauge, RefreshCw, CheckCircle2 } from "lucide-react";
import { api, impactColor, type OptimizeReport } from "@/lib/api";
import { Badge, Button, Card, SectionTitle, Spinner, StatCard } from "@/components/ui";

export default function Optimize() {
  const [rep, setRep] = useState<OptimizeReport | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    setBusy(true);
    try {
      setRep(await api.optimizeScan());
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  const cats = rep ? Array.from(new Set(rep.findings.map((f) => f.category))) : [];

  return (
    <div className="space-y-6 max-w-6xl">
      <SectionTitle
        title="System Tune-Up & Optimization"
        subtitle="Disk space recovery, orphan package cleanup, and TCP network stack optimizations."
        action={
          <Button variant="outline" size="sm" onClick={load} disabled={busy}>
            {busy ? <Spinner /> : <RefreshCw size={14} className="text-brand" />} Rescan
          </Button>
        }
      />

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard
          label="Reclaimable Space"
          value={rep?.total_reclaimable_human ?? "0 B"}
          accent="text-ok"
          icon={<HardDrive size={22} />}
        />
        <StatCard
          label="Optimization Tasks"
          value={rep?.opportunities ?? 0}
          accent={rep && rep.opportunities > 0 ? "text-brand" : "text-ok"}
          icon={<Rocket size={22} />}
        />
        <StatCard
          label="Subsystem Audits"
          value={rep?.findings.length ?? 0}
          icon={<Gauge size={22} />}
        />
      </div>

      <Card className="p-0 overflow-hidden">
        <div className="px-6 py-4 border-b border-line flex items-center justify-between bg-surface">
          <h2 className="text-sm font-bold text-fg">Optimization Opportunities</h2>
          <Badge color={rep && rep.opportunities > 0 ? "warn" : "ok"}>
            {rep && rep.opportunities > 0 ? `${rep.opportunities} Pending` : "Optimized"}
          </Badge>
        </div>

        {!rep ? (
          <div className="flex items-center justify-center py-16 text-xs text-fg-muted">
            <Spinner />
            <span className="ml-2">Scanning system performance metrics...</span>
          </div>
        ) : rep.findings.length === 0 ? (
          <div className="p-16 text-center space-y-2">
            <CheckCircle2 size={36} className="text-ok mx-auto opacity-70" />
            <div className="text-sm font-bold text-fg">System is Fully Optimized</div>
            <p className="text-xs text-fg-muted">All storage caches and network settings are running at optimal throughput.</p>
          </div>
        ) : (
          <div className="divide-y divide-line">
            {cats.map((c) => (
              <div key={c} className="p-6 space-y-3">
                <div className="text-xs font-bold uppercase tracking-wider text-fg-subtle">{c}</div>
                <div className="space-y-2">
                  {rep.findings
                    .filter((f) => f.category === c)
                    .map((f, i) => (
                      <div
                        key={i}
                        className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 rounded-xl border border-line bg-surface-2"
                      >
                        <div>
                          <div className="text-xs font-bold text-fg">{f.title}</div>
                          <div className="text-[11px] text-fg-muted mt-0.5">{f.detail}</div>
                        </div>

                        <div className="flex items-center gap-3 shrink-0">
                          {f.reclaimable_human && (
                            <span className="text-xs font-mono font-bold text-ok tab-nums">
                              +{f.reclaimable_human}
                            </span>
                          )}
                          <Badge color={f.impact === 2 ? "warn" : f.impact === 1 ? "blue" : "ok"}>
                            {f.action ? "Actionable" : "Optimal"}
                          </Badge>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
