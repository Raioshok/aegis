import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Rocket, HardDrive, Gauge, RefreshCw } from "lucide-react";
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
    <div>
      <SectionTitle
        title="Optimize"
        subtitle="Arch system & network tune-up — reclaim space and check performance settings."
        action={
          <Button variant="primary" onClick={load} disabled={busy}>
            {busy ? <Spinner /> : <RefreshCw size={16} />} Rescan
          </Button>
        }
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-3">
        <StatCard
          label="Reclaimable space"
          value={rep?.total_reclaimable_human ?? "—"}
          accent="text-ok"
          icon={<HardDrive size={20} />}
        />
        <StatCard
          label="Opportunities"
          value={rep?.opportunities ?? 0}
          accent={rep && rep.opportunities > 0 ? "text-warn" : "text-ok"}
          icon={<Rocket size={20} />}
        />
        <StatCard label="Checks run" value={rep?.findings.length ?? 0} icon={<Gauge size={20} />} />
      </div>

      {!rep ? (
        <Card>
          <div className="flex items-center gap-2 text-sm text-muted">
            <Spinner /> Scanning system & network…
          </div>
        </Card>
      ) : (
        <div className="space-y-5">
          {cats.map((cat) => (
            <Card key={cat}>
              <h2 className="mb-3 text-base font-semibold">{cat}</h2>
              <div className="space-y-2">
                {rep.findings
                  .filter((f) => f.category === cat)
                  .sort((a, b) => b.impact - a.impact)
                  .map((f, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -6 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.02 }}
                      className="rounded-xl border border-border bg-black/20 px-4 py-3"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Badge
                            color={
                              f.impact === 0
                                ? "ok"
                                : f.impact === 1
                                  ? "accent"
                                  : f.impact === 2
                                    ? "warn"
                                    : "danger"
                            }
                          >
                            {f.impact_label}
                          </Badge>
                          <span className="text-sm font-medium">{f.title}</span>
                        </div>
                        {f.reclaimable > 0 && (
                          <span className="text-sm font-semibold text-ok">
                            ~{f.reclaimable_human}
                          </span>
                        )}
                      </div>
                      <div className="mt-1 text-xs text-muted">{f.detail}</div>
                      {f.action && (
                        <div className={`mt-1 font-mono text-[11px] ${impactColor(f.impact)}`}>
                          $ {f.action}
                          {f.needs_root && <span className="text-muted"> (needs sudo)</span>}
                        </div>
                      )}
                    </motion.div>
                  ))}
              </div>
            </Card>
          ))}
          <p className="text-center text-xs text-muted">
            Scans are read-only. Apply fixes from the CLI:{" "}
            <code>aegis optimize clean --apply</code> · <code>aegis optimize tune --apply</code>
          </p>
        </div>
      )}
    </div>
  );
}
