import { useState } from "react";
import { Radar, Cpu } from "lucide-react";
import { api, severityColor, type ThreatRow } from "@/lib/api";
import { Button, Card, SectionTitle, Spinner } from "@/components/ui";

function Findings({ rows }: { rows: ThreatRow[] }) {
  if (rows.length === 0)
    return <p className="text-sm text-ok">✓ nothing suspicious found</p>;
  return (
    <div className="space-y-2">
      {rows.map((r, i) => (
        <div key={i} className="rounded-lg border border-border bg-black/20 px-3 py-2">
          <div className="flex items-center gap-2">
            <span className={`text-sm font-medium ${severityColor(r.severity)}`}>
              [{r.severity_label}]
            </span>
            <span className="text-sm">{r.names}</span>
          </div>
          <div className="mt-0.5 text-xs text-muted">{r.path.toString()}</div>
        </div>
      ))}
    </div>
  );
}

export default function Behavior() {
  const [rootkit, setRootkit] = useState<ThreatRow[] | null>(null);
  const [memory, setMemory] = useState<ThreatRow[] | null>(null);
  const [pid, setPid] = useState("");
  const [busy, setBusy] = useState<"rootkit" | "memory" | null>(null);

  const runRootkit = async () => {
    setBusy("rootkit");
    try {
      setRootkit(await api.rootkitScan());
    } finally {
      setBusy(null);
    }
  };
  const runMemory = async () => {
    setBusy("memory");
    try {
      const p = pid.trim() ? parseInt(pid.trim(), 10) : undefined;
      setMemory(await api.memoryScan(p));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div>
      <SectionTitle
        title="Behavioral engine"
        subtitle="Signature-less defence: rootkit integrity checks and process-memory inspection."
      />

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-base font-semibold">
              <Radar size={18} className="text-accent" /> Rootkit scan
            </h2>
            <Button onClick={runRootkit} disabled={busy !== null}>
              {busy === "rootkit" ? <Spinner /> : "Run"}
            </Button>
          </div>
          <p className="mb-3 text-xs text-muted">
            Cross-view /proc ⇄ /sys: hidden processes, hidden modules, ld.so.preload,
            kernel taint.
          </p>
          {rootkit && <Findings rows={rootkit} />}
        </Card>

        <Card>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-base font-semibold">
              <Cpu size={18} className="text-accent" /> Memory scan
            </h2>
            <div className="flex gap-2">
              <input
                value={pid}
                onChange={(e) => setPid(e.target.value)}
                placeholder="PID (blank = all)"
                className="w-32 rounded-lg border border-border bg-black/30 px-2 py-1.5 text-xs outline-none placeholder:text-muted"
              />
              <Button onClick={runMemory} disabled={busy !== null}>
                {busy === "memory" ? <Spinner /> : "Run"}
              </Button>
            </div>
          </div>
          <p className="mb-3 text-xs text-muted">
            /proc/&lt;pid&gt;/maps: W^X regions, anonymous executable memory,
            deleted-backing executables.
          </p>
          {memory && <Findings rows={memory} />}
        </Card>
      </div>
    </div>
  );
}
