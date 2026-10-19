import { useState } from "react";
import { Radar, Cpu, ShieldCheck, AlertTriangle, Play, Activity } from "lucide-react";
import { api, severityColor, type ThreatRow } from "@/lib/api";
import { Button, Card, SectionTitle, Badge, Spinner } from "@/components/ui";

function Findings({ rows }: { rows: ThreatRow[] }) {
  if (rows.length === 0)
    return (
      <div className="flex items-center gap-2.5 rounded-xl border border-[#A7F3D0] bg-[#ECFDF5] p-4 text-xs text-[#065F46] font-semibold">
        <ShieldCheck size={18} className="text-[#10B981]" />
        <span>No anomalies or rootkit hooks detected. System integrity clean.</span>
      </div>
    );
  return (
    <div className="space-y-2.5">
      {rows.map((r, i) => (
        <div key={i} className="rounded-xl border border-[#FFE2CC] bg-[#FFF8F3] p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#DC2626] flex items-center gap-2">
              <AlertTriangle size={15} className="text-[#FF7222]" />
              {r.names}
            </span>
            <Badge color="danger">
              [{r.severity_label}]
            </Badge>
          </div>
          <div className="mt-1 font-mono text-[11px] text-[#475569] truncate">{r.path.toString()}</div>
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
    <div className="space-y-6 max-w-6xl">
      <SectionTitle
        title="Behavioral Engine & Threat Guard"
        subtitle="In-memory code injection analysis, rootkit cross-view validation, and ransomware activity traps."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Rootkit Detector */}
        <Card className="p-6 space-y-4">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#EFF6FF] text-[#2563EB]">
                <Radar size={20} />
              </div>
              <div>
                <h2 className="text-sm font-bold text-[#1E293B]">Kernel & Rootkit Audit</h2>
                <p className="text-xs text-[#64748B]">Cross-view validation across drivers & processes</p>
              </div>
            </div>
            <Button
              variant="blue"
              size="sm"
              onClick={runRootkit}
              disabled={busy === "rootkit"}
            >
              {busy === "rootkit" ? <Spinner /> : <Play size={14} />} Run Audit
            </Button>
          </div>

          <p className="text-xs text-[#64748B] leading-relaxed">
            Performs hidden module inspection, kernel syscall table validation, and checks for DKOM unlinked threads.
          </p>

          <div className="pt-2">
            {!rootkit && busy !== "rootkit" && (
              <div className="p-8 text-center text-xs text-[#94A3B8] border border-dashed border-[#EAEFF5] rounded-xl">
                Ready to inspect system drivers and kernel hooks.
              </div>
            )}
            {busy === "rootkit" && (
              <div className="flex items-center justify-center gap-2 py-8 text-xs text-[#64748B]">
                <Spinner />
                <span>Auditing kernel driver structures...</span>
              </div>
            )}
            {rootkit && <Findings rows={rootkit} />}
          </div>
        </Card>

        {/* Memory Injection Scanner */}
        <Card className="p-6 space-y-4">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#FFF4EC] text-[#FF7222]">
                <Cpu size={20} />
              </div>
              <div>
                <h2 className="text-sm font-bold text-[#1E293B]">Process Memory Inspection</h2>
                <p className="text-xs text-[#64748B]">Shellcode, unbacked threads & W+X pages</p>
              </div>
            </div>
            <Button
              variant="primary"
              size="sm"
              onClick={runMemory}
              disabled={busy === "memory"}
            >
              {busy === "memory" ? <Spinner /> : <Play size={14} />} Scan Memory
            </Button>
          </div>

          <div className="flex gap-2">
            <input
              value={pid}
              onChange={(e) => setPid(e.target.value)}
              placeholder="PID (optional, leave blank for all)"
              className="flex-1 rounded-xl border border-[#EAEFF5] bg-[#F8FAFC] px-3.5 py-2 text-xs text-[#1E293B] outline-none placeholder:text-[#94A3B8] font-mono"
            />
          </div>

          <div className="pt-2">
            {!memory && busy !== "memory" && (
              <div className="p-8 text-center text-xs text-[#94A3B8] border border-dashed border-[#EAEFF5] rounded-xl">
                Ready to inspect process memory maps and unbacked thread entries.
              </div>
            )}
            {busy === "memory" && (
              <div className="flex items-center justify-center gap-2 py-8 text-xs text-[#64748B]">
                <Spinner />
                <span>Scanning virtual memory pages...</span>
              </div>
            )}
            {memory && <Findings rows={memory} />}
          </div>
        </Card>
      </div>
    </div>
  );
}
