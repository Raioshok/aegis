import { useState, useEffect } from "react";
import { Radar, Cpu, ShieldCheck, AlertTriangle, Play, GitBranch, Bot, Skull, Copy } from "lucide-react";
import { api, severityColor, type ThreatRow, type LineageAlertDto } from "@/lib/api";
import { Button, Card, SectionTitle, Badge, Spinner } from "@/components/ui";
import { SpotlightCard, Magnet, DecryptedText, useContextMenu } from "@/components/reactbits";

function Findings({ rows }: { rows: ThreatRow[] }) {
  if (rows.length === 0)
    return (
      <div className="flex items-center gap-2.5 rounded-xl border border-ok/30 bg-ok-soft p-4 text-xs text-ok font-semibold">
        <ShieldCheck size={18} className="text-ok" />
        <span>No anomalies or rootkit hooks detected. System integrity clean.</span>
      </div>
    );
  return (
    <div className="space-y-2.5">
      {rows.map((r, i) => (
        <div key={i} className="rounded-xl border border-brand/30 bg-brand-soft p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-danger flex items-center gap-2">
              <AlertTriangle size={15} className="text-brand" />
              {r.names}
            </span>
            <Badge color="danger">
              [{r.severity_label}]
            </Badge>
          </div>
          <div className="mt-1 font-mono text-[11px] text-fg-muted truncate">{r.path.toString()}</div>
        </div>
      ))}
    </div>
  );
}

export default function Behavior() {
  const { showMenu } = useContextMenu();
  const [rootkit, setRootkit] = useState<ThreatRow[] | null>(null);
  const [memory, setMemory] = useState<ThreatRow[] | null>(null);
  const [lineageAlerts, setLineageAlerts] = useState<LineageAlertDto[]>([]);
  const [pid, setPid] = useState("");
  const [busy, setBusy] = useState<"rootkit" | "memory" | null>(null);

  const loadAlerts = () => {
    api.getLineageAlerts().then(setLineageAlerts).catch(() => {});
  };

  useEffect(() => {
    loadAlerts();
    const iv = setInterval(loadAlerts, 4000);
    return () => clearInterval(iv);
  }, []);

  const handleKill = async (targetPid: number) => {
    try {
      await api.killProcess(targetPid);
      loadAlerts();
    } catch (e) {
      console.error(e);
    }
  };

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
        subtitle="Rootkit checks, process memory scans and live process-lineage alerts."
      />

      {/* Process Execution DAG Lineage Alerts (MITRE ATT&CK) */}
      {lineageAlerts.length > 0 && (
        <Card className="p-5 border border-danger/30 bg-danger-soft space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5 font-bold text-sm text-danger">
              <GitBranch size={18} />
              <span>Process Execution DAG Anomaly Alerts ({lineageAlerts.length})</span>
            </div>
            <Badge color="danger">High Severity Lineages</Badge>
          </div>
          <div className="space-y-2">
            {lineageAlerts.map((a) => (
              <div
                key={a.alert_id}
                onContextMenu={(e) => {
                  showMenu(e, [
                    {
                      label: `Terminate Process (PID ${a.child_pid})`,
                      icon: <Skull size={14} className="text-danger" />,
                      danger: true,
                      action: () => handleKill(a.child_pid),
                    },
                    {
                      label: "Copy Commandline",
                      icon: <Copy size={14} className="text-fg-muted" />,
                      action: () => navigator.clipboard.writeText(a.child_cmdline),
                    },
                    {
                      label: `Copy Parent Process (${a.parent_name})`,
                      action: () => navigator.clipboard.writeText(`${a.parent_name} (PID ${a.parent_pid})`),
                    },
                  ]);
                }}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 rounded-xl bg-surface border border-danger/30 font-mono text-xs cursor-context-menu hover:border-danger transition-colors"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2 font-bold text-danger">
                    <span>[{a.threat}]</span>
                    {a.agent_context && (
                      <span className="inline-flex items-center gap-1 rounded bg-violet-soft border border-violet/30 px-1.5 py-0.5 text-[10px] text-violet">
                        <Bot size={11} /> {a.agent_context}
                      </span>
                    )}
                    {a.mitre_techniques?.map((t) => (
                      <span
                        key={t}
                        className="rounded bg-danger-soft border border-danger/30 px-1 text-[9px] text-danger"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                  <div className="text-[11px] text-fg-muted font-sans">
                    {a.explanation}
                  </div>
                  <div className="text-[10px] text-fg-subtle truncate max-w-xl">
                    Parent: {a.parent_name} (PID {a.parent_pid}) ➔ Child PID {a.child_pid}: {a.child_cmdline}
                  </div>
                </div>

                <div className="shrink-0 flex items-center gap-2">
                  <Badge color="danger">Score {a.risk_score}</Badge>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={() => handleKill(a.child_pid)}
                  >
                    <Skull size={13} /> Terminate
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Rootkit Detector */}
        <Card className="p-6 space-y-4">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-info-soft text-info">
                <Radar size={20} />
              </div>
              <div>
                <h2 className="text-sm font-bold text-fg">Kernel & Rootkit Audit</h2>
                <p className="text-xs text-fg-muted">Cross-view validation across drivers & processes</p>
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

          <p className="text-xs text-fg-muted leading-relaxed">
            Performs hidden module inspection, kernel syscall table validation, and checks for DKOM unlinked threads.
          </p>

          <div className="pt-2">
            {!rootkit && busy !== "rootkit" && (
              <div className="p-8 text-center text-xs text-fg-subtle border border-dashed border-line rounded-xl">
                Ready to inspect system drivers and kernel hooks.
              </div>
            )}
            {busy === "rootkit" && (
              <div className="flex items-center justify-center gap-2 py-8 text-xs text-fg-muted">
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
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-soft text-brand">
                <Cpu size={20} />
              </div>
              <div>
                <h2 className="text-sm font-bold text-fg">Process Memory Inspection</h2>
                <p className="text-xs text-fg-muted">Shellcode, unbacked threads & W+X pages</p>
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
              className="flex-1 rounded-xl border border-line bg-surface-2 px-3.5 py-2 text-xs text-fg outline-none placeholder:text-fg-subtle font-mono"
            />
          </div>

          <div className="pt-2">
            {!memory && busy !== "memory" && (
              <div className="p-8 text-center text-xs text-fg-subtle border border-dashed border-line rounded-xl">
                Ready to inspect process memory maps and unbacked thread entries.
              </div>
            )}
            {busy === "memory" && (
              <div className="flex items-center justify-center gap-2 py-8 text-xs text-fg-muted">
                <Spinner />
                <span>Scanning virtual memory pages...</span>
              </div>
            )}
            {memory && <Findings rows={memory} />}
          </div>
        </Card>
      </div>

      <Card className="p-6">
        <div className="text-sm font-semibold">What a memory scan checks</div>
        <p className="mt-1 text-xs text-fg-muted">These run each time you start a memory scan above; they are not resident monitors.</p>
        <ul className="mt-4 grid grid-cols-1 gap-x-8 gap-y-2.5 text-[13px] md:grid-cols-2">
          {[
            ["Injected code", "executable memory that is writable or not backed by a file (both OSes)"],
            ["Fileless payloads", "programs running from memfd_create mappings (Linux)"],
            ["Reflective DLL injection", "PE images mapped in memory that no file backs (Windows)"],
            ["Direct and indirect syscalls", "syscall stubs, and stack return addresses, in unbacked memory (Windows)"],
            ["Injected threads", "threads that start or run in unbacked memory: CreateRemoteThread, hijacking, PoolParty (Windows)"],
            ["FunctionPeekaboo", "sleep-masking markers in each thread's TEB (Windows)"],
            ["Module stomping", "a loaded DLL's .text section compared with the file on disk (Windows)"],
            ["AMSI / ETW tampering", "AmsiScanBuffer and EtwEventWrite patched to return early (Windows)"],
          ].map(([name, what]) => (
            <li key={name} className="flex gap-2.5">
              <ShieldCheck size={16} className="mt-0.5 shrink-0 text-brand" />
              <span>
                <span className="font-semibold">{name}</span> <span className="text-fg-muted">— {what}</span>
              </span>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
