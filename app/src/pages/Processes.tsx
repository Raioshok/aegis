import { useEffect, useState } from "react";
import {
  Monitor,
  Search,
  RefreshCw,
  ShieldCheck,
  AlertTriangle,
  Skull,
  Eye,
  CheckCircle2,
  GitBranch,
  Table as TableIcon,
  Bot,
  Terminal,
  ShieldAlert,
  Activity,
} from "lucide-react";
import {
  api,
  type ProcessItem,
  type ThreatRow,
  type ProcessDagSnapshot,
  type ProcessTreeNodeDto,
} from "@/lib/api";
import { Badge, Button, Card, SectionTitle, Spinner } from "@/components/ui";
import { SwarmGraphCanvas } from "@/components/swarm/SwarmGraphCanvas";

function TreeNode({
  node,
  selectedPid,
  onSelect,
  depth = 0,
}: {
  node: ProcessTreeNodeDto;
  selectedPid: number | null;
  onSelect: (pid: number) => void;
  depth?: number;
}) {
  const isSelected = selectedPid === node.pid;
  const isHighRisk = node.risk_score >= 70;
  const isMediumRisk = node.risk_score >= 35 && node.risk_score < 70;

  return (
    <div className="select-none font-mono text-xs">
      <div
        onClick={() => onSelect(node.pid)}
        className={`flex items-center justify-between py-2 px-2.5 rounded-xl cursor-pointer transition-colors ${
          isSelected
            ? "bg-brand-soft border border-brand/30"
            : "hover:bg-surface-2 border border-transparent"
        }`}
        style={{ paddingLeft: `${Math.max(10, depth * 20)}px` }}
      >
        <div className="flex items-center gap-2 truncate">
          <span className="text-fg-subtle font-mono text-[11px] w-12 shrink-0">
            {depth > 0 ? "└── " : ""}{node.pid}
          </span>
          <span className="font-sans font-bold text-fg truncate">
            {node.name}
          </span>

          {node.is_agent_context && (
            <span className="inline-flex items-center gap-1 rounded-md bg-violet-soft border border-violet/30 px-1.5 py-0.5 text-[10px] font-sans font-bold text-violet">
              <Bot size={11} />
              {node.agent_type_label || "AI Agent"}
            </span>
          )}

          {node.mitre_techniques && node.mitre_techniques.length > 0 && (
            <span className="hidden sm:inline-flex items-center gap-1">
              {node.mitre_techniques.slice(0, 2).map((t) => (
                <span
                  key={t}
                  className="rounded bg-danger-soft border border-danger/30 px-1 py-0.2 text-[9px] font-mono font-bold text-danger"
                >
                  {t}
                </span>
              ))}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <Badge color={isHighRisk ? "danger" : isMediumRisk ? "warn" : "ok"}>
            Score: {node.risk_score}
          </Badge>
          {node.is_signed ? (
            <span className="text-ok text-[10px] font-sans font-semibold hidden md:inline">
              Signed
            </span>
          ) : (
            <span className="text-fg-subtle text-[10px] font-sans hidden md:inline">
              Unsigned
            </span>
          )}
        </div>
      </div>

      {node.children && node.children.length > 0 && (
        <div className="border-l border-line ml-4 pl-1">
          {node.children.map((c) => (
            <TreeNode
              key={c.pid}
              node={c}
              selectedPid={selectedPid}
              onSelect={onSelect}
              depth={depth + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function Processes() {
  const [list, setList] = useState<ProcessItem[]>([]);
  const [dagSnapshot, setDagSnapshot] = useState<ProcessDagSnapshot | null>(null);
  const [viewMode, setViewMode] = useState<"table" | "tree" | "swarm">("swarm");
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState(false);
  const [inspectPid, setInspectPid] = useState<number | null>(null);
  const [inspecting, setInspecting] = useState(false);
  const [inspectThreats, setInspectThreats] = useState<ThreatRow[] | null>(null);

  const refresh = async () => {
    setBusy(true);
    try {
      const [items, snap] = await Promise.all([
        api.listProcesses(),
        api.getProcessDag().catch(() => null),
      ]);
      setList(items);
      setDagSnapshot(snap);
    } catch (e) {
      console.error(e);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const handleInspect = async (pid: number) => {
    setInspectPid(pid);
    setInspecting(true);
    try {
      const res = await api.inspectProcessMemory(pid);
      setInspectThreats(res);
    } catch (e) {
      setInspectThreats([]);
    } finally {
      setInspecting(false);
    }
  };

  const handleKill = async (pid: number) => {
    try {
      await api.killProcess(pid);
      refresh();
      if (inspectPid === pid) {
        setInspectPid(null);
        setInspectThreats(null);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const selectedProcess = list.find((p) => p.pid === inspectPid);

  const filtered = list.filter(
    (p) =>
      p.name.toLowerCase().includes(filter.toLowerCase()) ||
      p.pid.toString().includes(filter) ||
      p.path.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="space-y-6 max-w-6xl">
      <SectionTitle
        title="Process Lineage & DAG Inspector"
        subtitle="Directed Acyclic Graph (DAG) process lineage tracking, AI Agent context auditing, and in-memory injection forensic analysis."
        action={
          <div className="flex items-center gap-2">
            <div className="flex items-center rounded-xl bg-surface-2 p-1 border border-line">
              <button
                onClick={() => setViewMode("swarm")}
                className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                  viewMode === "swarm"
                    ? "bg-brand text-brand-ink shadow-sm font-bold"
                    : "text-fg-muted hover:text-fg"
                }`}
              >
                <Activity size={13} />
                Swarm Graph
              </button>
              <button
                onClick={() => setViewMode("tree")}
                className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                  viewMode === "tree"
                    ? "bg-surface text-fg shadow-sm font-bold"
                    : "text-fg-muted hover:text-fg"
                }`}
              >
                <GitBranch size={13} />
                Execution DAG
              </button>
              <button
                onClick={() => setViewMode("table")}
                className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                  viewMode === "table"
                    ? "bg-surface text-fg shadow-sm font-bold"
                    : "text-fg-muted hover:text-fg"
                }`}
              >
                <TableIcon size={13} />
                Flat Table
              </button>
            </div>

            <Button variant="outline" size="sm" onClick={refresh} disabled={busy}>
              <RefreshCw size={14} className={busy ? "animate-spin text-brand" : ""} />
              {busy ? "Auditing..." : "Refresh"}
            </Button>
          </div>
        }
      />

      {/* Filter and Summary Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-2.5 rounded-xl border border-line bg-surface px-3.5 py-2.5 w-full max-w-md shadow-card">
          <Search size={16} className="text-fg-subtle" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by process name, PID, or image path..."
            className="flex-1 bg-transparent text-xs text-fg outline-none placeholder:text-fg-subtle font-mono font-medium"
          />
        </div>
        <div className="flex items-center gap-3 text-xs text-fg-muted font-mono">
          <span>{dagSnapshot?.total_nodes ?? list.length} Active Nodes</span>
          <span>•</span>
          <span className="text-violet font-bold flex items-center gap-1">
            <Bot size={13} />
            {list.filter((p) => p.is_agent_context).length} AI Agent Contexts
          </span>
          <span>•</span>
          <span className="text-danger font-bold">
            {dagSnapshot?.active_alerts ?? 0} Alerts
          </span>
        </div>
      </div>

      {/* Main Split: Process DAG/Table & Detail Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 p-0 overflow-hidden">
          <div className="max-h-[620px] overflow-y-auto">
            {viewMode === "swarm" ? (
              <div className="p-2">
                <SwarmGraphCanvas
                  nodesData={list}
                  treesData={dagSnapshot?.trees ?? []}
                  selectedPid={inspectPid}
                  onSelectPid={handleInspect}
                  onKillPid={handleKill}
                />
              </div>
            ) : viewMode === "tree" ? (
              <div className="p-4 space-y-1">
                {dagSnapshot?.trees && dagSnapshot.trees.length > 0 ? (
                  dagSnapshot.trees.map((t) => (
                    <TreeNode
                      key={t.pid}
                      node={t}
                      selectedPid={inspectPid}
                      onSelect={handleInspect}
                    />
                  ))
                ) : (
                  <div className="py-20 text-center text-xs text-fg-subtle">
                    Loading Process Execution DAG hierarchy...
                  </div>
                )}
              </div>
            ) : (
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-surface-2 text-fg-muted border-b border-line sticky top-0">
                  <tr>
                    <th className="px-4 py-3 font-semibold">PID / PPID</th>
                    <th className="px-4 py-3 font-semibold">Process</th>
                    <th className="px-4 py-3 font-semibold">Context / MITRE</th>
                    <th className="px-4 py-3 font-semibold">Risk</th>
                    <th className="px-4 py-3 font-semibold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {filtered.map((p) => (
                    <tr
                      key={p.pid}
                      className={`hover:bg-surface-2 cursor-pointer transition-colors ${
                        inspectPid === p.pid ? "bg-brand-soft" : ""
                      }`}
                      onClick={() => handleInspect(p.pid)}
                    >
                      <td className="px-4 py-3 text-fg-muted">
                        {p.pid} <span className="text-[10px] text-fg-subtle">({p.ppid})</span>
                      </td>
                      <td className="px-4 py-3 text-fg font-sans font-bold">
                        <div className="truncate max-w-[180px]" title={p.path}>
                          {p.name}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap items-center gap-1">
                          {p.is_agent_context && (
                            <span className="inline-flex items-center gap-1 rounded bg-violet-soft border border-violet/30 px-1.5 py-0.5 text-[9px] font-sans font-bold text-violet">
                              <Bot size={10} />
                              {p.agent_label || "AI Agent"}
                            </span>
                          )}
                          {p.mitre_techniques?.map((t) => (
                            <span
                              key={t}
                              className="rounded bg-danger-soft border border-danger/30 px-1 text-[9px] font-mono font-bold text-danger"
                            >
                              {t}
                            </span>
                          ))}
                          {!p.is_agent_context && (!p.mitre_techniques || p.mitre_techniques.length === 0) && (
                            <span className="text-[11px] text-fg-subtle font-sans">
                              {p.is_signed ? "Standard" : "Unsigned"}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <Badge
                          color={
                            p.risk_score >= 70
                              ? "danger"
                              : p.risk_score >= 35
                              ? "warn"
                              : "ok"
                          }
                        >
                          {p.risk_score}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => handleInspect(p.pid)}
                            className="rounded-lg p-1.5 text-fg-muted hover:text-fg hover:bg-surface-2 transition-colors"
                            title="Inspect Memory"
                          >
                            <Eye size={15} />
                          </button>
                          <button
                            onClick={() => handleKill(p.pid)}
                            className="rounded-lg p-1.5 text-fg-muted hover:text-danger hover:bg-danger-soft transition-colors"
                            title="Terminate Process"
                          >
                            <Skull size={15} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </Card>

        {/* Process Detail Inspector Panel */}
        <Card className="p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-line pb-3">
            <div className="text-sm font-bold text-fg">Forensic Lineage Details</div>
            {inspectPid && (
              <span className="font-mono text-xs font-bold text-brand">PID {inspectPid}</span>
            )}
          </div>

          {inspectPid && selectedProcess ? (
            <div className="space-y-4 text-xs font-mono">
              <div className="space-y-1.5 bg-surface-2 p-3 rounded-xl border border-line">
                <div className="font-bold text-fg font-sans text-sm truncate">
                  {selectedProcess.name}
                </div>
                <div className="text-[11px] text-fg-muted break-all">
                  {selectedProcess.path}
                </div>
                <div className="flex items-center gap-2 pt-1 font-sans text-[11px]">
                  <span className="text-fg-muted">Parent PID:</span>
                  <span className="font-mono font-bold text-fg">{selectedProcess.ppid}</span>
                </div>
              </div>

              {/* AI Agent Context Card */}
              {selectedProcess.is_agent_context && (
                <div className="rounded-xl bg-violet-soft p-3 border border-violet/30 space-y-1">
                  <div className="font-bold text-violet font-sans flex items-center gap-1.5">
                    <Bot size={14} />
                    <span>{selectedProcess.agent_label || "AI Agent"} Context</span>
                  </div>
                  <p className="text-[11px] text-fg-muted font-sans leading-relaxed">
                    This process is operating within an AI coding agent or local LLM runner tree. Tool calls and network egress are continuously audited.
                  </p>
                </div>
              )}

              {/* MITRE ATT&CK & Risk Factors */}
              {selectedProcess.mitre_techniques && selectedProcess.mitre_techniques.length > 0 && (
                <div className="space-y-1.5">
                  <div className="font-sans font-bold text-fg text-[11px] flex items-center gap-1">
                    <ShieldAlert size={14} className="text-danger" />
                    <span>MITRE ATT&CK Mapping</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {selectedProcess.mitre_techniques.map((t) => (
                      <span
                        key={t}
                        className="rounded-md bg-danger-soft border border-danger/30 px-1.5 py-0.5 text-[10px] font-bold text-danger"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selectedProcess.risk_factors && selectedProcess.risk_factors.length > 0 && (
                <div className="space-y-1 font-sans text-[11px] text-fg-muted bg-brand-soft p-2.5 rounded-xl border border-brand/30">
                  <div className="font-bold text-warn">Lineage Risk Factors:</div>
                  <ul className="list-disc list-inside space-y-0.5">
                    {selectedProcess.risk_factors.map((rf, i) => (
                      <li key={i}>{rf}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* In-Memory Scan Findings */}
              {inspecting ? (
                <div className="flex items-center gap-2 text-xs text-fg-muted py-6 justify-center">
                  <Spinner />
                  <span>Auditing virtual memory pages & thread contexts...</span>
                </div>
              ) : inspectThreats && inspectThreats.length > 0 ? (
                <div className="space-y-2.5">
                  <div className="flex items-center gap-1.5 text-xs text-danger font-bold font-sans">
                    <AlertTriangle size={15} />
                    <span>In-Memory Injections Detected</span>
                  </div>
                  {inspectThreats.map((t, idx) => (
                    <div key={idx} className="rounded-xl bg-danger-soft p-2.5 border border-danger/30 text-[11px]">
                      <div className="font-bold text-danger">{t.names}</div>
                      <div className="mt-0.5 text-fg-muted break-all">{t.path}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="flex items-center gap-2 text-ok font-sans font-semibold text-xs py-2">
                  <ShieldCheck size={16} />
                  <span>No unbacked code or hook tampering detected.</span>
                </div>
              )}

              <Button
                variant="danger"
                size="sm"
                className="w-full mt-2"
                onClick={() => handleKill(inspectPid)}
              >
                <Skull size={14} /> Terminate Process
              </Button>
            </div>
          ) : (
            <div className="text-center py-24 text-xs text-fg-subtle font-sans">
              Select a process or DAG node to view parent-child lineage, MITRE techniques, and forensic details.
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
