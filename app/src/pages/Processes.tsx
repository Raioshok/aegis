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
} from "lucide-react";
import { api, type ProcessItem, type ThreatRow } from "@/lib/api";
import { Badge, Button, Card, SectionTitle, Spinner } from "@/components/ui";

export default function Processes() {
  const [list, setList] = useState<ProcessItem[]>([]);
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState(false);
  const [inspectPid, setInspectPid] = useState<number | null>(null);
  const [inspecting, setInspecting] = useState(false);
  const [inspectThreats, setInspectThreats] = useState<ThreatRow[] | null>(null);

  const refresh = async () => {
    setBusy(true);
    try {
      const items = await api.listProcesses();
      setList(items);
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

  const filtered = list.filter(
    (p) =>
      p.name.toLowerCase().includes(filter.toLowerCase()) ||
      p.pid.toString().includes(filter) ||
      p.path.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="space-y-6 max-w-6xl">
      <SectionTitle
        title="Process Inspector"
        subtitle="Forensic process auditing: checks Authenticode signatures, thread hijacking, RIP context, and unbacked memory pages."
        action={
          <Button variant="outline" size="sm" onClick={refresh} disabled={busy}>
            <RefreshCw size={14} className={busy ? "animate-spin text-[#FF7222]" : ""} />
            {busy ? "Querying..." : "Refresh"}
          </Button>
        }
      />

      {/* Filter Bar */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2.5 rounded-xl border border-[#EAEFF5] bg-white px-3.5 py-2.5 w-full max-w-md shadow-card">
          <Search size={16} className="text-[#94A3B8]" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by process name, PID, or image path..."
            className="flex-1 bg-transparent text-xs text-[#1E293B] outline-none placeholder:text-[#94A3B8] font-mono font-medium"
          />
        </div>
        <div className="text-xs text-[#64748B] font-mono">
          Showing {filtered.length} of {list.length} processes
        </div>
      </div>

      {/* Main Split: Process Table & Detail Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 p-0 overflow-hidden">
          <div className="max-h-[600px] overflow-y-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#F8FAFC] text-[#64748B] border-b border-[#EAEFF5] sticky top-0">
                <tr>
                  <th className="px-4 py-3 font-semibold">PID</th>
                  <th className="px-4 py-3 font-semibold">Process</th>
                  <th className="px-4 py-3 font-semibold">Signature</th>
                  <th className="px-4 py-3 font-semibold">Status</th>
                  <th className="px-4 py-3 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#EAEFF5]">
                {filtered.map((p) => (
                  <tr
                    key={p.pid}
                    className={`hover:bg-[#F8FAFC] cursor-pointer transition-colors ${
                      inspectPid === p.pid ? "bg-[#FFF4EC]" : ""
                    }`}
                    onClick={() => handleInspect(p.pid)}
                  >
                    <td className="px-4 py-3 text-[#64748B]">{p.pid}</td>
                    <td className="px-4 py-3 text-[#1E293B] font-sans font-bold">
                      <div className="truncate max-w-[200px]" title={p.path}>
                        {p.name}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {p.is_signed ? (
                        <span className="text-[#059669] font-sans font-semibold text-[11px] flex items-center gap-1">
                          <CheckCircle2 size={12} /> Signed
                        </span>
                      ) : (
                        <span className="text-[#94A3B8] font-sans text-[11px]">Unsigned</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {p.is_suspicious ? (
                        <Badge color="danger">Threat</Badge>
                      ) : (
                        <Badge color="ok">Protected</Badge>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => handleInspect(p.pid)}
                          className="rounded-lg p-1.5 text-[#64748B] hover:text-[#1E293B] hover:bg-[#F1F5F9] transition-colors"
                          title="Inspect Memory"
                        >
                          <Eye size={15} />
                        </button>
                        <button
                          onClick={() => handleKill(p.pid)}
                          className="rounded-lg p-1.5 text-[#64748B] hover:text-[#DC2626] hover:bg-[#FEF2F2] transition-colors"
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
          </div>
        </Card>

        {/* Process Detail Inspector Panel */}
        <Card className="p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-[#EAEFF5] pb-3">
            <div className="text-sm font-bold text-[#1E293B]">Forensic Details</div>
            {inspectPid && (
              <span className="font-mono text-xs font-bold text-[#FF7222]">PID {inspectPid}</span>
            )}
          </div>

          {inspectPid ? (
            <div className="space-y-4">
              {inspecting ? (
                <div className="flex items-center gap-2 text-xs text-[#64748B] py-10 justify-center">
                  <Spinner />
                  <span>Auditing memory pages & thread contexts...</span>
                </div>
              ) : inspectThreats && inspectThreats.length > 0 ? (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-xs text-[#DC2626] font-bold">
                    <AlertTriangle size={16} />
                    <span>Memory Anomalies Flagged</span>
                  </div>
                  {inspectThreats.map((t, idx) => (
                    <div key={idx} className="rounded-xl bg-[#FEF2F2] p-3 border border-[#FECACA] text-xs font-mono">
                      <div className="font-bold text-[#DC2626]">{t.names}</div>
                      <div className="mt-1 text-[11px] text-[#64748B] break-all">{t.path}</div>
                    </div>
                  ))}
                  <Button
                    variant="danger"
                    size="sm"
                    className="w-full"
                    onClick={() => handleKill(inspectPid)}
                  >
                    <Skull size={14} /> Terminate Injected Process
                  </Button>
                </div>
              ) : (
                <div className="space-y-3 text-xs">
                  <div className="flex items-center gap-2 text-[#059669] font-bold">
                    <ShieldCheck size={18} />
                    <span>No Injections or Thread Hooks Found</span>
                  </div>
                  <p className="text-[11px] text-[#64748B] leading-relaxed">
                    All threads have verified start addresses inside legitimate disk-backed DLLs.
                    No W+X private heap regions or AMSI/ETW patches detected.
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full"
                    onClick={() => handleKill(inspectPid)}
                  >
                    Kill Process
                  </Button>
                </div>
              )}
            </div>
          ) : (
            <div className="text-center py-20 text-xs text-[#94A3B8]">
              Select a process from the table to perform live in-memory inspection.
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
