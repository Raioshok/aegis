import { useEffect, useState } from "react";
import { ShieldAlert, Network as NetIcon, Search, CheckCircle2 } from "lucide-react";
import {
  api,
  severityColor,
  type NetworkReport,
  type PluginRow,
} from "@/lib/api";
import { Badge, Button, Card, SectionTitle, Spinner } from "@/components/ui";

export default function Network() {
  const [rep, setRep] = useState<NetworkReport | null>(null);
  const [plugins, setPlugins] = useState<PluginRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState("");
  const [activeTab, setActiveTab] = useState<"connections" | "findings" | "plugins">("connections");

  const load = async () => {
    setBusy(true);
    try {
      setRep(await api.networkScan());
      setPlugins(await api.pluginsList());
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const filteredConns = (rep?.connections ?? []).filter(
    (c) =>
      c.local.includes(filter) ||
      c.remote.includes(filter) ||
      c.state.toLowerCase().includes(filter.toLowerCase()) ||
      c.protocol.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="space-y-6 max-w-6xl">
      <SectionTitle
        title="Network & Host Firewall"
        subtitle="Real-time socket inspection, LOLBin egress defense, and multi-port reconnaissance detection."
        action={
          <Button variant="outline" size="sm" onClick={load} disabled={busy}>
            {busy ? <Spinner /> : <NetIcon size={14} />} Refresh Connections
          </Button>
        }
      />

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card className="p-5">
          <span className="text-xs text-[#64748B] font-medium block">Listening Ports</span>
          <span className="text-2xl font-extrabold text-[#1E293B] tab-nums mt-1 block">{rep?.listening ?? 0}</span>
          <span className="text-[11px] text-[#94A3B8]">Bound local endpoints</span>
        </Card>
        <Card className="p-5">
          <span className="text-xs text-[#64748B] font-medium block">Established Sockets</span>
          <span className="text-2xl font-extrabold text-[#1E293B] tab-nums mt-1 block">{rep?.established ?? 0}</span>
          <span className="text-[11px] text-[#94A3B8]">Active remote connections</span>
        </Card>
        <Card className="p-5">
          <span className="text-xs text-[#64748B] font-medium block">Intrusion Alerts</span>
          <span className={`text-2xl font-extrabold tab-nums mt-1 block ${rep && rep.findings.length > 0 ? "text-[#DC2626]" : "text-[#059669]"}`}>
            {rep?.findings.length ?? 0}
          </span>
          <span className="text-[11px] text-[#94A3B8]">C2 & reconnaissance hits</span>
        </Card>
      </div>

      {/* Clean Tabs Header */}
      <div className="flex items-center gap-2 border-b border-[#EAEFF5] pb-3">
        <button
          onClick={() => setActiveTab("connections")}
          className={`px-4 py-2 text-xs font-bold rounded-xl transition-all duration-150 ${
            activeTab === "connections"
              ? "bg-[#1E293B] text-white shadow-sm"
              : "text-[#64748B] hover:text-[#1E293B] hover:bg-[#F1F5F9]"
          }`}
        >
          Active Connections ({rep?.connections.length ?? 0})
        </button>
        <button
          onClick={() => setActiveTab("findings")}
          className={`px-4 py-2 text-xs font-bold rounded-xl transition-all duration-150 ${
            activeTab === "findings"
              ? "bg-[#1E293B] text-white shadow-sm"
              : "text-[#64748B] hover:text-[#1E293B] hover:bg-[#F1F5F9]"
          }`}
        >
          Intrusion Alerts ({rep?.findings.length ?? 0})
        </button>
        <button
          onClick={() => setActiveTab("plugins")}
          className={`px-4 py-2 text-xs font-bold rounded-xl transition-all duration-150 ${
            activeTab === "plugins"
              ? "bg-[#1E293B] text-white shadow-sm"
              : "text-[#64748B] hover:text-[#1E293B] hover:bg-[#F1F5F9]"
          }`}
        >
          Network Plugins ({plugins.length})
        </button>
      </div>

      {/* Active Tab Views */}
      {activeTab === "connections" && (
        <div className="space-y-4">
          <Card className="p-3.5">
            <div className="flex items-center gap-2.5 px-2">
              <Search size={16} className="text-[#94A3B8] shrink-0" />
              <input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Filter by local address, remote IP, port, or state..."
                className="flex-1 bg-transparent text-xs text-[#1E293B] outline-none placeholder:text-[#94A3B8] font-medium"
              />
              {filter && (
                <button
                  onClick={() => setFilter("")}
                  className="text-xs text-[#64748B] hover:text-[#1E293B] font-medium"
                >
                  Clear
                </button>
              )}
            </div>
          </Card>

          <Card className="p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#F8FAFC] text-[#64748B] border-b border-[#EAEFF5]">
                  <tr>
                    <th className="px-5 py-3 font-semibold">Proto</th>
                    <th className="px-5 py-3 font-semibold">Local Address</th>
                    <th className="px-5 py-3 font-semibold">Remote Address</th>
                    <th className="px-5 py-3 font-semibold">State</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#EAEFF5]">
                  {filteredConns.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="px-5 py-10 text-center text-[#64748B] font-sans">
                        No connections matching filter.
                      </td>
                    </tr>
                  ) : (
                    filteredConns.map((c, i) => (
                      <tr key={i} className="hover:bg-[#F8FAFC] transition-colors">
                        <td className="px-5 py-3 uppercase font-bold text-[#1E293B]">{c.protocol}</td>
                        <td className="px-5 py-3 text-[#1E293B] font-medium">{c.local}</td>
                        <td className="px-5 py-3 text-[#64748B]">{c.remote || "—"}</td>
                        <td className="px-5 py-3">
                          <Badge
                            color={
                              c.state === "ESTABLISHED"
                                ? "ok"
                                : c.state === "LISTEN"
                                ? "blue"
                                : "muted"
                            }
                          >
                            {c.state}
                          </Badge>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      {activeTab === "findings" && (
        <Card className="p-0 overflow-hidden">
          <div className="px-6 py-4 border-b border-[#EAEFF5] bg-white">
            <h2 className="text-sm font-bold text-[#1E293B]">Network Intrusion Indicators</h2>
          </div>
          {(!rep || rep.findings.length === 0) ? (
            <div className="p-16 text-center space-y-2">
              <CheckCircle2 size={36} className="text-[#10B981] mx-auto opacity-80" />
              <div className="text-sm font-bold text-[#1E293B]">No Malicious Connections Detected</div>
              <p className="text-xs text-[#64748B] max-w-sm mx-auto">
                Zero known C2 botnet endpoints, backdoor shells, or LOLBin egress sockets detected.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-[#EAEFF5]">
              {rep.findings.map((f, i) => (
                <div key={i} className="p-5 flex items-start justify-between gap-4">
                  <div>
                    <div className="text-sm font-bold text-[#DC2626]">{f.names}</div>
                    <div className="mt-1 text-xs text-[#475569] font-mono">{f.path.toString()}</div>
                  </div>
                  <Badge color="danger">[{f.severity_label}]</Badge>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {activeTab === "plugins" && (
        <Card className="p-0 overflow-hidden">
          <div className="px-6 py-4 border-b border-[#EAEFF5] bg-white">
            <h2 className="text-sm font-bold text-[#1E293B]">Installed Network Plugins</h2>
          </div>
          {plugins.length === 0 ? (
            <div className="p-12 text-center text-xs text-[#64748B]">
              No additional firewall plugins installed in config directory.
            </div>
          ) : (
            <div className="divide-y divide-[#EAEFF5]">
              {plugins.map((p, i) => (
                <div key={i} className="p-5 flex items-center justify-between">
                  <div>
                    <div className="text-sm font-bold text-[#1E293B]">{p.name}</div>
                    <div className="text-xs text-[#64748B] mt-0.5">Permissions: {p.permissions.join(", ") || "None"}</div>
                  </div>
                  <Badge color={p.trusted ? "ok" : "warn"}>{p.trusted ? "Verified" : "Untrusted"}</Badge>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
