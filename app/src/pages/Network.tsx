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
        subtitle="Open connections and listening ports, checked against your IP blocklist and the Feodo Tracker C2 feed when you scan."
        action={
          <Button variant="outline" size="sm" onClick={load} disabled={busy}>
            {busy ? <Spinner /> : <NetIcon size={14} />} Refresh Connections
          </Button>
        }
      />

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card className="p-5">
          <span className="text-xs text-fg-muted font-medium block">Listening Ports</span>
          <span className="text-2xl font-extrabold text-fg tab-nums mt-1 block">{rep?.listening ?? 0}</span>
          <span className="text-[11px] text-fg-subtle">Bound local endpoints</span>
        </Card>
        <Card className="p-5">
          <span className="text-xs text-fg-muted font-medium block">Established Sockets</span>
          <span className="text-2xl font-extrabold text-fg tab-nums mt-1 block">{rep?.established ?? 0}</span>
          <span className="text-[11px] text-fg-subtle">Active remote connections</span>
        </Card>
        <Card className="p-5">
          <span className="text-xs text-fg-muted font-medium block">Intrusion Alerts</span>
          <span className={`text-2xl font-extrabold tab-nums mt-1 block ${rep && rep.findings.length > 0 ? "text-danger" : "text-ok"}`}>
            {rep?.findings.length ?? 0}
          </span>
          <span className="text-[11px] text-fg-subtle">C2 & reconnaissance hits</span>
        </Card>
      </div>

      {/* Clean Tabs Header */}
      <div className="flex items-center gap-2 border-b border-line pb-3">
        <button
          onClick={() => setActiveTab("connections")}
          className={`px-4 py-2 text-xs font-bold rounded-xl transition-all duration-150 ${
            activeTab === "connections"
              ? "bg-surface text-fg shadow-sm"
              : "text-fg-muted hover:text-fg hover:bg-surface-2"
          }`}
        >
          Active Connections ({rep?.connections.length ?? 0})
        </button>
        <button
          onClick={() => setActiveTab("findings")}
          className={`px-4 py-2 text-xs font-bold rounded-xl transition-all duration-150 ${
            activeTab === "findings"
              ? "bg-surface text-fg shadow-sm"
              : "text-fg-muted hover:text-fg hover:bg-surface-2"
          }`}
        >
          Intrusion Alerts ({rep?.findings.length ?? 0})
        </button>
        <button
          onClick={() => setActiveTab("plugins")}
          className={`px-4 py-2 text-xs font-bold rounded-xl transition-all duration-150 ${
            activeTab === "plugins"
              ? "bg-surface text-fg shadow-sm"
              : "text-fg-muted hover:text-fg hover:bg-surface-2"
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
              <Search size={16} className="text-fg-subtle shrink-0" />
              <input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Filter by local address, remote IP, port, or state..."
                className="flex-1 bg-transparent text-xs text-fg outline-none placeholder:text-fg-subtle font-medium"
              />
              {filter && (
                <button
                  onClick={() => setFilter("")}
                  className="text-xs text-fg-muted hover:text-fg font-medium"
                >
                  Clear
                </button>
              )}
            </div>
          </Card>

          <Card className="p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-surface-2 text-fg-muted border-b border-line">
                  <tr>
                    <th className="px-5 py-3 font-semibold">Proto</th>
                    <th className="px-5 py-3 font-semibold">Local Address</th>
                    <th className="px-5 py-3 font-semibold">Remote Address</th>
                    <th className="px-5 py-3 font-semibold">State</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {filteredConns.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="px-5 py-10 text-center text-fg-muted font-sans">
                        No connections matching filter.
                      </td>
                    </tr>
                  ) : (
                    filteredConns.map((c, i) => (
                      <tr key={i} className="hover:bg-surface-2 transition-colors">
                        <td className="px-5 py-3 uppercase font-bold text-fg">{c.protocol}</td>
                        <td className="px-5 py-3 text-fg font-medium">{c.local}</td>
                        <td className="px-5 py-3 text-fg-muted">{c.remote || "—"}</td>
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
          <div className="px-6 py-4 border-b border-line bg-surface">
            <h2 className="text-sm font-bold text-fg">Network Intrusion Indicators</h2>
          </div>
          {(!rep || rep.findings.length === 0) ? (
            <div className="p-16 text-center space-y-2">
              <CheckCircle2 size={36} className="text-ok mx-auto opacity-80" />
              <div className="text-sm font-bold text-fg">No Malicious Connections Detected</div>
              <p className="text-xs text-fg-muted max-w-sm mx-auto">
                Zero known C2 botnet endpoints, backdoor shells, or LOLBin egress sockets detected.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-line">
              {rep.findings.map((f, i) => (
                <div key={i} className="p-5 flex items-start justify-between gap-4">
                  <div>
                    <div className="text-sm font-bold text-danger">{f.names}</div>
                    <div className="mt-1 text-xs text-fg-muted font-mono">{f.path.toString()}</div>
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
          <div className="px-6 py-4 border-b border-line bg-surface">
            <h2 className="text-sm font-bold text-fg">Installed Network Plugins</h2>
          </div>
          {plugins.length === 0 ? (
            <div className="p-12 text-center text-xs text-fg-muted">
              No additional firewall plugins installed in config directory.
            </div>
          ) : (
            <div className="divide-y divide-line">
              {plugins.map((p, i) => (
                <div key={i} className="p-5 flex items-center justify-between">
                  <div>
                    <div className="text-sm font-bold text-fg">{p.name}</div>
                    <div className="text-xs text-fg-muted mt-0.5">Permissions: {p.permissions.join(", ") || "None"}</div>
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
