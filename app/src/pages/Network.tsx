import { useEffect, useState } from "react";
import { ShieldAlert, Puzzle, Network as NetIcon } from "lucide-react";
import {
  api,
  severityColor,
  type NetworkReport,
  type PluginRow,
} from "@/lib/api";
import { Badge, Button, Card, SectionTitle, Spinner, StatCard } from "@/components/ui";

export default function Network() {
  const [rep, setRep] = useState<NetworkReport | null>(null);
  const [plugins, setPlugins] = useState<PluginRow[]>([]);
  const [busy, setBusy] = useState(false);

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

  return (
    <div>
      <SectionTitle
        title="Network & Firewall"
        subtitle="Live connection IDS: C2 / backdoor / Tor indicators and exposed listeners."
        action={
          <Button variant="primary" onClick={load} disabled={busy}>
            {busy ? <Spinner /> : <NetIcon size={16} />} Rescan
          </Button>
        }
      />

      <div className="mb-5 grid grid-cols-2 gap-4 lg:grid-cols-3">
        <StatCard label="Listening sockets" value={rep?.listening ?? 0} icon={<NetIcon size={20} />} />
        <StatCard label="Established" value={rep?.established ?? 0} />
        <StatCard
          label="Network findings"
          value={rep?.findings.length ?? 0}
          accent={rep && rep.findings.length > 0 ? "text-warn" : "text-ok"}
          icon={<ShieldAlert size={20} />}
        />
      </div>

      <Card className="mb-5">
        <h2 className="mb-3 text-base font-semibold">Intrusion findings</h2>
        {!rep ? (
          <p className="text-sm text-muted">Scanning…</p>
        ) : rep.findings.length === 0 ? (
          <p className="text-sm text-ok">✓ no suspicious network activity</p>
        ) : (
          <div className="space-y-2">
            {rep.findings.map((f, i) => (
              <div key={i} className="rounded-lg border border-border bg-black/20 px-3 py-2">
                <div className="flex items-center gap-2">
                  <span className={`text-sm font-medium ${severityColor(f.severity)}`}>
                    [{f.severity_label}]
                  </span>
                  <span className="text-sm">{f.names}</span>
                </div>
                <div className="mt-0.5 text-xs text-muted">{f.path.toString()}</div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card>
          <h2 className="mb-3 text-base font-semibold">Active connections</h2>
          <div className="max-h-[300px] overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-black/40 text-left text-muted backdrop-blur">
                <tr>
                  <th className="px-2 py-1.5 font-medium">Proto</th>
                  <th className="px-2 py-1.5 font-medium">Local</th>
                  <th className="px-2 py-1.5 font-medium">Remote</th>
                  <th className="px-2 py-1.5 font-medium">State</th>
                </tr>
              </thead>
              <tbody>
                {(rep?.connections ?? []).map((c, i) => (
                  <tr key={i} className="border-t border-border">
                    <td className="px-2 py-1.5 text-muted">{c.protocol}</td>
                    <td className="px-2 py-1.5">{c.local}</td>
                    <td className="px-2 py-1.5 text-muted">{c.remote}</td>
                    <td className="px-2 py-1.5">
                      <Badge color={c.state === "LISTEN" ? "accent" : "muted"}>{c.state}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <Card>
          <h2 className="mb-3 flex items-center gap-2 text-base font-semibold">
            <Puzzle size={18} className="text-accent" /> Plugins
          </h2>
          {plugins.length === 0 ? (
            <p className="text-sm text-muted">
              No plugins installed. Drop signed plugins in{" "}
              <code className="text-xs">~/.config/aegis/plugins</code>.
            </p>
          ) : (
            <div className="space-y-2">
              {plugins.map((p, i) => (
                <div key={i} className="flex items-center justify-between rounded-lg px-3 py-2">
                  <span className="text-sm">{p.name}</span>
                  <Badge color={p.trusted ? "ok" : "danger"}>{p.status}</Badge>
                </div>
              ))}
            </div>
          )}
          <p className="mt-3 text-xs text-muted">
            Plugins run only when ed25519-signed by a trusted key.
          </p>
        </Card>
      </div>
    </div>
  );
}
