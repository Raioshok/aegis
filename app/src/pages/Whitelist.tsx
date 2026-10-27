import { useEffect, useState } from "react";
import { Plus, Trash2, FolderCheck, Hash, ShieldCheck } from "lucide-react";
import { api, type WhitelistRow } from "@/lib/api";
import { Badge, Button, Card, SectionTitle } from "@/components/ui";

export default function Whitelist() {
  const [rows, setRows] = useState<WhitelistRow[]>([]);
  const [path, setPath] = useState("");
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () => api.whitelist().then(setRows).catch(() => {});
  useEffect(() => {
    load();
  }, []);

  const add = async () => {
    if (!path.trim()) return;
    setBusy(true);
    try {
      await api.addWhitelist(path.trim(), label.trim());
      setPath("");
      setLabel("");
      load();
    } finally {
      setBusy(false);
    }
  };

  const remove = async (value: string) => {
    await api.removeWhitelist(value);
    load();
  };

  return (
    <div className="space-y-6 max-w-6xl">
      <SectionTitle
        title="Trusted Projects & Allowlist"
        subtitle="Whitelisted directory trees and verified SHA-256 hashes bypass heuristic alarms. Known-bad hashes always override paths."
      />

      {/* Add Rule Form */}
      <Card className="p-6">
        <h2 className="text-sm font-bold text-fg mb-3">Add Allowlist Rule</h2>
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="Absolute folder path (e.g. C:\Projects\MyRepo or /home/user/work)"
            className="flex-1 rounded-xl border border-line bg-surface-2 px-4 py-2.5 text-xs text-fg outline-none placeholder:text-fg-subtle focus:border-brand font-mono font-medium"
          />
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="Label (optional)"
            className="sm:w-48 rounded-xl border border-line bg-surface-2 px-4 py-2.5 text-xs text-fg outline-none placeholder:text-fg-subtle focus:border-brand font-medium"
          />
          <Button variant="primary" size="md" onClick={add} disabled={busy || !path.trim()}>
            <Plus size={16} /> Add Rule
          </Button>
        </div>
      </Card>

      {/* Rules Table */}
      <Card className="p-0 overflow-hidden">
        <div className="px-6 py-4 border-b border-line flex items-center justify-between bg-surface">
          <span className="text-sm font-bold text-fg">Active Trusted Entries</span>
          <Badge color={rows.length > 0 ? "ok" : "neutral"}>{rows.length} Rules</Badge>
        </div>

        {rows.length === 0 ? (
          <div className="p-16 text-center text-xs text-fg-muted space-y-2">
            <ShieldCheck size={36} className="text-ok mx-auto opacity-70" />
            <div className="text-sm font-bold text-fg">No allowlist rules defined</div>
            <p className="text-xs text-fg-muted max-w-sm mx-auto">
              Add your development directories above to avoid false positives during builds.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-line">
            {rows.map((r, i) => (
              <div
                key={i}
                className="p-4 flex items-center justify-between hover:bg-surface-2 transition-colors"
              >
                <div className="min-w-0 flex-1 flex items-center gap-3.5">
                  <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-surface-2 border border-line text-fg-muted shrink-0">
                    {r.kind === "path" ? <FolderCheck size={18} className="text-ok" /> : <Hash size={18} className="text-info" />}
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-xs text-fg">{r.label || "Untilted Rule"}</span>
                      <Badge color={r.kind === "path" ? "ok" : "blue"}>{r.kind}</Badge>
                      {r.recursive && <span className="text-[10px] text-fg-subtle font-mono">(recursive)</span>}
                    </div>
                    <div className="text-xs font-mono text-fg-muted truncate mt-0.5" title={r.value}>
                      {r.value}
                    </div>
                  </div>
                </div>

                <Button variant="ghost" size="sm" onClick={() => remove(r.value)}>
                  <Trash2 size={15} className="text-fg-subtle hover:text-danger" />
                </Button>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
