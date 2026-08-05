import { useEffect, useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { api, type WhitelistRow } from "@/lib/api";
import { Badge, Button, Card, SectionTitle } from "@/components/ui";

export default function Whitelist() {
  const [rows, setRows] = useState<WhitelistRow[]>([]);
  const [path, setPath] = useState("");
  const [label, setLabel] = useState("");

  const load = () => api.whitelist().then(setRows).catch(() => {});
  useEffect(() => {
    load();
  }, []);

  const add = async () => {
    if (!path.trim()) return;
    await api.addWhitelist(path.trim(), label.trim());
    setPath("");
    setLabel("");
    load();
  };
  const remove = async (value: string) => {
    await api.removeWhitelist(value);
    load();
  };

  return (
    <div>
      <SectionTitle
        title="Whitelist"
        subtitle="Trust your own projects so they never trip a false positive. Checked before any engine runs."
      />

      <Card className="mb-5">
        <h2 className="mb-3 text-base font-semibold">Add a trusted project</h2>
        <div className="flex gap-3">
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="/home/you/Projects/myapp"
            className="flex-1 rounded-xl border border-border bg-black/30 px-3 py-2.5 text-sm outline-none placeholder:text-muted"
          />
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="label (optional)"
            className="w-48 rounded-xl border border-border bg-black/30 px-3 py-2.5 text-sm outline-none placeholder:text-muted"
          />
          <Button variant="primary" onClick={add}>
            <Plus size={16} /> Add
          </Button>
        </div>
      </Card>

      <Card>
        {rows.length === 0 ? (
          <p className="text-sm text-muted">Whitelist is empty.</p>
        ) : (
          <div className="space-y-1">
            {rows.map((r, i) => (
              <div
                key={i}
                className="flex items-center justify-between rounded-lg px-3 py-2.5 text-sm hover:bg-white/5"
              >
                <div className="flex items-center gap-3">
                  <Badge color={r.kind === "path" ? "accent" : "muted"}>{r.kind}</Badge>
                  <div>
                    <div className="font-medium">{r.label || "—"}</div>
                    <div className="max-w-[420px] truncate text-xs text-muted" title={r.value}>
                      {r.value}
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => remove(r.value)}
                  className="rounded-lg p-2 text-muted hover:bg-danger/15 hover:text-danger"
                >
                  <Trash2 size={16} />
                </button>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
