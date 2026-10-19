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
        <h2 className="text-sm font-bold text-[#1E293B] mb-3">Add Allowlist Rule</h2>
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="Absolute folder path (e.g. C:\Projects\MyRepo or /home/user/work)"
            className="flex-1 rounded-xl border border-[#EAEFF5] bg-[#F8FAFC] px-4 py-2.5 text-xs text-[#1E293B] outline-none placeholder:text-[#94A3B8] focus:border-[#FF7222] font-mono font-medium"
          />
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="Label (optional)"
            className="sm:w-48 rounded-xl border border-[#EAEFF5] bg-[#F8FAFC] px-4 py-2.5 text-xs text-[#1E293B] outline-none placeholder:text-[#94A3B8] focus:border-[#FF7222] font-medium"
          />
          <Button variant="primary" size="md" onClick={add} disabled={busy || !path.trim()}>
            <Plus size={16} /> Add Rule
          </Button>
        </div>
      </Card>

      {/* Rules Table */}
      <Card className="p-0 overflow-hidden">
        <div className="px-6 py-4 border-b border-[#EAEFF5] flex items-center justify-between bg-white">
          <span className="text-sm font-bold text-[#1E293B]">Active Trusted Entries</span>
          <Badge color={rows.length > 0 ? "ok" : "neutral"}>{rows.length} Rules</Badge>
        </div>

        {rows.length === 0 ? (
          <div className="p-16 text-center text-xs text-[#64748B] space-y-2">
            <ShieldCheck size={36} className="text-[#10B981] mx-auto opacity-70" />
            <div className="text-sm font-bold text-[#1E293B]">No allowlist rules defined</div>
            <p className="text-xs text-[#64748B] max-w-sm mx-auto">
              Add your development directories above to avoid false positives during builds.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-[#EAEFF5]">
            {rows.map((r, i) => (
              <div
                key={i}
                className="p-4 flex items-center justify-between hover:bg-[#F8FAFC] transition-colors"
              >
                <div className="min-w-0 flex-1 flex items-center gap-3.5">
                  <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[#F8FAFC] border border-[#EAEFF5] text-[#64748B] shrink-0">
                    {r.kind === "path" ? <FolderCheck size={18} className="text-[#059669]" /> : <Hash size={18} className="text-[#2563EB]" />}
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-xs text-[#1E293B]">{r.label || "Untilted Rule"}</span>
                      <Badge color={r.kind === "path" ? "ok" : "blue"}>{r.kind}</Badge>
                      {r.recursive && <span className="text-[10px] text-[#94A3B8] font-mono">(recursive)</span>}
                    </div>
                    <div className="text-xs font-mono text-[#64748B] truncate mt-0.5" title={r.value}>
                      {r.value}
                    </div>
                  </div>
                </div>

                <Button variant="ghost" size="sm" onClick={() => remove(r.value)}>
                  <Trash2 size={15} className="text-[#94A3B8] hover:text-[#DC2626]" />
                </Button>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
