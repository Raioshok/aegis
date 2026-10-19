import { useEffect, useState } from "react";
import { RotateCcw, Trash2, Lock, Search, ShieldCheck } from "lucide-react";
import { api, fmtBytes, fmtTime, type QuarantineRow } from "@/lib/api";
import { Button, Card, SectionTitle, Badge } from "@/components/ui";

export default function Quarantine() {
  const [rows, setRows] = useState<QuarantineRow[]>([]);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(false);

  const load = () => {
    setLoading(true);
    api.quarantine()
      .then(setRows)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const act = async (sha: string, action: "restore" | "delete") => {
    await api.quarantineAction(sha, action);
    load();
  };

  const filtered = rows.filter(
    (q) =>
      q.threat.toLowerCase().includes(filter.toLowerCase()) ||
      q.original_path.toLowerCase().includes(filter.toLowerCase()) ||
      q.sha256.toLowerCase().includes(filter.toLowerCase())
  );

  const totalBytes = rows.reduce((acc, curr) => acc + curr.size, 0);

  return (
    <div className="space-y-6 max-w-6xl">
      <SectionTitle
        title="Quarantine Vault"
        subtitle="Encrypted isolated storage for neutralized threats. Sealed with ChaCha20-Poly1305 AEAD and DPAPI machine keys."
        action={
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            Refresh
          </Button>
        }
      />

      {/* Summary Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card className="p-5">
          <span className="text-xs text-[#64748B] font-medium block">Quarantined Objects</span>
          <span className="text-2xl font-extrabold text-[#1E293B] tab-nums mt-1 block">{rows.length}</span>
        </Card>
        <Card className="p-5">
          <span className="text-xs text-[#64748B] font-medium block">Vault Volume</span>
          <span className="text-2xl font-extrabold text-[#1E293B] tab-nums mt-1 block">{fmtBytes(totalBytes)}</span>
        </Card>
        <Card className="p-5">
          <span className="text-xs text-[#64748B] font-medium block">Vault Encryption</span>
          <span className="text-base font-bold text-[#059669] mt-1 block">ChaCha20-Poly1305</span>
          <span className="text-[11px] text-[#94A3B8]">DPAPI Machine Key Scope</span>
        </Card>
      </div>

      {/* Filter / Search Bar */}
      <Card className="p-4">
        <div className="flex items-center gap-3">
          <Search size={18} className="text-[#94A3B8] shrink-0" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Search by threat name, filename, path, or SHA-256..."
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

      {/* Vault List */}
      <Card className="p-0 overflow-hidden">
        <div className="px-6 py-4 border-b border-[#EAEFF5] flex items-center justify-between bg-white">
          <span className="text-sm font-bold text-[#1E293B]">Isolated Artifacts</span>
          <Badge color={rows.length > 0 ? "warn" : "ok"}>
            {rows.length === 0 ? "Vault Clean" : `${rows.length} Sealed`}
          </Badge>
        </div>

        {rows.length === 0 ? (
          <div className="p-16 text-center space-y-2">
            <Lock size={36} className="text-[#10B981] mx-auto opacity-70" />
            <div className="text-sm font-bold text-[#1E293B]">Quarantine Vault is Clean</div>
            <p className="text-xs text-[#64748B] max-w-sm mx-auto">
              No active threat objects have been isolated. When dangerous files are detected, they are moved here securely.
            </p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-10 text-center text-xs text-[#64748B]">
            No items matching "{filter}".
          </div>
        ) : (
          <div className="divide-y divide-[#EAEFF5]">
            {filtered.map((q) => (
              <div
                key={q.sha256}
                className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-[#F8FAFC] transition-colors"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2.5">
                    <span className="font-bold text-sm text-[#DC2626]">{q.threat}</span>
                    <span className="text-xs text-[#64748B] font-mono tab-nums">{fmtBytes(q.size)}</span>
                  </div>

                  <div className="mt-1 font-mono text-xs text-[#1E293B] truncate" title={q.original_path}>
                    {q.original_path}
                  </div>

                  <div className="mt-1.5 flex flex-wrap items-center gap-3 text-[11px] text-[#94A3B8] font-mono">
                    <span>Isolated: {fmtTime(q.quarantined_at)}</span>
                    <span className="truncate max-w-xs text-[#64748B]">SHA256: {q.sha256}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => act(q.sha256, "restore")}
                  >
                    <RotateCcw size={13} /> Restore
                  </Button>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={() => act(q.sha256, "delete")}
                  >
                    <Trash2 size={13} /> Purge
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
