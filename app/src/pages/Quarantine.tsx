import { useEffect, useState } from "react";
import { RotateCcw, Trash2 } from "lucide-react";
import { api, fmtBytes, fmtTime, type QuarantineRow } from "@/lib/api";
import { Button, Card, SectionTitle } from "@/components/ui";

export default function Quarantine() {
  const [rows, setRows] = useState<QuarantineRow[]>([]);
  const load = () => api.quarantine().then(setRows).catch(() => {});
  useEffect(() => {
    load();
  }, []);

  const act = async (sha: string, action: "restore" | "delete") => {
    await api.quarantineAction(sha, action);
    load();
  };

  return (
    <div>
      <SectionTitle
        title="Quarantine"
        subtitle="Threats are AES-256-GCM encrypted at rest. Restore returns the file byte-for-byte."
      />
      <Card>
        {rows.length === 0 ? (
          <p className="text-sm text-muted">Quarantine is empty.</p>
        ) : (
          <div className="space-y-2">
            {rows.map((q) => (
              <div
                key={q.sha256}
                className="flex items-center justify-between rounded-xl border border-border bg-black/20 px-4 py-3"
              >
                <div className="min-w-0">
                  <div className="font-medium text-danger">{q.threat}</div>
                  <div className="max-w-[420px] truncate text-xs text-muted" title={q.original_path}>
                    {q.original_path}
                  </div>
                  <div className="mt-0.5 text-[11px] text-muted">
                    {fmtBytes(q.size)} · {fmtTime(q.quarantined_at)}
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button onClick={() => act(q.sha256, "restore")}>
                    <RotateCcw size={15} /> Restore
                  </Button>
                  <Button variant="danger" onClick={() => act(q.sha256, "delete")}>
                    <Trash2 size={15} /> Delete
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
