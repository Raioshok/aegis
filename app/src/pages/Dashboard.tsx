import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, ShieldAlert, ScanLine, FileSearch, Bug, ListChecks } from "lucide-react";
import { api, type Dashboard as Dash } from "@/lib/api";
import { Button, Card, StatCard } from "@/components/ui";

export default function Dashboard({ onNavigateScan }: { onNavigateScan: () => void }) {
  const [d, setD] = useState<Dash | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = () => {
    api
      .dashboard()
      .then(setD)
      .catch((e) => setErr(String(e)));
  };
  useEffect(() => {
    load();
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, []);

  const protectedState = (d?.threats ?? 0) === 0;

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Aegis</h1>
          <p className="mt-1 text-sm text-muted">
            Multi-engine protection for Linux
          </p>
        </div>
        <Button variant="primary" onClick={onNavigateScan}>
          <ScanLine size={16} /> Quick Scan
        </Button>
      </div>

      {/* Protection banner */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        className="card mb-6 flex items-center gap-5 p-6"
      >
        <div className="relative">
          <div
            className={`flex h-16 w-16 items-center justify-center rounded-2xl ${
              protectedState ? "bg-ok/15" : "bg-danger/15"
            }`}
          >
            {protectedState ? (
              <ShieldCheck size={34} className="text-ok" />
            ) : (
              <ShieldAlert size={34} className="text-danger" />
            )}
          </div>
          {protectedState && (
            <span className="absolute inset-0 rounded-2xl border border-ok/40 animate-pulse-ring" />
          )}
        </div>
        <div className="flex-1">
          <div
            className={`text-xl font-bold ${protectedState ? "text-ok" : "text-danger"}`}
          >
            {protectedState ? "Protected" : `${d?.threats} threat(s) on record`}
          </div>
          <div className="text-sm text-muted">
            {d?.daemon_running
              ? `Daemon running${d?.realtime?.enabled ? " · real-time on (" + d.realtime.backend + ")" : " · real-time off"}`
              : "Daemon not running — start with `aegis daemon`"}
          </div>
        </div>
        {d?.realtime && (
          <div className="text-right text-sm">
            <div className="text-muted">real-time events</div>
            <div className="text-2xl font-bold">{d.realtime.events_seen}</div>
          </div>
        )}
      </motion.div>

      {/* Stat grid */}
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Total scans" value={d?.scans ?? 0} icon={<ScanLine size={20} />} delay={0.05} />
        <StatCard label="Files checked" value={d?.files ?? 0} icon={<FileSearch size={20} />} delay={0.1} />
        <StatCard label="Threats found" value={d?.threats ?? 0} accent="text-danger" icon={<Bug size={20} />} delay={0.15} />
        <StatCard label="Whitelisted" value={d?.whitelist_count ?? 0} accent="text-ok" icon={<ListChecks size={20} />} delay={0.2} />
      </div>

      {/* Engine health */}
      <Card>
        <h2 className="mb-3 text-base font-semibold">Detection engines</h2>
        <div className="space-y-2">
          {(d?.engines ?? []).map((e) => (
            <div key={e.name} className="flex items-center gap-3 text-sm">
              <span className="h-2 w-2 rounded-full bg-ok shadow-[0_0_8px] shadow-ok" />
              <span className="w-24 font-medium">{e.name}</span>
              <span className="text-muted">{e.status}</span>
            </div>
          ))}
          {!d && !err && <div className="text-sm text-muted">Loading…</div>}
          {err && <div className="text-sm text-danger">{err}</div>}
        </div>
      </Card>
    </div>
  );
}
