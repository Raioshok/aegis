import { useEffect, useState, type ReactNode } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  ScanSearch,
  RefreshCw,
  Bug,
  Lock,
  Cpu,
  Network,
  ShieldHalf,
  Smartphone,
  Rocket,
  ListChecks,
  ChevronRight,
  Database,
  Radio,
} from "lucide-react";
import { api, fmtTime, type Dashboard as DashboardData, type HistoryRow, type SyncReport } from "@/lib/api";
import { ago, findIssues } from "@/lib/status";
import { Button, Card, Badge, Spinner } from "@/components/ui";
import { cn } from "@/lib/utils";
import type { PageId } from "@/App";

export default function Dashboard({
  data,
  onNavigate,
  onRefresh,
}: {
  data: DashboardData | null;
  onNavigate: (p: PageId) => void;
  onRefresh: () => Promise<unknown>;
}) {
  const [history, setHistory] = useState<HistoryRow[] | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [sync, setSync] = useState<SyncReport | string | null>(null);

  useEffect(() => {
    api.history(5).then(setHistory).catch(() => setHistory([]));
  }, []);

  const updateDatabases = async () => {
    setSyncing(true);
    setSync(null);
    try {
      setSync(await api.syncThreatFeeds());
      await onRefresh();
    } catch (e) {
      setSync(String(e));
    } finally {
      setSyncing(false);
    }
  };

  if (!data || history === null) {
    return (
      <div className="flex items-center gap-3 py-24 text-sm text-fg-muted justify-center">
        <Spinner /> Loading protection status…
      </div>
    );
  }

  const lastScan = history[0];
  const issues = findIssues(data, lastScan);
  const healthy = issues.length === 0;

  return (
    <div className="space-y-6">
      {/* Protection status */}
      <section
        className={cn(
          "relative overflow-hidden rounded-[20px] border p-7",
          healthy ? "border-brand/20 bg-brand-soft" : "border-warn/25 bg-warn-soft"
        )}
      >
        <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
          <div className="flex items-start gap-5">
            <div
              className={cn(
                "flex h-20 w-20 shrink-0 items-center justify-center rounded-full",
                healthy ? "bg-brand text-brand-ink shadow-hero" : "bg-warn text-white"
              )}
            >
              {healthy ? <ShieldCheck size={40} strokeWidth={2} /> : <ShieldAlert size={40} strokeWidth={2} />}
            </div>
            <div className="space-y-2">
              <h1 className="text-2xl font-semibold tracking-tight [text-wrap:balance]">
                {healthy ? "Your device is protected" : "Your protection needs attention"}
              </h1>
              {healthy ? (
                <p className="text-sm text-fg-muted">
                  Real-time protection is on ({data.realtime?.backend}). Last scan {ago(lastScan?.finished)}, databases
                  updated {ago(data.last_feed_sync)}.
                </p>
              ) : (
                <ul className="space-y-1.5">
                  {issues.map((i) => (
                    <li key={i.text} className="flex flex-wrap items-center gap-x-3 text-sm text-fg">
                      <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-warn" />
                      {i.text}
                      {i.action && (
                        <button
                          onClick={() => onNavigate(i.action!.page)}
                          className="text-sm font-semibold text-brand hover:underline"
                        >
                          {i.action.label}
                        </button>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
          <div className="flex shrink-0 flex-col gap-2 sm:flex-row md:flex-col lg:flex-row">
            <Button variant="primary" size="lg" onClick={() => onNavigate("scan")}>
              <ScanSearch size={17} /> Scan
            </Button>
            <Button variant="outline" size="lg" onClick={updateDatabases} disabled={syncing}>
              <RefreshCw size={16} className={syncing ? "animate-spin" : ""} />
              {syncing ? "Updating…" : "Update databases"}
            </Button>
          </div>
        </div>
        {sync !== null && (
          <div className="mt-5 rounded-xl border border-line bg-surface px-4 py-3 text-xs">
            {typeof sync === "string" ? (
              <span className="text-danger">Update failed: {sync}</span>
            ) : (
              <div className="space-y-1">
                <div className="text-fg">
                  Loaded {sync.malware_hashes.toLocaleString()} malware hashes, {sync.c2_ips.toLocaleString()} C2 addresses
                  and {sync.vulnerable_drivers.toLocaleString()} vulnerable-driver hashes.
                </div>
                {sync.errors.map((e) => (
                  <div key={e} className="text-warn">
                    {e}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </section>

      {/* Feature tiles */}
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
        <Tile icon={<ScanSearch size={20} />} tone="brand" title="Scan" onClick={() => onNavigate("scan")}>
          {lastScan ? `Last: ${lastScan.files.toLocaleString()} files, ${lastScan.threats} threats, ${ago(lastScan.finished)}` : "No scans yet"}
        </Tile>
        <Tile icon={<Bug size={20} />} tone={data.threats > 0 ? "danger" : "ok"} title="Detections" onClick={() => onNavigate("threats")}>
          {data.threats > 0 ? `${data.threats.toLocaleString()} threats found across ${data.scans} scans` : "Nothing detected so far"}
        </Tile>
        <Tile icon={<Lock size={20} />} tone="warn" title="Quarantine" onClick={() => onNavigate("quarantine")}>
          {data.quarantine_count > 0 ? `${data.quarantine_count} encrypted items` : "Empty"}
        </Tile>
        <Tile icon={<Cpu size={20} />} tone="info" title="Processes" onClick={() => onNavigate("processes")}>
          Process tree, signatures and lineage alerts
        </Tile>
        <Tile icon={<Network size={20} />} tone="info" title="Network" onClick={() => onNavigate("network")}>
          Open connections checked against C2 feeds
        </Tile>
        <Tile icon={<ShieldHalf size={20} />} tone="violet" title="Hardening" onClick={() => onNavigate("vulnerabilities")}>
          {data.vulnerable_driver_signatures > 0
            ? `OS settings and drivers vs ${data.vulnerable_driver_signatures.toLocaleString()} vulnerable-driver hashes`
            : "OS security settings audit"}
        </Tile>
        <Tile icon={<Smartphone size={20} />} tone="ok" title="Android apps" onClick={() => onNavigate("android")}>
          Inspect .apk and .dex files
        </Tile>
        <Tile icon={<Rocket size={20} />} tone="brand" title="Tune-up" onClick={() => onNavigate("optimize")}>
          Reclaimable disk space and system tweaks
        </Tile>
        <Tile icon={<ListChecks size={20} />} tone="neutral" title="Exclusions" onClick={() => onNavigate("whitelist")}>
          {data.whitelist_count > 0 ? `${data.whitelist_count} trusted paths` : "No exclusions"}
        </Tile>
      </section>

      {/* Components */}
      <section className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card className="p-0">
          <div className="flex items-center gap-2 border-b border-line px-5 py-3.5 text-sm font-semibold">
            <Database size={16} className="text-fg-muted" /> Detection engines
          </div>
          <ul className="divide-y divide-line">
            {data.engines.map((e) => (
              <li key={e.name} className="flex items-center justify-between gap-4 px-5 py-3">
                <span className="text-[13px] font-medium">{e.name}</span>
                <span className="truncate text-right text-xs text-fg-muted" title={e.status}>
                  {e.status}
                </span>
              </li>
            ))}
          </ul>
        </Card>
        <Card className="p-0">
          <div className="flex items-center gap-2 border-b border-line px-5 py-3.5 text-sm font-semibold">
            <Radio size={16} className="text-fg-muted" /> Real-time protection
          </div>
          {data.daemon_running && data.realtime ? (
            <dl className="divide-y divide-line text-[13px]">
              <Row label="State">
                <Badge color={data.realtime.enabled ? "ok" : "warn"}>{data.realtime.enabled ? "On" : "Off"}</Badge>
              </Row>
              <Row label="Watcher">{data.realtime.backend}</Row>
              <Row label="File events checked">{data.realtime.events_seen.toLocaleString()}</Row>
              <Row label="Threats blocked">{data.realtime.threats_blocked.toLocaleString()}</Row>
              <Row label="Total files scanned">{data.files.toLocaleString()}</Row>
            </dl>
          ) : (
            <div className="px-5 py-6 text-[13px] leading-relaxed text-fg-muted">
              The Aegis service is not running. Start <code className="rounded bg-surface-2 px-1">aegisd</code> to check
              files as they arrive. Manual scans from this window still work.
            </div>
          )}
          {lastScan && (
            <div className="border-t border-line px-5 py-3 text-xs text-fg-subtle">
              Last scan finished {fmtTime(lastScan.finished)} · {lastScan.target}
            </div>
          )}
        </Card>
      </section>
    </div>
  );
}

const TONES = {
  brand: "bg-brand-soft text-brand",
  ok: "bg-ok-soft text-ok",
  warn: "bg-warn-soft text-warn",
  danger: "bg-danger-soft text-danger",
  info: "bg-info-soft text-info",
  violet: "bg-violet-soft text-violet",
  neutral: "bg-surface-2 text-fg-muted",
};

function Tile({
  icon,
  tone,
  title,
  children,
  onClick,
}: {
  icon: ReactNode;
  tone: keyof typeof TONES;
  title: string;
  children: ReactNode;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="group flex items-center gap-4 rounded-card border border-line bg-surface p-4 text-left shadow-card transition-[box-shadow,border-color] hover:border-fg-subtle/40 hover:shadow-card-hover"
    >
      <div className={cn("flex h-11 w-11 shrink-0 items-center justify-center rounded-xl", TONES[tone])}>{icon}</div>
      <div className="min-w-0 flex-1">
        <div className="text-[14px] font-semibold">{title}</div>
        <div className="mt-0.5 truncate text-xs text-fg-muted">{children}</div>
      </div>
      <ChevronRight size={18} className="shrink-0 text-fg-subtle transition-transform group-hover:translate-x-0.5" />
    </button>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between px-5 py-3">
      <dt className="text-fg-muted">{label}</dt>
      <dd className="font-medium tabular-nums">{children}</dd>
    </div>
  );
}
