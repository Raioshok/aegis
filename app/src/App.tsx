import { useEffect, useState, type ReactNode } from "react";
import {
  Home,
  ScanSearch,
  Bug,
  Lock,
  ListChecks,
  Smartphone,
  Cpu,
  Radar,
  Network,
  ShieldHalf,
  Rocket,
  Settings as SettingsIcon,
  ShieldCheck,
  ShieldAlert,
  Sun,
  Moon,
  Copy,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { api, type Dashboard as DashboardData } from "@/lib/api";
import { useTheme } from "@/lib/theme";
import { ContextMenuProvider, useContextMenu } from "@/components/reactbits";
import Dashboard from "@/pages/Dashboard";
import Scan from "@/pages/Scan";
import Threats from "@/pages/Threats";
import Whitelist from "@/pages/Whitelist";
import Quarantine from "@/pages/Quarantine";
import Behavior from "@/pages/Behavior";
import NetworkPage from "@/pages/Network";
import Optimize from "@/pages/Optimize";
import Processes from "@/pages/Processes";
import Settings from "@/pages/Settings";
import AndroidScanner from "@/pages/AndroidScanner";
import Vulnerabilities from "@/pages/Vulnerabilities";

export type PageId =
  | "dashboard"
  | "scan"
  | "android"
  | "threats"
  | "processes"
  | "whitelist"
  | "quarantine"
  | "behavior"
  | "network"
  | "vulnerabilities"
  | "optimize"
  | "settings";

interface NavItem {
  id: PageId;
  label: string;
  icon: ReactNode;
  badge?: number;
}

/** Protection as the backend reports it: daemon reachable and real-time on. */
export function protectionLevel(d: DashboardData | null): "ok" | "warn" | "unknown" {
  if (!d) return "unknown";
  return d.daemon_running && d.realtime?.enabled ? "ok" : "warn";
}

function MainShell() {
  const [page, setPage] = useState<PageId>("dashboard");
  const [dash, setDash] = useState<DashboardData | null>(null);
  const [threatCount, setThreatCount] = useState(0);
  const { theme, toggleTheme } = useTheme();
  const { showMenu } = useContextMenu();

  useEffect(() => {
    const load = () => {
      api.dashboard().then(setDash).catch(() => setDash(null));
      api.threats(200).then((t) => setThreatCount(t.length)).catch(() => {});
    };
    load();
    const id = window.setInterval(load, 10_000);
    return () => window.clearInterval(id);
  }, [page]);

  const groups: { title?: string; items: NavItem[] }[] = [
    { items: [{ id: "dashboard", label: "Home", icon: <Home size={18} /> }] },
    {
      title: "Security",
      items: [
        { id: "scan", label: "Scan", icon: <ScanSearch size={18} /> },
        { id: "threats", label: "Detections", icon: <Bug size={18} />, badge: threatCount || undefined },
        { id: "quarantine", label: "Quarantine", icon: <Lock size={18} />, badge: dash?.quarantine_count || undefined },
        { id: "whitelist", label: "Exclusions", icon: <ListChecks size={18} /> },
        { id: "android", label: "Android apps", icon: <Smartphone size={18} /> },
      ],
    },
    {
      title: "Monitoring",
      items: [
        { id: "processes", label: "Processes", icon: <Cpu size={18} /> },
        { id: "behavior", label: "Behavior & memory", icon: <Radar size={18} /> },
        { id: "network", label: "Network", icon: <Network size={18} /> },
      ],
    },
    {
      title: "System",
      items: [
        { id: "vulnerabilities", label: "Hardening", icon: <ShieldHalf size={18} /> },
        { id: "optimize", label: "Tune-up", icon: <Rocket size={18} /> },
      ],
    },
  ];
  const allItems = [...groups.flatMap((g) => g.items), { id: "settings" as PageId, label: "Settings", icon: null }];
  const level = protectionLevel(dash);

  const handleContextMenu = (e: React.MouseEvent) => {
    showMenu(e, [
      { label: "Scan", icon: <ScanSearch size={14} className="text-brand" />, action: () => setPage("scan") },
      { label: "Quarantine", icon: <Lock size={14} className="text-warn" />, action: () => setPage("quarantine") },
      { label: "Settings", icon: <SettingsIcon size={14} className="text-fg-muted" />, action: () => setPage("settings") },
      {
        label: "Copy version info",
        icon: <Copy size={14} className="text-fg-muted" />,
        action: () => {
          const engines = dash?.engines.map((e) => `${e.name}: ${e.status}`).join("\n") ?? "";
          navigator.clipboard.writeText(`Aegis ${dash?.version ?? "unknown"}\n${engines}`);
        },
      },
    ]);
  };

  const navButton = (n: NavItem) => {
    const active = page === n.id;
    return (
      <button
        key={n.id}
        onClick={() => setPage(n.id)}
        aria-current={active ? "page" : undefined}
        className={cn(
          "flex w-full items-center justify-between rounded-xl px-3 py-2 text-[13px] transition-colors",
          active ? "bg-brand-soft font-semibold text-brand" : "text-fg-muted hover:bg-surface-2 hover:text-fg"
        )}
      >
        <span className="flex items-center gap-3">
          {n.icon}
          {n.label}
        </span>
        {n.badge !== undefined && (
          <span className="min-w-5 rounded-full bg-danger px-1.5 text-center text-[10px] font-bold leading-5 text-white tabular-nums">
            {n.badge}
          </span>
        )}
      </button>
    );
  };

  return (
    <div onContextMenu={handleContextMenu} className="flex h-full select-none overflow-hidden bg-bg text-fg">
      <aside className="flex w-[244px] shrink-0 flex-col border-r border-line bg-surface">
        <div className="flex items-center gap-2.5 px-5 pb-4 pt-5">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand text-brand-ink">
            <ShieldCheck size={19} strokeWidth={2.4} />
          </div>
          <div className="text-lg font-semibold tracking-tight">Aegis</div>
        </div>

        <nav className="flex-1 space-y-4 overflow-y-auto px-3 pb-4" aria-label="Main">
          {groups.map((g, i) => (
            <div key={i} className="space-y-0.5">
              {g.title && (
                <div className="px-3 pb-1 text-[11px] font-semibold uppercase tracking-wider text-fg-subtle">{g.title}</div>
              )}
              {g.items.map(navButton)}
            </div>
          ))}
        </nav>

        <div className="space-y-2 border-t border-line p-3">
          {navButton({ id: "settings", label: "Settings", icon: <SettingsIcon size={18} /> })}
          <div
            className={cn(
              "flex items-center gap-2.5 rounded-xl px-3 py-2.5 text-xs font-medium",
              level === "ok" ? "bg-ok-soft text-ok" : level === "warn" ? "bg-warn-soft text-warn" : "bg-surface-2 text-fg-muted"
            )}
          >
            {level === "ok" ? <ShieldCheck size={16} /> : <ShieldAlert size={16} />}
            {level === "ok" ? "Real-time protection on" : level === "warn" ? "Real-time protection off" : "Checking protection…"}
          </div>
        </div>
      </aside>

      <main className="flex flex-1 flex-col overflow-hidden">
        <header className="flex h-14 shrink-0 items-center justify-between border-b border-line bg-surface px-6">
          <div className="text-sm font-semibold">{allItems.find((i) => i.id === page)?.label}</div>
          <div className="flex items-center gap-3">
            {dash && <span className="text-xs text-fg-subtle tabular-nums">v{dash.version}</span>}
            <button
              onClick={toggleTheme}
              className="rounded-lg p-2 text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg"
              aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            >
              {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
            </button>
          </div>
        </header>
        <div className="flex-1 overflow-y-auto">
          <div className="mx-auto max-w-[1280px] p-6 lg:p-8">
            {page === "dashboard" && <Dashboard data={dash} onNavigate={setPage} onRefresh={() => api.dashboard().then(setDash)} />}
            {page === "scan" && <Scan />}
            {page === "android" && <AndroidScanner />}
            {page === "threats" && <Threats />}
            {page === "processes" && <Processes />}
            {page === "whitelist" && <Whitelist />}
            {page === "quarantine" && <Quarantine />}
            {page === "behavior" && <Behavior />}
            {page === "network" && <NetworkPage />}
            {page === "vulnerabilities" && <Vulnerabilities />}
            {page === "optimize" && <Optimize />}
            {page === "settings" && <Settings />}
          </div>
        </div>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <ContextMenuProvider>
      <MainShell />
    </ContextMenuProvider>
  );
}
