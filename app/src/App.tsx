import { useState, useEffect } from "react";
import {
  LayoutGrid,
  Shield,
  Bug,
  Monitor,
  ListChecks,
  Lock,
  Radar,
  Network,
  Rocket,
  Sliders,
  ShieldCheck,
  User,
  MoreVertical,
  Sun,
  Moon,
  Smartphone,
  FileCheck2,
  Terminal,
  Activity,
  Copy,
  Search,
  Bell,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import { useTheme } from "@/lib/theme";
import { ContextMenuProvider, useContextMenu, ShinyText } from "@/components/reactbits";
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
  icon: JSX.Element;
  badge?: number | string;
}

function MainShell() {
  const [page, setPage] = useState<PageId>("dashboard");
  const [threatCount, setThreatCount] = useState<number>(0);
  const { theme, toggleTheme } = useTheme();
  const { showMenu } = useContextMenu();

  useEffect(() => {
    api.threats(20)
      .then((t) => setThreatCount(t.length))
      .catch(() => {});
  }, [page]);

  const handleGlobalContextMenu = (e: React.MouseEvent) => {
    showMenu(e, [
      {
        label: "Run Smart Scan",
        icon: <Shield size={14} className="text-[#FF7222]" />,
        shortcut: "Ctrl+S",
        action: () => setPage("scan"),
      },
      {
        label: "Memory Evasion Audit",
        icon: <Radar size={14} className="text-emerald-400" />,
        action: () => setPage("behavior"),
      },
      {
        label: "Quarantine Vault",
        icon: <Lock size={14} className="text-amber-400" />,
        action: () => setPage("quarantine"),
      },
      {
        label: "Android APK Inspector",
        icon: <Smartphone size={14} className="text-sky-400" />,
        action: () => setPage("android"),
      },
      {
        label: "Shields & Settings",
        icon: <Sliders size={14} className="text-slate-400" />,
        action: () => setPage("settings"),
      },
      {
        label: "Copy Version & Diagnostics",
        icon: <Copy size={14} className="text-slate-400" />,
        action: () => {
          navigator.clipboard.writeText("Aegis EDR v0.1.0 (Pure-Rust Engine + ReactBits UI)");
        },
      },
    ]);
  };

  const NAV: NavItem[] = [
    { id: "dashboard", label: "Overview", icon: <LayoutGrid size={18} /> },
    { id: "scan", label: "Smart Scan", icon: <Shield size={18} /> },
    { id: "android", label: "Android Antivirus", icon: <Smartphone size={18} /> },
    {
      id: "threats",
      label: "Threat Events",
      icon: <Bug size={18} />,
      badge: threatCount > 0 ? threatCount : undefined,
    },
    { id: "processes", label: "Process Inspector", icon: <Monitor size={18} /> },
    { id: "whitelist", label: "Allowlist", icon: <ListChecks size={18} /> },
    { id: "quarantine", label: "Quarantine Vault", icon: <Lock size={18} /> },
    { id: "behavior", label: "Behavior Guard", icon: <Radar size={18} /> },
    { id: "network", label: "Network Firewall", icon: <Network size={18} /> },
    { id: "vulnerabilities", label: "Hardening & BYOVD", icon: <FileCheck2 size={18} /> },
    { id: "optimize", label: "System Tune-Up", icon: <Rocket size={18} /> },
    { id: "settings", label: "Shields & Settings", icon: <Sliders size={18} /> },
  ];

  return (
    <div
      onContextMenu={handleGlobalContextMenu}
      className="app-shell flex h-full select-none overflow-hidden bg-[#F4F7FB] dark:bg-[#080B12] text-[#152033] dark:text-white transition-colors"
    >
      {/* Sidebar with Dark/Light Support */}
      <aside className="flex w-[270px] shrink-0 flex-col bg-white dark:bg-[#0D121C] border-r border-[#E5EAF2] dark:border-[#1B2535] px-4 py-5 justify-between transition-colors">
        <div>
          {/* Logo Brand: Minimalist Shield + lowercase aegis */}
          <div className="flex items-center justify-between px-2 mb-8">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-[14px] bg-[#142033] dark:bg-[#FF7222] text-white shadow-[0_8px_18px_rgba(20,32,51,0.18)]">
                <ShieldCheck size={20} strokeWidth={2.2} />
              </div>
              <div>
                <div className="text-[21px] font-extrabold tracking-[-0.04em] text-[#142033] dark:text-white leading-none">
                  <ShinyText text="aegis" speed={4} />
                </div>
                <div className="text-[9px] font-bold uppercase tracking-[0.18em] text-[#8290A5] mt-1">
                  Endpoint defense
                </div>
              </div>
            </div>

            {/* Dark / Light Mode Switch Button in Header */}
            <button
              onClick={toggleTheme}
              className="p-2 rounded-xl text-[#64748B] dark:text-[#8491A2] hover:bg-[#F1F5F9] dark:hover:bg-[#1E293B] hover:text-[#1E293B] dark:hover:text-white transition-colors active:scale-95"
              title={theme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode"}
            >
              {theme === "dark" ? (
                <Sun size={17} className="text-[#F59E0B]" />
              ) : (
                <Moon size={17} className="text-[#64748B]" />
              )}
            </button>
          </div>

          {/* Navigation Menu */}
          <div className="px-3 mb-2 text-[9px] font-bold uppercase tracking-[0.18em] text-[#9AA6B8]">Command center</div>
          <nav className="flex flex-col gap-1">
            {NAV.map((n) => {
              const isActive = page === n.id;
              return (
                <button
                  key={n.id}
                  onClick={() => setPage(n.id)}
                  className={cn(
                    "group relative flex items-center justify-between rounded-[11px] px-3.5 py-2.5 text-xs font-medium transition-all duration-150 active:scale-[0.98]",
                    isActive
                      ? "bg-[#EEF3F9] dark:bg-[#172333] text-[#152033] dark:text-white font-semibold shadow-sm before:absolute before:left-0 before:top-2 before:h-5 before:w-1 before:rounded-r-full before:bg-[#FF7222]"
                      : "text-[#68778D] dark:text-[#91A0B5] hover:bg-[#F7F9FC] dark:hover:bg-[#121B29] hover:text-[#152033] dark:hover:text-white"
                  )}
                >
                  <div className="flex items-center gap-3">
                    <span className={cn(isActive ? "text-[#FF7222]" : "text-[#64748B] dark:text-[#8491A2]")}>
                      {n.icon}
                    </span>
                    <span>{n.label}</span>
                  </div>

                  {n.badge !== undefined && (
                    <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-[#FF7222] px-1.5 text-[10px] font-bold text-white shadow-sm">
                      {n.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* User / Host Status Card + Quick Theme Info */}
        <div className="space-y-2">
          <div className="rounded-2xl border border-[#EAEFF5] dark:border-[#212533] bg-[#F8FAFC] dark:bg-[#13151D] p-3 shadow-sm">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3 min-w-0">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-white dark:bg-[#1E293B] border border-[#EAEFF5] dark:border-[#334155] text-[#64748B] dark:text-[#94A3B8] shadow-sm shrink-0">
                  <User size={18} />
                </div>
                <div className="min-w-0">
                  <div className="text-xs font-bold text-[#1E293B] dark:text-white truncate">
                    User Account
                  </div>
                  <div className="text-[11px] text-[#059669] dark:text-[#34D399] font-medium truncate flex items-center gap-1">
                    <span className="h-1.5 w-1.5 rounded-full bg-[#10B981]" />
                    Active Protection
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content Viewport */}
      <main className="flex-1 overflow-y-auto bg-[#F4F7FB] dark:bg-[#080B12] transition-colors">
        <div className="sticky top-0 z-10 flex h-[66px] items-center justify-between border-b border-[#E5EAF2] bg-[#F4F7FB]/90 px-6 backdrop-blur-xl dark:border-[#1B2535] dark:bg-[#080B12]/90 sm:px-8">
          <div className="flex items-center gap-3 text-xs text-[#8090A5]">
            <span className="font-semibold text-[#152033] dark:text-white">Aegis EDR</span>
            <span className="text-[#C4CBD6] dark:text-[#344155]">/</span>
            <span>{NAV.find((item) => item.id === page)?.label}</span>
          </div>
          <div className="flex items-center gap-2 sm:gap-4">
            <div className="hidden items-center gap-2 rounded-lg border border-[#E0E6EF] bg-white px-3 py-2 text-[11px] text-[#9AA6B8] shadow-sm dark:border-[#1B2535] dark:bg-[#0D121C] sm:flex">
              <Search size={14} />
              <span>Search anything</span>
              <kbd className="ml-3 rounded border border-[#E5EAF2] px-1.5 py-0.5 text-[9px] dark:border-[#273348]">⌘ K</kbd>
            </div>
            <div className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-[11px] font-semibold text-[#059669] dark:text-[#34D399]">
              <span className="relative flex h-2 w-2"><span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#10B981] opacity-60" /><span className="relative inline-flex h-2 w-2 rounded-full bg-[#10B981]" /></span>
              <span className="hidden sm:inline">Protection active</span>
            </div>
            <button className="rounded-lg p-2 text-[#8090A5] transition-colors hover:bg-white hover:text-[#152033] dark:hover:bg-[#121B29] dark:hover:text-white" title="Notifications">
              <Bell size={17} />
            </button>
          </div>
        </div>
        <div className="mx-auto max-w-[1480px] p-6 sm:p-8">
          {page === "dashboard" && (
            <Dashboard
              onNavigateScan={() => setPage("scan")}
              onNavigatePage={(p) => setPage(p as PageId)}
            />
          )}
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
