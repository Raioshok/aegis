import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Activity,
  ShieldCheck,
  ScanLine,
  Bug,
  ListChecks,
  Lock,
  Radar,
} from "lucide-react";
import { cn } from "@/lib/utils";
import Dashboard from "@/pages/Dashboard";
import Scan from "@/pages/Scan";
import Threats from "@/pages/Threats";
import Whitelist from "@/pages/Whitelist";
import Quarantine from "@/pages/Quarantine";
import Behavior from "@/pages/Behavior";

type PageId =
  | "dashboard"
  | "scan"
  | "threats"
  | "whitelist"
  | "quarantine"
  | "behavior";

const NAV: { id: PageId; label: string; icon: JSX.Element }[] = [
  { id: "dashboard", label: "Dashboard", icon: <Activity size={18} /> },
  { id: "scan", label: "Scan", icon: <ScanLine size={18} /> },
  { id: "threats", label: "Threats", icon: <Bug size={18} /> },
  { id: "whitelist", label: "Whitelist", icon: <ListChecks size={18} /> },
  { id: "quarantine", label: "Quarantine", icon: <Lock size={18} /> },
  { id: "behavior", label: "Behavior", icon: <Radar size={18} /> },
];

export default function App() {
  const [page, setPage] = useState<PageId>("dashboard");

  return (
    <div className="flex h-full">
      {/* Sidebar */}
      <aside className="flex w-56 flex-col border-r border-border bg-black/20 backdrop-blur-xl">
        <div className="flex items-center gap-2 px-5 py-5">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-accent shadow-glow">
            <ShieldCheck size={20} className="text-white" />
          </div>
          <div>
            <div className="text-sm font-bold leading-tight">Aegis</div>
            <div className="text-[11px] text-muted">Linux AV</div>
          </div>
        </div>
        <nav className="mt-2 flex flex-col gap-1 px-3">
          {NAV.map((n) => (
            <button
              key={n.id}
              onClick={() => setPage(n.id)}
              className={cn(
                "flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-all",
                page === n.id
                  ? "bg-accent text-white shadow-glow"
                  : "text-muted hover:bg-white/5 hover:text-fg",
              )}
            >
              {n.icon}
              {n.label}
            </button>
          ))}
        </nav>
        <div className="mt-auto px-5 py-4 text-[11px] text-muted">
          v0.1.0 · Milestone 4
        </div>
      </aside>

      {/* Content */}
      <main className="flex-1 overflow-y-auto p-8">
        <AnimatePresence mode="wait">
          <motion.div
            key={page}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.2 }}
          >
            {page === "dashboard" && <Dashboard onNavigateScan={() => setPage("scan")} />}
            {page === "scan" && <Scan />}
            {page === "threats" && <Threats />}
            {page === "whitelist" && <Whitelist />}
            {page === "quarantine" && <Quarantine />}
            {page === "behavior" && <Behavior />}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}
