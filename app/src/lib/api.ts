// Typed wrappers around the Tauri command bridge (see src-tauri/src/commands.rs).
import { invoke } from "@tauri-apps/api/core";

export interface EngineInfo {
  name: string;
  status: string;
}
export interface RealtimeInfo {
  enabled: boolean;
  backend: string;
  events_seen: number;
  threats_blocked: number;
}
export interface Dashboard {
  daemon_running: boolean;
  version: string;
  scans: number;
  files: number;
  threats: number;
  whitelist_count: number;
  quarantine_count: number;
  engines: EngineInfo[];
  realtime: RealtimeInfo | null;
}
export interface ThreatRow {
  severity: number;
  severity_label: string;
  path: string;
  sha256: string;
  names: string;
  engines: string;
}
export interface ScanReport {
  target: string;
  total_files: number;
  scanned: number;
  threats: number;
  duration_ms: number;
  results: ThreatRow[];
}
export interface HistoryRow {
  finished: number;
  target: string;
  files: number;
  threats: number;
  kind: string;
}
export interface QuarantineRow {
  sha256: string;
  original_path: string;
  threat: string;
  quarantined_at: number;
  size: number;
}
export interface WhitelistRow {
  kind: string;
  value: string;
  label: string;
  recursive: boolean;
}

export const api = {
  dashboard: () => invoke<Dashboard>("dashboard"),
  runScan: (path: string) => invoke<ScanReport>("run_scan", { path }),
  history: (limit = 50) => invoke<HistoryRow[]>("list_history", { limit }),
  threats: (limit = 200) => invoke<ThreatRow[]>("list_threats", { limit }),
  quarantine: () => invoke<QuarantineRow[]>("list_quarantine"),
  quarantineAction: (sha256: string, action: "restore" | "delete") =>
    invoke<void>("quarantine_action", { sha256, action }),
  whitelist: () => invoke<WhitelistRow[]>("list_whitelist"),
  addWhitelist: (path: string, label: string) =>
    invoke<void>("add_whitelist", { path, label }),
  removeWhitelist: (value: string) => invoke<void>("remove_whitelist", { value }),
  rootkitScan: () => invoke<ThreatRow[]>("rootkit_scan"),
  memoryScan: (pid?: number) => invoke<ThreatRow[]>("memory_scan", { pid: pid ?? null }),
};

export function severityColor(sev: number): string {
  switch (sev) {
    case 0:
      return "text-ok";
    case 1:
    case 2:
      return "text-warn";
    case 3:
      return "text-danger";
    default:
      return "text-crit";
  }
}

export function fmtTime(epoch: number): string {
  if (!epoch) return "—";
  return new Date(epoch * 1000).toLocaleString();
}

export function fmtBytes(n: number): string {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let v = n,
    i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(1)} ${u[i]}`;
}
