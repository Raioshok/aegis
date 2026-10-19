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

export interface ConnRow {
  protocol: string;
  local: string;
  remote: string;
  state: string;
}
export interface NetworkReport {
  findings: ThreatRow[];
  connections: ConnRow[];
  listening: number;
  established: number;
}
export interface PluginRow {
  name: string;
  status: string;
  trusted: boolean;
  permissions: string[];
}

export interface OptimizeFinding {
  category: string;
  title: string;
  detail: string;
  impact: number;
  impact_label: string;
  reclaimable: number;
  reclaimable_human: string;
  action: string | null;
  needs_root: boolean;
}
export interface OptimizeReport {
  findings: OptimizeFinding[];
  total_reclaimable: number;
  total_reclaimable_human: string;
  opportunities: number;
}

export interface ProcessItem {
  pid: number;
  name: string;
  path: string;
  is_signed: boolean;
  is_suspicious: boolean;
  risk_score: number;
}

export interface VulnerabilityItem {
  id: string;
  title: string;
  category: string;
  severity: string;
  detail: string;
  status: string;
  fixable: boolean;
}

export interface SecurityAuditReport {
  overall_score: number;
  items: VulnerabilityItem[];
  issues_count: number;
}

export interface FeedSyncResult {
  success: boolean;
  hashes_updated: number;
  ips_updated: number;
  yara_rules_version: string;
  message: string;
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
  networkScan: () => invoke<NetworkReport>("network_scan"),
  pluginsList: () => invoke<PluginRow[]>("plugins_list"),
  optimizeScan: () => invoke<OptimizeReport>("optimize_scan"),
  isAutostartActive: () => invoke<boolean>("is_autostart_active"),
  toggleAutostart: (enable: boolean) => invoke<boolean>("toggle_autostart", { enable }),
  listProcesses: () => invoke<ProcessItem[]>("list_processes"),
  killProcess: (pid: number) => invoke<void>("kill_process", { pid }),
  inspectProcessMemory: (pid: number) => invoke<ThreatRow[]>("inspect_process_memory", { pid }),
  securityAudit: () => invoke<SecurityAuditReport>("security_audit"),
  syncThreatFeeds: () => invoke<FeedSyncResult>("sync_threat_feeds"),
  deployHoneypot: () => invoke<string>("deploy_ransomware_honeypot"),
  getProtectionConfig: () => invoke<ProtectionConfig>("get_protection_config"),
  setProtectionConfig: (dto: ProtectionConfig) => invoke<void>("set_protection_config", { dto }),
  getGameModeStatus: () => invoke<GameModeStatus>("get_game_mode_status"),
  toggleGameMode: (enabled: boolean) => invoke<GameModeStatus>("toggle_game_mode", { enabled }),
  getScanProgress: () => invoke<ScanProgress>("get_scan_progress"),
  getSmartScanTarget: () => invoke<string>("get_smart_scan_target"),
  scanAndroidPackage: (path: string) => invoke<ApkReport>("scan_android_package", { path }),
};

export interface DexAnalysis {
  is_valid_dex: boolean;
  string_count: number;
  detected_indicators: string[];
  suspicious_strings: string[];
  risk_score: number;
}

export interface ApkReport {
  filename: string;
  package_name: string | null;
  sha256: string;
  size_bytes: number;
  dangerous_permissions: string[];
  total_permissions: number;
  dex_analyses: DexAnalysis[];
  threats: string[];
  overall_risk_score: number;
  verdict: string;
}

export interface ScanProgress {
  is_active: boolean;
  current_file: string;
  scanned: number;
  total: number;
  threats: number;
  rate: number;
  elapsed_secs: number;
  percent: number;
}

export interface ProtectionConfig {
  realtime_filesystem: boolean;
  memory_defense: boolean;
  network_firewall: boolean;
  ransomware_guard: boolean;
  cloud_threat_feeds: boolean;
  game_mode_enabled: boolean;
  game_mode_auto_detect: boolean;
  entropy_threshold: number;
}

export interface GameModeStatus {
  is_gaming_active: boolean;
  game_mode_enabled: boolean;
  auto_detect: boolean;
  priority_lowered: boolean;
  background_scans_paused: boolean;
}

export function impactColor(i: number): string {
  switch (i) {
    case 0:
      return "text-ok";
    case 1:
      return "text-accent";
    case 2:
      return "text-warn";
    default:
      return "text-danger";
  }
}

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
