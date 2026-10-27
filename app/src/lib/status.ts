// Pure status logic for the Home screen (kept free of JSX so node can test it).
import type { Dashboard as DashboardData, HistoryRow } from "./api";

export type PageId = "settings" | "scan";

const DAY = 86_400;

/** Human "3 hours ago" for a unix-seconds timestamp. */
export function ago(epoch: number | null | undefined): string {
  if (!epoch) return "never";
  const s = Math.max(0, Date.now() / 1000 - epoch);
  if (s < 90) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < DAY) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / DAY)} days ago`;
}

interface Issue {
  text: string;
  action?: { label: string; page: PageId };
}

/** Everything that keeps the device from being fully protected, from real state only. */
export function findIssues(d: DashboardData, lastScan: HistoryRow | undefined): Issue[] {
  const issues: Issue[] = [];
  if (!d.daemon_running) {
    issues.push({ text: "The Aegis service (aegisd) is not running, so files are not checked as they arrive." });
  } else if (!d.realtime?.enabled) {
    issues.push({ text: "Real-time protection is turned off.", action: { label: "Open settings", page: "settings" } });
  }
  const now = Date.now() / 1000;
  if (!d.last_feed_sync) {
    issues.push({ text: "Threat databases have never been downloaded; only the built-in signatures are used." });
  } else if (now - d.last_feed_sync > 7 * DAY) {
    issues.push({ text: `Threat databases are ${Math.round((now - d.last_feed_sync) / DAY)} days old.` });
  }
  if (!lastScan) {
    issues.push({ text: "No scan has been run yet.", action: { label: "Scan now", page: "scan" } });
  } else if (now - lastScan.finished > 14 * DAY) {
    issues.push({ text: `Last scan was ${ago(lastScan.finished)}.`, action: { label: "Scan now", page: "scan" } });
  }
  return issues;
}

