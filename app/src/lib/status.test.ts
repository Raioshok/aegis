// Run: node --test src/lib/status.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { ago, findIssues } from "./status.ts";

const now = Math.floor(Date.now() / 1000);
const healthy = {
  daemon_running: true,
  version: "0.1.0",
  scans: 3,
  files: 100,
  threats: 0,
  whitelist_count: 0,
  quarantine_count: 0,
  engines: [],
  realtime: { enabled: true, backend: "inotify", events_seen: 0, threats_blocked: 0 },
  last_feed_sync: now - 3600,
  vulnerable_driver_signatures: 0,
};
const recentScan = { finished: now - 60, target: "/home", files: 10, threats: 0, kind: "ui" };

test("healthy state has no issues", () => {
  assert.deepEqual(findIssues(healthy, recentScan), []);
});

test("each real problem is reported", () => {
  const texts = findIssues({ ...healthy, daemon_running: false, last_feed_sync: null }, undefined).map((i) => i.text);
  assert.equal(texts.length, 3);
  assert.match(texts[0], /not running/);
  assert.match(texts[1], /never been downloaded/);
  assert.match(texts[2], /No scan/);
});

test("stale databases and old scans are flagged; realtime off only when daemon runs", () => {
  const issues = findIssues(
    { ...healthy, realtime: { ...healthy.realtime, enabled: false }, last_feed_sync: now - 10 * 86400 },
    { ...recentScan, finished: now - 20 * 86400 }
  );
  assert.equal(issues.length, 3);
  assert.equal(issues[0].action?.page, "settings");
  assert.match(issues[1].text, /10 days old/);
  assert.equal(issues[2].action?.page, "scan");
});

test("ago formats relative times", () => {
  assert.equal(ago(null), "never");
  assert.equal(ago(now - 10), "just now");
  assert.equal(ago(now - 2 * 86400), "2 days ago");
});
