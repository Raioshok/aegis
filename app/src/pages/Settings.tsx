import { useEffect, useState, type ReactNode } from "react";
import { api, type ProtectionConfig, type GameModeStatus } from "@/lib/api";
import { Card, SectionTitle, Switch, Spinner, Badge } from "@/components/ui";

export default function Settings() {
  const [config, setConfig] = useState<ProtectionConfig | null>(null);
  const [gameMode, setGameMode] = useState<GameModeStatus | null>(null);
  const [autostart, setAutostart] = useState<boolean | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  useEffect(() => {
    api.getProtectionConfig().then(setConfig).catch((e) => setError(String(e)));
    api.isAutostartActive().then(setAutostart).catch(() => setAutostart(null));
    const poll = () => api.getGameModeStatus().then(setGameMode).catch(() => {});
    poll();
    const id = window.setInterval(poll, 3000);
    return () => window.clearInterval(id);
  }, []);

  const save = async (next: ProtectionConfig) => {
    const prev = config;
    setConfig(next);
    setSaving(true);
    setError(null);
    try {
      await api.setProtectionConfig(next);
      setSavedAt(Date.now());
      api.getGameModeStatus().then(setGameMode).catch(() => {});
    } catch (e) {
      setConfig(prev);
      setError(String(e));
    } finally {
      setSaving(false);
    }
  };
  const set = <K extends keyof ProtectionConfig>(key: K, value: ProtectionConfig[K]) => config && save({ ...config, [key]: value });

  const toggleAutostart = async () => {
    if (autostart === null) return;
    try {
      setAutostart(await api.toggleAutostart(!autostart));
    } catch (e) {
      setError(String(e));
    }
  };

  if (!config) {
    return (
      <div className="flex items-center justify-center gap-3 py-24 text-sm text-fg-muted">
        {error ? <span className="text-danger">{error}</span> : <><Spinner /> Loading settings…</>}
      </div>
    );
  }

  return (
    <div className="max-w-3xl space-y-6">
      <SectionTitle
        title="Settings"
        subtitle="Saved to the Aegis config file. Real-time changes take effect when the aegisd service restarts."
        action={
          <span className="text-xs text-fg-muted" aria-live="polite">
            {saving ? "Saving…" : savedAt ? "Saved" : ""}
          </span>
        }
      />
      {error && <div className="rounded-xl border border-danger/30 bg-danger-soft px-4 py-3 text-xs text-danger">{error}</div>}

      <Section title="Real-time protection">
        <Toggle label="Check files as they are written" hint="Runs in the aegisd service." checked={config.realtime_enabled} onChange={(v) => set("realtime_enabled", v)} />
        <Toggle label="Quarantine detections automatically" hint="Otherwise detections are only recorded." checked={config.auto_quarantine} onChange={(v) => set("auto_quarantine", v)} />
        <Toggle
          label="Block detected programs before they run"
          hint="Linux with the fanotify backend: each program launch waits for a scan."
          checked={config.block_exec}
          onChange={(v) => set("block_exec", v)}
        />
      </Section>

      <Section title="Ransomware guard">
        <Toggle label="Watch for mass encryption and decoy tampering" checked={config.ransomware_guard} onChange={(v) => set("ransomware_guard", v)} />
        <Toggle
          label="Stop the offending process"
          hint="Needs a backend that reports the process (Linux fanotify)."
          checked={config.ransomware_auto_kill}
          disabled={!config.ransomware_guard}
          onChange={(v) => set("ransomware_auto_kill", v)}
        />
      </Section>

      <Section title="Detection">
        <Toggle label="Download threat databases daily" hint="abuse.ch MalwareBazaar and Feodo Tracker, LOLDrivers." checked={config.auto_update_feeds} onChange={(v) => set("auto_update_feeds", v)} />
        <Toggle label="Machine-learning engine" hint="Gradient boosted trees over PE file structure." checked={config.ml_engine} onChange={(v) => set("ml_engine", v)} />
        <div className="flex items-center justify-between gap-6 px-5 py-4">
          <div>
            <div className="text-[13px] font-medium">Packed-file entropy threshold</div>
            <div className="mt-0.5 text-xs text-fg-muted">Lower flags more files as packed (more detections, more false alarms).</div>
          </div>
          <div className="flex shrink-0 items-center gap-3">
            <input
              type="range"
              min={6}
              max={8}
              step={0.05}
              value={config.entropy_threshold}
              onChange={(e) => setConfig({ ...config, entropy_threshold: Number(e.target.value) })}
              onPointerUp={() => save(config)}
              onKeyUp={() => save(config)}
              aria-label="Entropy threshold"
              className="w-36 cursor-pointer accent-brand"
            />
            <span className="w-10 text-right text-xs tabular-nums">{config.entropy_threshold.toFixed(2)}</span>
          </div>
        </div>
      </Section>

      <Section title="Game mode">
        <Toggle
          label="Lower Aegis priority and pause scheduled scans while gaming"
          checked={config.game_mode_enabled}
          onChange={(v) => set("game_mode_enabled", v)}
        />
        <Toggle
          label="Only when a full-screen app is detected"
          checked={config.game_mode_auto_detect}
          disabled={!config.game_mode_enabled}
          onChange={(v) => set("game_mode_auto_detect", v)}
        />
        {gameMode && (
          <div className="flex flex-wrap gap-2 px-5 py-3.5 text-xs">
            <Badge color={gameMode.is_gaming_active ? "accent" : "neutral"}>{gameMode.is_gaming_active ? "Full-screen app detected" : "No full-screen app"}</Badge>
            <Badge color={gameMode.priority_lowered ? "ok" : "neutral"}>{gameMode.priority_lowered ? "Priority lowered" : "Normal priority"}</Badge>
            <Badge color={gameMode.background_scans_paused ? "ok" : "neutral"}>{gameMode.background_scans_paused ? "Scheduled scans paused" : "Scheduled scans run"}</Badge>
          </div>
        )}
      </Section>

      <Section title="Startup">
        <Toggle
          label="Open Aegis when I sign in"
          hint={autostart === null ? "Could not read the startup setting." : undefined}
          checked={autostart ?? false}
          disabled={autostart === null}
          onChange={toggleAutostart}
        />
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h2 className="mb-2 px-1 text-xs font-semibold uppercase tracking-wider text-fg-subtle">{title}</h2>
      <Card className="divide-y divide-line p-0">{children}</Card>
    </section>
  );
}

function Toggle({
  label,
  hint,
  checked,
  disabled,
  onChange,
}: {
  label: string;
  hint?: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-6 px-5 py-4">
      <div className={disabled ? "opacity-50" : ""}>
        <div className="text-[13px] font-medium">{label}</div>
        {hint && <div className="mt-0.5 text-xs text-fg-muted">{hint}</div>}
      </div>
      <Switch checked={checked} onChange={onChange} disabled={disabled} label={label} />
    </div>
  );
}
