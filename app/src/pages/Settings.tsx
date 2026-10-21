import { useEffect, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Gamepad2,
  HardDrive,
  Cpu,
  Network,
  Zap,
  Sliders,
  CheckCircle2,
  RefreshCw,
  Layers,
  Brain,
  EyeOff,
  FileCode2,
} from "lucide-react";
import {
  api,
  type ProtectionConfig,
  type GameModeStatus,
} from "@/lib/api";
import { Badge, Button, Card, SectionTitle, Switch } from "@/components/ui";

export default function Settings() {
  const [config, setConfig] = useState<ProtectionConfig>({
    realtime_filesystem: true,
    memory_defense: true,
    network_firewall: true,
    ransomware_guard: true,
    cloud_threat_feeds: true,
    game_mode_enabled: true,
    game_mode_auto_detect: true,
    entropy_threshold: 7.2,
    ml_engine: true,
    byovd_defense: true,
    sleep_obfuscation_defense: true,
  });
  const [gameMode, setGameMode] = useState<GameModeStatus | null>({
    is_gaming_active: false,
    game_mode_enabled: true,
    auto_detect: true,
    priority_lowered: false,
    background_scans_paused: false,
  });
  const [autostart, setAutostart] = useState(false);
  const [busy, setBusy] = useState(false);
  const [savedMessage, setSavedMessage] = useState(false);

  const load = async () => {
    try {
      const cfg = await api.getProtectionConfig();
      const gm = await api.getGameModeStatus();
      const auto = await api.isAutostartActive();
      setConfig(cfg);
      setGameMode(gm);
      setAutostart(auto);
    } catch (e) {
      console.error("Failed to load settings:", e);
    }
  };

  useEffect(() => {
    load();
    const interval = setInterval(() => {
      api.getGameModeStatus().then(setGameMode).catch(() => {});
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleSave = async (updated: ProtectionConfig) => {
    setBusy(true);
    try {
      await api.setProtectionConfig(updated);
      setConfig(updated);
      const gm = await api.getGameModeStatus();
      setGameMode(gm);
      setSavedMessage(true);
      setTimeout(() => setSavedMessage(false), 2500);
    } catch (e) {
      console.error("Failed to save protection config:", e);
    } finally {
      setBusy(false);
    }
  };

  const toggleShield = (key: keyof ProtectionConfig) => {
    if (!config) return;
    const next = { ...config, [key]: !config[key] };
    handleSave(next);
  };

  const handleAutostartToggle = async () => {
    const next = !autostart;
    setAutostart(next);
    await api.toggleAutostart(next);
  };

  if (!config) {
    return (
      <div className="flex items-center justify-center py-20 text-xs text-[#64748B] font-mono">
        Loading configuration...
      </div>
    );
  }

  const allShieldsActive =
    config.realtime_filesystem &&
    config.memory_defense &&
    config.network_firewall &&
    config.ransomware_guard;

  return (
    <div className="space-y-6 max-w-6xl">
      <SectionTitle
        title="Shields & Protection Settings"
        subtitle="Modular security shields, real-time file inspection, and Kaspersky-style Game Mode resource throttling."
        action={
          <div className="flex items-center gap-3">
            {savedMessage && (
              <span className="text-xs text-[#059669] font-bold flex items-center gap-1.5 bg-[#ECFDF5] px-3 py-1 rounded-full border border-[#A7F3D0]">
                <CheckCircle2 size={14} /> Settings Saved
              </span>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={load}
              disabled={busy}
            >
              <RefreshCw size={13} className={busy ? "animate-spin text-[#FF7222]" : ""} /> Refresh
            </Button>
          </div>
        }
      />

      {/* Master Real-Time Protection Banner */}
      <Card
        className={`p-6 border transition-all ${
          allShieldsActive
            ? "border-[#A7F3D0] bg-[#ECFDF5]"
            : "border-[#FFD8BF] bg-[#FFF8F3]"
        }`}
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div
              className={`flex h-12 w-12 items-center justify-center rounded-2xl font-bold shrink-0 ${
                allShieldsActive
                  ? "bg-[#10B981] text-white shadow-sm"
                  : "bg-[#FF7222] text-white shadow-sm"
              }`}
            >
              {allShieldsActive ? <ShieldCheck size={28} /> : <ShieldAlert size={28} />}
            </div>
            <div>
              <div className="text-base font-bold text-[#1E293B] flex items-center gap-2">
                Real-Time Protection Status
                <Badge color={allShieldsActive ? "ok" : "warn"}>
                  {allShieldsActive ? "Fully Armed" : "Partially Armed"}
                </Badge>
              </div>
              <p className="text-xs text-[#64748B] mt-0.5 max-w-xl">
                {allShieldsActive
                  ? "Continuous on-access scanning, memory injection interception, and network egress rules are active."
                  : "One or more defensive shields are currently disabled. Re-enable all shields for optimal defense."}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant={allShieldsActive ? "outline" : "primary"}
              size="sm"
              onClick={() => {
                const next = {
                  ...config,
                  realtime_filesystem: !allShieldsActive,
                  memory_defense: !allShieldsActive,
                  network_firewall: !allShieldsActive,
                  ransomware_guard: !allShieldsActive,
                  cloud_threat_feeds: !allShieldsActive,
                };
                handleSave(next);
              }}
            >
              {allShieldsActive ? "Disable All Shields" : "Enable All Shields"}
            </Button>
          </div>
        </div>
      </Card>

      {/* Kaspersky-Style Gaming Mode Console */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-[#1E293B] flex items-center gap-2">
            <Gamepad2 size={18} className="text-[#FF7222]" />
            Game Mode (Resource Throttling)
          </h2>
          <Badge color={gameMode?.priority_lowered ? "ok" : "neutral"}>
            {gameMode?.priority_lowered
              ? "Resource Throttled (Game Mode Active)"
              : "Desktop Mode (Full Performance)"}
          </Badge>
        </div>

        <Card className="p-6 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#EAEFF5]">
            <div>
              <div className="text-sm font-bold text-[#1E293B] flex items-center gap-2">
                Game Mode Master Control
                {gameMode?.is_gaming_active && (
                  <span className="text-[11px] font-mono font-bold text-[#059669]">
                    [🎮 Direct3D / Fullscreen App Detected]
                  </span>
                )}
              </div>
              <p className="text-xs text-[#64748B] mt-1 max-w-xl">
                Automatically detects when full-screen Direct3D games or GPU applications are running.
                Lowers Aegis CPU priority to IDLE, pauses background scans, and suppresses notifications.
              </p>
            </div>
            <Switch
              checked={config.game_mode_enabled}
              onChange={() => toggleShield("game_mode_enabled")}
              label="Enable Game Mode"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="flex items-center justify-between p-4 rounded-xl bg-[#F8FAFC] border border-[#EAEFF5]">
              <div>
                <span className="text-xs font-bold text-[#1E293B] block">Auto-Detect Fullscreen & D3D</span>
                <span className="text-[11px] text-[#64748B] block mt-0.5">
                  Uses Windows SHQueryUserNotificationState
                </span>
              </div>
              <Switch
                checked={config.game_mode_auto_detect}
                onChange={() => toggleShield("game_mode_auto_detect")}
                disabled={!config.game_mode_enabled}
                label="Auto Detect"
              />
            </div>

            <div className="flex items-center justify-between p-4 rounded-xl bg-[#F8FAFC] border border-[#EAEFF5]">
              <div>
                <span className="text-xs font-bold text-[#1E293B] block">Aegis CPU Priority Status</span>
                <span className="text-[11px] text-[#64748B] block mt-0.5 font-mono">
                  {gameMode?.priority_lowered ? "IDLE_PRIORITY_CLASS (Throttled)" : "NORMAL_PRIORITY_CLASS"}
                </span>
              </div>
              <Badge color={gameMode?.priority_lowered ? "ok" : "neutral"}>
                {gameMode?.priority_lowered ? "Low CPU" : "Normal"}
              </Badge>
            </div>
          </div>
        </Card>
      </div>

      {/* Individual Modular Shields */}
      <div className="space-y-3">
        <h2 className="text-sm font-bold text-[#1E293B] flex items-center gap-2">
          <Layers size={18} className="text-[#FF7222]" />
          Modular Defensive Shields
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* File System Shield */}
          <Card className="p-5 flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#ECFDF5] text-[#059669] shrink-0">
                <HardDrive size={20} />
              </div>
              <div>
                <div className="text-sm font-bold text-[#1E293B]">File System Shield</div>
                <p className="text-xs text-[#64748B] mt-1 leading-relaxed">
                  Scans files in real time on open, write, and execute using zero-copy memory mapping.
                </p>
              </div>
            </div>
            <Switch
              checked={config.realtime_filesystem}
              onChange={() => toggleShield("realtime_filesystem")}
              label="Toggle File Shield"
            />
          </Card>

          {/* Memory & Injection Defense */}
          <Card className="p-5 flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#EFF6FF] text-[#2563EB] shrink-0">
                <Cpu size={20} />
              </div>
              <div>
                <div className="text-sm font-bold text-[#1E293B]">Memory & Thread Defense</div>
                <p className="text-xs text-[#64748B] mt-1 leading-relaxed">
                  Detects unbacked private threads, thread context/RIP hijacking, and AMSI/ETW unhooking.
                </p>
              </div>
            </div>
            <Switch
              checked={config.memory_defense}
              onChange={() => toggleShield("memory_defense")}
              label="Toggle Memory Defense"
            />
          </Card>

          {/* Network & Host Firewall */}
          <Card className="p-5 flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#FFF4EC] text-[#FF7222] shrink-0">
                <Network size={20} />
              </div>
              <div>
                <div className="text-sm font-bold text-[#1E293B]">Host Firewall & LOLBin Guard</div>
                <p className="text-xs text-[#64748B] mt-1 leading-relaxed">
                  Enforces WFP application filters, blocks unauthorized LOLBin network egress, and detects port scans.
                </p>
              </div>
            </div>
            <Switch
              checked={config.network_firewall}
              onChange={() => toggleShield("network_firewall")}
              label="Toggle Firewall"
            />
          </Card>

          {/* Ransomware Guard */}
          <Card className="p-5 flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#FEF2F2] text-[#DC2626] shrink-0">
                <Zap size={20} />
              </div>
              <div>
                <div className="text-sm font-bold text-[#1E293B]">Ransomware Watchdog & Rollback</div>
                <p className="text-xs text-[#64748B] mt-1 leading-relaxed">
                  Traps burst encryption storms, shadow-copy destruction commands, and initiates rollback.
                </p>
              </div>
            </div>
            <Switch
              checked={config.ransomware_guard}
              onChange={() => toggleShield("ransomware_guard")}
              label="Toggle Ransomware Guard"
            />
          </Card>

          {/* On-Device Machine Learning Shield */}
          <Card className="p-5 flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#F5F3FF] text-[#7C3AED] shrink-0">
                <Brain size={20} />
              </div>
              <div>
                <div className="text-sm font-bold text-[#1E293B]">On-Device Machine Learning (GBDT)</div>
                <p className="text-xs text-[#64748B] mt-1 leading-relaxed">
                  Pure-Rust flat-tree array evaluator running on EMBER 2024 / SOREL-20M features (&lt;40μs inference latency).
                </p>
              </div>
            </div>
            <Switch
              checked={config.ml_engine}
              onChange={() => toggleShield("ml_engine")}
              label="Toggle ML Engine"
            />
          </Card>

          {/* BYOVD Driver Shield */}
          <Card className="p-5 flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#FFF1F2] text-[#E11D48] shrink-0">
                <FileCode2 size={20} />
              </div>
              <div>
                <div className="text-sm font-bold text-[#1E293B]">BYOVD Driver Blocklist (LOLDrivers)</div>
                <p className="text-xs text-[#64748B] mt-1 leading-relaxed">
                  Intercepts vulnerable signed kernel drivers (RTCore64, gdrv, dbutil, mhyprot2) before driver service load.
                </p>
              </div>
            </div>
            <Switch
              checked={config.byovd_defense}
              onChange={() => toggleShield("byovd_defense")}
              label="Toggle BYOVD Shield"
            />
          </Card>

          {/* In-Memory Evasion Shield */}
          <Card className="p-5 flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#F0FDF4] text-[#16A34A] shrink-0">
                <EyeOff size={20} />
              </div>
              <div>
                <div className="text-sm font-bold text-[#1E293B]">In-Memory Evasion & Sleep Shield</div>
                <p className="text-xs text-[#64748B] mt-1 leading-relaxed">
                  Inspects thread wait-states for sleep obfuscation (Ekko/Foliage), synthetic stack frames, and PoolParty injection.
                </p>
              </div>
            </div>
            <Switch
              checked={config.sleep_obfuscation_defense}
              onChange={() => toggleShield("sleep_obfuscation_defense")}
              label="Toggle Evasion Shield"
            />
          </Card>
        </div>
      </div>

      {/* System Startup & Heuristic Sensitivity */}
      <div className="space-y-3">
        <h2 className="text-sm font-bold text-[#1E293B] flex items-center gap-2">
          <Sliders size={18} className="text-[#FF7222]" />
          Engine & Platform Controls
        </h2>

        <Card className="p-6 space-y-4">
          <div className="flex items-center justify-between pb-4 border-b border-[#EAEFF5]">
            <div>
              <span className="text-sm font-bold text-[#1E293B] block">Start Aegis with Windows</span>
              <span className="text-xs text-[#64748B] block mt-0.5">
                Registers background service and startup task with highest privileges.
              </span>
            </div>
            <Switch
              checked={autostart}
              onChange={handleAutostartToggle}
              label="Start on Logon"
            />
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <span className="text-sm font-bold text-[#1E293B] block">Shannon Entropy Packer Threshold</span>
              <span className="text-xs text-[#64748B] block mt-0.5">
                Binaries with entropy above this threshold are flagged as encrypted or packed (default: 7.20).
              </span>
            </div>
            <div className="flex items-center gap-3">
              <input
                type="range"
                min="7.0"
                max="7.9"
                step="0.05"
                value={config.entropy_threshold}
                onChange={(e) => {
                  const val = parseFloat(e.target.value);
                  const next = { ...config, entropy_threshold: val };
                  handleSave(next);
                }}
                className="w-36 accent-[#FF7222] cursor-pointer"
              />
              <span className="text-xs font-mono font-bold text-[#FF7222] tab-nums w-10">
                {config.entropy_threshold.toFixed(2)}
              </span>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
