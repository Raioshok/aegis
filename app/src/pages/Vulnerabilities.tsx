import { useEffect, useState } from "react";
import { CheckCircle2, XCircle, HelpCircle, RefreshCw, Wrench, Cpu, Lock } from "lucide-react";
import { api, type SecurityAuditReport, type HardeningCheck, type ThreatRow } from "@/lib/api";
import { Button, Card, SectionTitle, Badge, RadialGauge, Spinner, Empty } from "@/components/ui";
import { cn } from "@/lib/utils";

const SEVERITY_COLOR = { Critical: "danger", High: "warn", Medium: "blue", Low: "neutral" } as const;

export default function Vulnerabilities() {
  const [report, setReport] = useState<SecurityAuditReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [fixing, setFixing] = useState<string | null>(null);
  const [fixError, setFixError] = useState<Record<string, string>>({});
  const [drivers, setDrivers] = useState<ThreatRow[] | null>(null);
  const [driversLoading, setDriversLoading] = useState(false);
  const [honeypot, setHoneypot] = useState<string | null>(null);
  const [deploying, setDeploying] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      setReport(await api.securityAudit());
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  const fix = async (c: HardeningCheck) => {
    setFixing(c.id);
    setFixError((e) => ({ ...e, [c.id]: "" }));
    try {
      await api.applyHardeningFix(c.id);
      await load();
    } catch (e) {
      setFixError((prev) => ({ ...prev, [c.id]: String(e) }));
    } finally {
      setFixing(null);
    }
  };

  const auditDrivers = async () => {
    setDriversLoading(true);
    try {
      setDrivers(await api.driverAudit());
    } finally {
      setDriversLoading(false);
    }
  };

  const deployHoneypot = async () => {
    setDeploying(true);
    try {
      setHoneypot(await api.deployHoneypot());
    } catch (e) {
      setHoneypot(`Failed: ${e}`);
    } finally {
      setDeploying(false);
    }
  };

  const failing = report?.items.filter((i) => i.state === "fail") ?? [];

  return (
    <div className="space-y-6">
      <SectionTitle
        title="Hardening"
        subtitle="Reads this computer's security settings and checks installed kernel drivers against known vulnerable ones."
        action={
          <Button variant="outline" onClick={load} disabled={loading}>
            <RefreshCw size={15} className={loading ? "animate-spin" : ""} />
            {loading ? "Checking…" : "Check again"}
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="flex items-center gap-6 p-6">
          {report ? (
            <RadialGauge value={report.overall_score} size={112} strokeWidth={10} label="score" />
          ) : (
            <Spinner />
          )}
          <div>
            <div className="text-base font-semibold">Security settings</div>
            <p className="mt-1 text-[13px] leading-relaxed text-fg-muted">
              {!report
                ? "Reading settings…"
                : failing.length === 0
                  ? `All ${report.items.length} checks pass.`
                  : `${failing.length} of ${report.items.length} checks need attention.`}
            </p>
          </div>
        </Card>

        <Card className="flex flex-col justify-between p-6">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-violet-soft text-violet">
              <Cpu size={19} />
            </div>
            <div>
              <div className="text-base font-semibold">Vulnerable drivers</div>
              <p className="mt-1 text-[13px] leading-relaxed text-fg-muted">
                Hashes every registered kernel driver and compares it to the built-in list and the LOLDrivers feed
                (update databases on Home to refresh it). Windows only.
              </p>
            </div>
          </div>
          <div className="mt-4 flex items-center justify-between gap-3">
            <span className="text-xs text-fg-muted">
              {drivers === null ? "Not checked yet" : drivers.length === 0 ? "No known vulnerable driver found" : `${drivers.length} found`}
            </span>
            <Button size="sm" variant="primary" onClick={auditDrivers} disabled={driversLoading}>
              {driversLoading ? "Checking…" : "Check drivers"}
            </Button>
          </div>
        </Card>

        <Card className="flex flex-col justify-between p-6">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-warn-soft text-warn">
              <Lock size={19} />
            </div>
            <div>
              <div className="text-base font-semibold">Ransomware decoys</div>
              <p className="mt-1 text-[13px] leading-relaxed text-fg-muted">
                Places decoy files in Documents and Desktop and adds those folders to real-time protection. Any change to
                a decoy raises a ransomware alert (and stops the process when it can be identified and auto-kill is on).
              </p>
            </div>
          </div>
          <div className="mt-4 flex items-center justify-between gap-3">
            <span className="text-xs text-fg-muted">{honeypot ?? "Existing files are never overwritten."}</span>
            <Button size="sm" variant="outline" onClick={deployHoneypot} disabled={deploying}>
              {deploying ? "Placing…" : "Place decoys"}
            </Button>
          </div>
        </Card>
      </div>

      {drivers && drivers.length > 0 && (
        <Card className="border-danger/30 p-0">
          <div className="border-b border-line px-5 py-3.5 text-sm font-semibold text-danger">Vulnerable drivers installed</div>
          <ul className="divide-y divide-line">
            {drivers.map((d) => (
              <li key={d.names} className="px-5 py-3 text-[13px]">
                <div className="font-semibold">{d.names}</div>
                <div className="mt-0.5 break-all text-xs text-fg-muted">{d.path}</div>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card className="overflow-hidden p-0">
        <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
          <span className="text-sm font-semibold">Checks</span>
          <span className="text-xs text-fg-muted">Fixes need Aegis to run as administrator (Windows) or root (Linux)</span>
        </div>
        {report && report.items.length === 0 && <Empty title="No checks for this operating system" />}
        <ul className="divide-y divide-line">
          {(report?.items ?? []).map((c) => (
            <li key={c.id} className="flex flex-col gap-3 px-5 py-4 md:flex-row md:items-center md:justify-between">
              <div className="flex items-start gap-3">
                <StateIcon state={c.state} />
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[14px] font-semibold">{c.title}</span>
                    <Badge color={SEVERITY_COLOR[c.severity]}>{c.severity}</Badge>
                    <span className="text-xs text-fg-subtle">{c.category}</span>
                  </div>
                  <p className="mt-1 font-mono text-xs text-fg-muted">{c.detail}</p>
                  {fixError[c.id] && <p className="mt-1 text-xs text-danger">{fixError[c.id]}</p>}
                </div>
              </div>
              {c.state === "fail" && c.fixable && (
                <Button size="sm" variant="primary" onClick={() => fix(c)} disabled={fixing !== null} className="shrink-0 self-end md:self-center">
                  <Wrench size={13} /> {fixing === c.id ? "Fixing…" : "Fix"}
                </Button>
              )}
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}

function StateIcon({ state }: { state: HardeningCheck["state"] }) {
  const Icon = state === "pass" ? CheckCircle2 : state === "fail" ? XCircle : HelpCircle;
  return (
    <Icon
      size={20}
      aria-label={state}
      className={cn("mt-0.5 shrink-0", state === "pass" ? "text-ok" : state === "fail" ? "text-danger" : "text-fg-subtle")}
    />
  );
}
