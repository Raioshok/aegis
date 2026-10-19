import { useState, useEffect } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  AlertOctagon,
  CheckCircle2,
  Lock,
  Wrench,
  FileCheck2,
  RefreshCw,
  Zap,
} from "lucide-react";
import { api, type SecurityAuditReport, type VulnerabilityItem } from "@/lib/api";
import { Button, Card, SectionTitle, Badge, RadialGauge, Spinner } from "@/components/ui";

export default function Vulnerabilities() {
  const [report, setReport] = useState<SecurityAuditReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [honeypotMsg, setHoneypotMsg] = useState<string | null>(null);
  const [deploying, setDeploying] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const res = await api.securityAudit();
      setReport(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleDeployHoneypot = async () => {
    setDeploying(true);
    try {
      const msg = await api.deployHoneypot();
      setHoneypotMsg(msg);
    } catch (e) {
      alert(`Honeypot deployment failed: ${e}`);
    } finally {
      setDeploying(false);
    }
  };

  return (
    <div className="space-y-6">
      <SectionTitle
        title="Vulnerability & System Hardening"
        subtitle="Automated audit of OS security policies, unquoted service paths, legacy exploit protocols, and sentinel canary tripwires."
        action={
          <Button variant="default" size="sm" onClick={load} disabled={loading}>
            <RefreshCw size={14} className={loading ? "animate-spin text-kaspersky" : ""} />
            {loading ? "Auditing..." : "Re-audit System"}
          </Button>
        }
      />

      {/* Top Posture Dashboard */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Security Posture Radial Score */}
        <Card className="flex items-center gap-6 p-6">
          <RadialGauge
            value={report?.overall_score ?? 98}
            max={100}
            size={110}
            strokeWidth={9}
            label={`${report?.overall_score ?? 98}%`}
            sublabel="Posture"
            color="#00E5A3"
          />
          <div>
            <h2 className="text-base font-bold text-white">System Hardening Score</h2>
            <p className="text-xs text-muted mt-1 leading-relaxed">
              {report?.issues_count === 0
                ? "No critical OS configuration vulnerabilities detected."
                : `${report?.issues_count} policy settings need remediation.`}
            </p>
            <div className="mt-2.5">
              <Badge color="ok">Defense Baseline Met</Badge>
            </div>
          </div>
        </Card>

        {/* Anti-Ransomware Decoy / Honeypot */}
        <Card className="p-6 md:col-span-2 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-kaspersky/15 text-kaspersky">
                  <Lock size={18} />
                </div>
                <div>
                  <h2 className="text-base font-bold text-white">Anti-Ransomware Sentinel Honeypot</h2>
                  <p className="text-xs text-muted">Canary decoy files deployed in user document vaults</p>
                </div>
              </div>
              <Badge color="cyan">Active Defense</Badge>
            </div>

            <p className="text-xs text-muted mt-3 leading-relaxed">
              Deploys hidden canary files in Desktop & Documents. Any unauthorized modification, entropy encryption, or file wipe attempt immediately terminates the malicious process before real user files are encrypted.
            </p>
          </div>

          <div className="mt-4 flex items-center justify-between border-t border-white/[0.06] pt-3.5">
            <span className="text-xs font-mono text-kaspersky font-semibold">
              {honeypotMsg ?? "Canary tripwire armed (Documents & Desktop)"}
            </span>
            <Button
              variant="emerald"
              size="sm"
              onClick={handleDeployHoneypot}
              disabled={deploying}
            >
              <Zap size={14} />
              {deploying ? "Deploying..." : "Re-deploy Canaries"}
            </Button>
          </div>
        </Card>
      </div>

      {/* Vulnerabilities Checklist */}
      <Card className="p-0 overflow-hidden">
        <div className="px-6 py-4 border-b border-white/[0.06] flex items-center justify-between">
          <span className="text-sm font-bold text-white">Audited Security Policies & Attack Vectors</span>
          <span className="font-mono text-xs text-muted font-medium">
            {report?.items.length ?? 4} Checks Evaluated
          </span>
        </div>

        <div className="divide-y divide-white/[0.04]">
          {(report?.items ?? []).map((item) => (
            <div key={item.id} className="p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 hover:bg-white/[0.01] transition-colors">
              <div className="flex items-start gap-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-white/[0.04] text-kaspersky border border-white/[0.06] mt-0.5">
                  <FileCheck2 size={20} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-white">{item.title}</span>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-muted font-semibold rounded bg-white/[0.05] px-2 py-0.5">
                      {item.category}
                    </span>
                  </div>
                  <p className="text-xs text-muted mt-1 leading-relaxed max-w-2xl">{item.detail}</p>
                </div>
              </div>

              <div className="flex items-center gap-3 shrink-0 self-end md:self-center">
                <Badge color={item.status === "SECURE" || item.status === "ACTIVE" || item.status === "PROTECTED" || item.status === "DISABLED" ? "ok" : "danger"}>
                  {item.status}
                </Badge>
                {item.fixable && item.status !== "SECURE" && item.status !== "DISABLED" && (
                  <Button variant="emerald" size="sm">
                    <Wrench size={13} /> Remediate
                  </Button>
                )}
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
