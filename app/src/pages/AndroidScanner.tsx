import { useState } from "react";
import {
  Smartphone,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  FolderSearch,
  CheckCircle2,
  FileCode,
  Lock,
} from "lucide-react";
import { api, fmtBytes, type ApkReport } from "@/lib/api";
import { Button, Card, SectionTitle, Badge, Spinner, ProtectionGauge } from "@/components/ui";

export default function AndroidScanner() {
  const [apkPath, setApkPath] = useState("C:\\Users\\raio\\Downloads");
  const [report, setReport] = useState<ApkReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!apkPath.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.scanAndroidPackage(apkPath.trim());
      setReport(res);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6 max-w-6xl">
      <SectionTitle
        title="Android Antivirus & APK Inspector"
        subtitle="Static APK container analysis: audits AndroidManifest.xml permissions, Dalvik bytecode overlays, and banking trojan indicators."
      />

      {/* Target APK Path Selection */}
      <Card className="p-5">
        <div className="flex flex-col sm:flex-row items-center gap-3">
          <div className="flex flex-1 items-center gap-2.5 rounded-xl border border-line bg-surface-2 px-4 py-2.5 w-full">
            <Smartphone size={18} className="text-brand" />
            <input
              value={apkPath}
              onChange={(e) => setApkPath(e.target.value)}
              placeholder="Absolute path to .apk or .dex file (e.g. C:\Downloads\app.apk)..."
              className="flex-1 bg-transparent text-xs text-fg outline-none placeholder:text-fg-subtle font-mono font-medium"
            />
          </div>

          <Button
            variant="primary"
            size="md"
            onClick={handleScan}
            disabled={busy || !apkPath.trim()}
          >
            {busy ? <Spinner /> : <FolderSearch size={16} />}
            {busy ? "Auditing Package..." : "Analyze Package"}
          </Button>
        </div>
      </Card>

      {error && (
        <Card className="p-4 border-danger/30 bg-danger-soft flex items-center gap-3">
          <AlertTriangle size={18} className="text-danger shrink-0" />
          <div className="text-xs text-danger font-mono">{error}</div>
        </Card>
      )}

      {/* Report Section */}
      {report && (
        <div className="space-y-6">
          {/* Top Score Banner */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
            <Card className="p-6 text-center flex flex-col items-center">
              <span className="text-xs font-bold text-fg-muted uppercase tracking-wider mb-4">
                Package Threat Score
              </span>
              <ProtectionGauge
                percent={report.overall_risk_score}
                color={report.overall_risk_score >= 70 ? "rgb(var(--danger))" : report.overall_risk_score >= 35 ? "rgb(var(--warn))" : "rgb(var(--ok))"}
                size={160}
                strokeWidth={14}
              />
              <div className="mt-4">
                <Badge
                  color={
                    report.verdict === "Malicious"
                      ? "danger"
                      : report.verdict === "Suspicious"
                      ? "warn"
                      : "ok"
                  }
                >
                  {report.verdict}
                </Badge>
              </div>
            </Card>

            <Card className="md:col-span-2 p-6 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-line">
                <div>
                  <h3 className="text-base font-bold text-fg">
                    {report.package_name || report.filename}
                  </h3>
                  <div className="text-xs text-fg-muted font-mono mt-0.5">
                    File: {report.filename} ({fmtBytes(report.size_bytes)})
                  </div>
                </div>
                <Badge color="neutral">Android Application</Badge>
              </div>

              <div className="space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between text-fg-muted">
                  <span>SHA-256 Digest</span>
                  <span className="truncate max-w-sm text-fg font-bold">{report.sha256}</span>
                </div>
                <div className="flex items-center justify-between text-fg-muted">
                  <span>Total Declared Permissions</span>
                  <span className="text-fg font-bold tab-nums">{report.total_permissions}</span>
                </div>
                <div className="flex items-center justify-between text-fg-muted">
                  <span>Identified Threat Families</span>
                  <span className="text-danger font-bold">{report.threats.length} flags</span>
                </div>
              </div>
            </Card>
          </div>

          {/* Identified Threat Families */}
          {report.threats.length > 0 && (
            <Card className="p-6 space-y-3 border-brand/30 bg-brand-soft">
              <div className="flex items-center gap-2 text-sm font-bold text-danger">
                <ShieldAlert size={18} />
                <span>Malicious Behavioral Patterns Identified</span>
              </div>
              <div className="space-y-2">
                {report.threats.map((t, i) => (
                  <div
                    key={i}
                    className="p-3 rounded-xl bg-surface border border-brand/30 flex items-center justify-between"
                  >
                    <span className="font-bold text-xs text-fg">{t}</span>
                    <Badge color="danger">High Risk</Badge>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Dangerous Permissions Breakdown */}
          <Card className="p-6 space-y-4">
            <h3 className="text-sm font-bold text-fg">
              Privileged & Dangerous Permissions Audited ({report.dangerous_permissions.length})
            </h3>
            {report.dangerous_permissions.length === 0 ? (
              <div className="text-xs text-ok flex items-center gap-2">
                <CheckCircle2 size={16} />
                <span>No high-risk or invasive Android permissions declared in manifest.</span>
              </div>
            ) : (
              <div className="divide-y divide-line">
                {report.dangerous_permissions.map((p, i) => (
                  <div key={i} className="py-2.5 flex items-center justify-between text-xs font-mono">
                    <span className="text-fg">{p}</span>
                    <Badge color="warn">Privileged</Badge>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}
