import { cn } from "@/lib/utils";
import { type ButtonHTMLAttributes, type ReactNode } from "react";
import { ShieldCheck, AlertTriangle, ArrowRight, CheckCircle2 } from "lucide-react";

/**
 * Concentric Card Surface.
 * Outer radius: 18px (rounded-[18px]), inner padding: 20px (p-5), inner children: 12px (rounded-xl).
 * math: 18px outer = 12px inner + 6px optical delta.
 * Follows make-interfaces-feel-better Rule 1 (Concentric Radii) and Rule 3 (Layered Shadows for Elevation).
 */
export function Card({
  children,
  className,
  onClick,
}: {
  children: ReactNode;
  className?: string;
  onClick?: () => void;
}) {
  return (
    <div
      onClick={onClick}
      className={cn(
        "rounded-[18px] bg-white dark:bg-[#12141D] p-5",
        "border border-[#EAEFF5] dark:border-[#1E2230]",
        "shadow-[0_1px_3px_0_rgba(15,23,42,0.03),0_6px_16px_0_rgba(15,23,42,0.02)]",
        "dark:shadow-[0_1px_3px_0_rgba(0,0,0,0.4),0_8px_24px_0_rgba(0,0,0,0.25)]",
        "text-[#1E293B] dark:text-[#F8FAFC]",
        "transition-[border-color,box-shadow,transform] duration-150 ease-out",
        onClick && "cursor-pointer hover:border-[#DFE5EE] dark:hover:border-[#2A3042] active:scale-[0.99]",
        className
      )}
    >
      {children}
    </div>
  );
}

export function Panel({
  children,
  className,
  elevated = false,
  onClick,
}: {
  children: ReactNode;
  className?: string;
  elevated?: boolean;
  onClick?: () => void;
}) {
  return (
    <div
      onClick={onClick}
      className={cn(
        "rounded-[18px] bg-white dark:bg-[#12141D] p-5",
        "border border-[#EAEFF5] dark:border-[#1E2230]",
        "shadow-[0_1px_3px_0_rgba(15,23,42,0.03),0_6px_16px_0_rgba(15,23,42,0.02)]",
        "dark:shadow-[0_1px_3px_0_rgba(0,0,0,0.4),0_8px_24px_0_rgba(0,0,0,0.25)]",
        elevated && "border-[#DFE5EE] dark:border-[#2A3042] shadow-[0_8px_24px_-4px_rgba(15,23,42,0.06)]",
        onClick && "cursor-pointer hover:border-[#DFE5EE] dark:hover:border-[#2A3042]",
        className
      )}
    >
      {children}
    </div>
  );
}

/**
 * Tactile Button.
 * Follows make-interfaces-feel-better Rule 12: Always use exact active:scale-[0.96].
 * Follows Rule 16: Minimum hit area (40px desktop minimum height).
 * Follows Rule 14: Never transition: all — specific properties only.
 */
export function Button({
  children,
  variant = "default",
  size = "md",
  className,
  disabled,
  ...rest
}: {
  children: ReactNode;
  variant?: "default" | "primary" | "orange" | "blue" | "danger" | "ghost" | "outline" | "emerald";
  size?: "sm" | "md" | "lg";
} & ButtonHTMLAttributes<HTMLButtonElement>) {
  const base =
    "inline-flex items-center justify-center gap-2 font-medium rounded-xl select-none cursor-pointer " +
    "transition-[transform,background-color,border-color,color,box-shadow] duration-100 ease-out " +
    "active:scale-[0.96] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#FF7222] " +
    "disabled:opacity-40 disabled:cursor-not-allowed disabled:active:scale-100";

  const sizes = {
    sm: "min-h-[34px] px-3 py-1.5 text-xs font-semibold",
    md: "min-h-[40px] px-4 py-2 text-xs font-semibold",
    lg: "min-h-[44px] px-6 py-2.5 text-sm font-bold",
  };

  const variants = {
    default:
      "bg-[#F1F5F9] dark:bg-[#1A1D27] text-[#334155] dark:text-[#E2E8F0] hover:bg-[#E2E8F0] dark:hover:bg-[#232838] border border-[#E2E8F0] dark:border-[#2A3042]",
    primary:
      "bg-[#FF7222] text-white hover:bg-[#E85D10] shadow-[0_2px_8px_rgba(255,114,34,0.25)] border border-[#E85D10]",
    orange:
      "bg-[#FF7222] text-white hover:bg-[#E85D10] shadow-[0_2px_8px_rgba(255,114,34,0.25)] border border-[#E85D10]",
    blue:
      "bg-[#2563EB] text-white hover:bg-[#1D4ED8] shadow-[0_2px_8px_rgba(37,99,235,0.25)] border border-[#1D4ED8]",
    emerald:
      "bg-[#059669] text-white hover:bg-[#047857] shadow-[0_2px_8px_rgba(5,150,105,0.25)] border border-[#047857]",
    danger:
      "bg-[#DC2626] text-white hover:bg-[#B91C1C] shadow-[0_2px_8px_rgba(220,38,38,0.25)] border border-[#B91C1C]",
    outline:
      "bg-white dark:bg-[#12141D] text-[#334155] dark:text-[#E2E8F0] hover:bg-[#F8FAFC] dark:hover:bg-[#191C26] border border-[#CBD5E1] dark:border-[#2A3042] shadow-[0_1px_2px_rgba(0,0,0,0.03)]",
    ghost:
      "bg-transparent text-[#64748B] dark:text-[#94A3B8] hover:text-[#1E293B] dark:hover:text-white hover:bg-[#F1F5F9] dark:hover:bg-[#1A1D27]",
  };

  return (
    <button
      className={cn(base, sizes[size], variants[variant], className)}
      disabled={disabled}
      {...rest}
    >
      {children}
    </button>
  );
}

/**
 * Status Badge without AI-slop decoration.
 * Honest structural indicator with crisp 1px borders and tabular numbers.
 */
export function Badge({
  children,
  color = "neutral",
  className,
}: {
  children: ReactNode;
  color?: "ok" | "warn" | "danger" | "accent" | "neutral" | "muted" | "blue" | "cyan";
  className?: string;
}) {
  const colors = {
    ok: "bg-[#ECFDF5] dark:bg-[#064E3B]/30 text-[#059669] dark:text-[#34D399] border-[#A7F3D0] dark:border-[#065F46]",
    warn: "bg-[#FFF4EC] dark:bg-[#7C2D12]/30 text-[#FF7222] dark:text-[#FB923C] border-[#FFE2CC] dark:border-[#9A3412]",
    accent: "bg-[#FFF4EC] dark:bg-[#7C2D12]/30 text-[#FF7222] dark:text-[#FB923C] border-[#FFE2CC] dark:border-[#9A3412]",
    danger: "bg-[#FEF2F2] dark:bg-[#7F1D1D]/30 text-[#DC2626] dark:text-[#F87171] border-[#FECACA] dark:border-[#991B1B]",
    blue: "bg-[#EFF6FF] dark:bg-[#1E3A8A]/30 text-[#2563EB] dark:text-[#60A5FA] border-[#BFDBFE] dark:border-[#1E40AF]",
    cyan: "bg-[#F0FDF4] dark:bg-[#0C4A6E]/30 text-[#0284C7] dark:text-[#38BDF8] border-[#BAE6FD] dark:border-[#0369A1]",
    neutral: "bg-[#F1F5F9] dark:bg-[#1E2230] text-[#475569] dark:text-[#94A3B8] border-[#E2E8F0] dark:border-[#2A3042]",
    muted: "bg-[#F8FAFC] dark:bg-[#12141D] text-[#64748B] dark:text-[#8491A2] border-[#E2E8F0] dark:border-[#2A3042]",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-lg text-[11px] font-semibold border tabular-nums select-none",
        colors[color],
        className
      )}
    >
      {children}
    </span>
  );
}

/**
 * Clean Section Heading.
 * Follows make-interfaces-feel-better Rule 10: text-wrap: balance on headings, text-wrap: pretty on body text.
 */
export function SectionTitle({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#1E293B] dark:text-white [text-wrap:balance]">
          {title}
        </h1>
        {subtitle && (
          <p className="mt-1 text-xs text-[#64748B] dark:text-[#8491A2] leading-relaxed max-w-2xl [text-wrap:pretty]">
            {subtitle}
          </p>
        )}
      </div>
      {action}
    </div>
  );
}

/**
 * Type-first KPI Card.
 * Follows taste-skill §5: "KPIs are type, not tiles. No screen puts an icon in a coloured circle on a KPI."
 * Honest figures: Zeros print as zeros, missing prints as grey dash.
 */
export function StatCard({
  label,
  value,
  detail,
  icon,
  accent,
}: {
  label: string;
  value: string | number;
  detail?: string;
  icon?: ReactNode;
  accent?: string;
}) {
  return (
    <Card className="p-4 sm:p-5 flex items-center justify-between">
      <div className="space-y-1">
        <div className="text-xs text-[#64748B] dark:text-[#8491A2] font-medium [text-wrap:pretty]">
          {label}
        </div>
        <div className={cn("text-2xl font-bold text-[#1E293B] dark:text-white font-mono tabular-nums", accent)}>
          {value !== undefined && value !== null ? value : "—"}
        </div>
        {detail && (
          <div className="text-[11px] font-sans font-medium text-[#64748B] dark:text-[#8491A2] truncate">
            {detail}
          </div>
        )}
      </div>
      {icon && (
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[#F8FAFC] dark:bg-[#1A1D27] border border-[#EAEFF5] dark:border-[#2A3042] text-[#FF7222]">
          {icon}
        </div>
      )}
    </Card>
  );
}

/**
 * Tactile Switch Toggle.
 * Follows make-interfaces-feel-better Rule 12: active:scale-[0.96].
 */
export function Switch({
  checked,
  onChange,
  disabled = false,
  label,
}: {
  checked: boolean;
  onChange: (val: boolean) => void;
  disabled?: boolean;
  label?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => !disabled && onChange(!checked)}
      className={cn(
        "relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-[background-color,transform] duration-150 ease-out focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#FF7222] active:scale-[0.96]",
        checked ? "bg-[#FF7222]" : "bg-[#CBD5E1] dark:bg-[#2A3042]",
        disabled && "opacity-40 cursor-not-allowed active:scale-100"
      )}
      title={label}
    >
      <span
        className={cn(
          "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-[0_1px_3px_rgba(0,0,0,0.2)] transition-transform duration-150 ease-out",
          checked ? "translate-x-5" : "translate-x-0"
        )}
      />
    </button>
  );
}

export function Spinner() {
  return (
    <div className="h-4 w-4 animate-spin rounded-full border-2 border-[#CBD5E1] dark:border-[#2A3042] border-t-[#FF7222]" />
  );
}

/**
 * The Central Antivirus Security Status Hero Banner.
 * Designed following The Skins Factory Cybersecurity UX & taste-skill:
 * 1. Immediate, unambiguous security posture verdict ("System Protected" vs "Threats Detected").
 * 2. Active shield metric count (e.g. 8 of 8 Shields Armed).
 * 3. One-click primary action (Run Smart Scan).
 */
export function StatusHero({
  isArmed = true,
  threatCount = 0,
  activeShields = 8,
  totalShields = 8,
  onPrimaryAction,
  primaryActionLabel = "Run Smart Scan",
  lastScanTime = "Today, 10:45 AM",
}: {
  isArmed?: boolean;
  threatCount?: number;
  activeShields?: number;
  totalShields?: number;
  onPrimaryAction?: () => void;
  primaryActionLabel?: string;
  lastScanTime?: string;
}) {
  const isHealthy = isArmed && threatCount === 0;

  return (
    <div
      className={cn(
        "rounded-[20px] p-6 transition-[border-color,background-color] duration-200 border",
        isHealthy
          ? "bg-white dark:bg-[#12141D] border-[#EAEFF5] dark:border-[#1E2230] shadow-[0_2px_8px_0_rgba(15,23,42,0.03),0_12px_28px_0_rgba(15,23,42,0.02)]"
          : "bg-[#FFF9F6] dark:bg-[#1E1410] border-[#FFD8BF] dark:border-[#5C2307] shadow-[0_2px_12px_rgba(255,114,34,0.08)]"
      )}
    >
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="flex items-start gap-4">
          <div
            className={cn(
              "flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl shadow-sm border",
              isHealthy
                ? "bg-[#ECFDF5] dark:bg-[#064E3B]/40 border-[#A7F3D0] dark:border-[#065F46] text-[#059669] dark:text-[#34D399]"
                : "bg-[#FEF2F2] dark:bg-[#7F1D1D]/40 border-[#FECACA] dark:border-[#991B1B] text-[#DC2626] dark:text-[#F87171]"
            )}
          >
            {isHealthy ? (
              <ShieldCheck size={26} strokeWidth={2.2} />
            ) : (
              <AlertTriangle size={26} strokeWidth={2.2} />
            )}
          </div>

          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <h2 className="text-lg font-bold text-[#1E293B] dark:text-white [text-wrap:balance]">
                {isHealthy ? "System Fully Protected" : `${threatCount} Threat${threatCount === 1 ? "" : "s"} Require Action`}
              </h2>
              <span
                className={cn(
                  "inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-bold font-mono uppercase tracking-wide",
                  isHealthy
                    ? "bg-[#ECFDF5] text-[#059669] border border-[#A7F3D0]"
                    : "bg-[#FEF2F2] text-[#DC2626] border border-[#FECACA]"
                )}
              >
                {isHealthy ? "Armed" : "Attention"}
              </span>
            </div>

            <p className="text-xs text-[#64748B] dark:text-[#8491A2] leading-relaxed [text-wrap:pretty]">
              {isHealthy
                ? `All ${activeShields} of ${totalShields} real-time defensive shields are active. Filesystem, memory threads, and kernel driver blocklist enforced.`
                : "Aegis flagged threats in your memory maps or filesystem quarantine. Review the findings below."}
            </p>

            <div className="flex items-center gap-3 pt-1 text-[11px] font-mono text-[#94A3B8] dark:text-[#64748B]">
              <span>Last audit: {lastScanTime}</span>
              <span>•</span>
              <span className="text-[#059669] dark:text-[#34D399] font-medium flex items-center gap-1">
                <CheckCircle2 size={12} /> Real-Time Engine Active
              </span>
            </div>
          </div>
        </div>

        {onPrimaryAction && (
          <div className="shrink-0 flex items-center gap-3">
            <Button
              variant={isHealthy ? "primary" : "danger"}
              size="lg"
              onClick={onPrimaryAction}
              className="w-full sm:w-auto"
            >
              <span>{primaryActionLabel}</span>
              <ArrowRight size={15} strokeWidth={2} />
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

export function ProtectionGauge({
  percent,
  value,
  max = 100,
  size = 180,
  strokeWidth = 14,
  label,
  sublabel: _sublabel,
  color = "#FF7222",
}: {
  percent?: number;
  value?: number;
  max?: number;
  size?: number;
  strokeWidth?: number;
  label?: string;
  sublabel?: string;
  color?: string;
}) {
  const effectivePercent = percent !== undefined ? percent : value !== undefined ? (value / max) * 100 : 0;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, effectivePercent));
  const offset = circumference - (clamped / 100) * circumference;

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          className="text-[#F1F5F9] dark:text-[#1E293B]"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color || "#FF7222"}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="absolute flex flex-col items-center justify-center text-center">
        <span className="text-3xl font-bold text-[#1E293B] dark:text-white tabular-nums tracking-tight">
          {Math.round(clamped)}%
        </span>
        {label && <span className="text-[11px] font-semibold text-[#64748B] dark:text-[#8491A2] mt-0.5">{label}</span>}
      </div>
    </div>
  );
}
export const RadialGauge = ProtectionGauge;
