import { cn } from "@/lib/utils";
import { type ButtonHTMLAttributes, type ReactNode } from "react";

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
        "rounded-2xl bg-white dark:bg-[#13151D] p-6 shadow-card border border-[#EAEFF5] dark:border-[#212533] text-[#1E293B] dark:text-white transition-all duration-200",
        onClick && "cursor-pointer hover:shadow-card-hover hover:border-[#DFE5EE] dark:hover:border-[#30364A]",
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
        "rounded-2xl bg-white dark:bg-[#13151D] p-6 shadow-card border border-[#EAEFF5] dark:border-[#212533] text-[#1E293B] dark:text-white transition-all duration-200",
        elevated && "shadow-card-hover border-[#DFE5EE] dark:border-[#30364A]",
        onClick && "cursor-pointer hover:shadow-card-hover",
        className
      )}
    >
      {children}
    </div>
  );
}

export function Button({
  children,
  variant = "default",
  size = "md",
  className,
  ...rest
}: {
  children: ReactNode;
  variant?: "default" | "primary" | "orange" | "blue" | "danger" | "ghost" | "outline" | "emerald";
  size?: "sm" | "md" | "lg";
} & ButtonHTMLAttributes<HTMLButtonElement>) {
  const base =
    "inline-flex items-center justify-center gap-2 font-medium rounded-xl transition-all duration-150 active:scale-[0.97] focus:outline-none disabled:opacity-40 disabled:cursor-not-allowed select-none";

  const sizes = {
    sm: "px-3 py-1.5 text-xs",
    md: "px-4 py-2.5 text-xs",
    lg: "px-6 py-3 text-sm",
  };

  const variants = {
    default:
      "bg-[#F1F5F9] dark:bg-[#1E293B] text-[#334155] dark:text-[#E2E8F0] hover:bg-[#E2E8F0] dark:hover:bg-[#334155] border border-[#E2E8F0] dark:border-[#334155]",
    primary:
      "bg-[#FF7222] text-white hover:bg-[#E85D10] shadow-button font-semibold",
    orange:
      "bg-[#FF7222] text-white hover:bg-[#E85D10] shadow-button font-semibold",
    blue:
      "bg-[#2563EB] text-white hover:bg-[#1D4ED8] shadow-[0_2px_8px_rgba(37,99,235,0.25)] font-semibold",
    emerald:
      "bg-[#10B981] text-white hover:bg-[#059669] shadow-[0_2px_8px_rgba(16,185,129,0.25)] font-semibold",
    danger:
      "bg-[#EF4444] text-white hover:bg-[#DC2626] shadow-[0_2px_8px_rgba(239,68,68,0.25)] font-semibold",
    outline:
      "bg-white dark:bg-[#13151D] text-[#334155] dark:text-[#E2E8F0] hover:bg-[#F8FAFC] dark:hover:bg-[#191C26] border border-[#CBD5E1] dark:border-[#334155] shadow-sm",
    ghost:
      "bg-transparent text-[#64748B] dark:text-[#94A3B8] hover:text-[#1E293B] dark:hover:text-white hover:bg-[#F1F5F9] dark:hover:bg-[#1E293B]",
  };

  return (
    <button
      className={cn(base, sizes[size], variants[variant], className)}
      {...rest}
    >
      {children}
    </button>
  );
}

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
    ok: "bg-[#ECFDF5] dark:bg-[#064E3B]/40 text-[#059669] dark:text-[#34D399] border-[#A7F3D0] dark:border-[#065F46]",
    warn: "bg-[#FFF4EC] dark:bg-[#7C2D12]/40 text-[#FF7222] dark:text-[#FB923C] border-[#FFE2CC] dark:border-[#9A3412]",
    accent: "bg-[#FFF4EC] dark:bg-[#7C2D12]/40 text-[#FF7222] dark:text-[#FB923C] border-[#FFE2CC] dark:border-[#9A3412]",
    danger: "bg-[#FEF2F2] dark:bg-[#7F1D1D]/40 text-[#DC2626] dark:text-[#F87171] border-[#FECACA] dark:border-[#991B1B]",
    blue: "bg-[#EFF6FF] dark:bg-[#1E3A8A]/40 text-[#2563EB] dark:text-[#60A5FA] border-[#BFDBFE] dark:border-[#1E40AF]",
    cyan: "bg-[#F0FDF4] dark:bg-[#0C4A6E]/40 text-[#0284C7] dark:text-[#38BDF8] border-[#BAE6FD] dark:border-[#0369A1]",
    neutral: "bg-[#F1F5F9] dark:bg-[#1E293B] text-[#475569] dark:text-[#94A3B8] border-[#E2E8F0] dark:border-[#334155]",
    muted: "bg-[#F8FAFC] dark:bg-[#13151D] text-[#64748B] dark:text-[#94A3B8] border-[#E2E8F0] dark:border-[#334155]",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-semibold border shadow-pill tracking-tight",
        colors[color],
        className
      )}
    >
      {children}
    </span>
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
        {/* Background Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          className="text-[#F1F5F9] dark:text-[#1E293B] transition-all"
        />
        {/* Active Arc */}
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
      {/* Center Label */}
      <div className="absolute flex flex-col items-center justify-center text-center">
        <span className="text-3xl font-extrabold text-[#1E293B] dark:text-white tab-nums tracking-tight">
          {Math.round(clamped)}%
        </span>
        {label && <span className="text-[10px] font-bold text-[#64748B] dark:text-[#94A3B8] mt-0.5 uppercase tracking-wider">{label}</span>}
      </div>
    </div>
  );
}

export const RadialGauge = ProtectionGauge;

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
        "relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none active:scale-[0.96]",
        checked ? "bg-[#FF7222]" : "bg-[#CBD5E1] dark:bg-[#334155]",
        disabled && "opacity-40 cursor-not-allowed"
      )}
      title={label}
    >
      <span
        className={cn(
          "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md transition duration-200 ease-in-out",
          checked ? "translate-x-5" : "translate-x-0"
        )}
      />
    </button>
  );
}

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
        <h1 className="text-2xl font-bold tracking-tight text-[#1E293B] dark:text-white">{title}</h1>
        {subtitle && <p className="mt-1 text-xs text-[#64748B] dark:text-[#8491A2] leading-relaxed max-w-2xl">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function Spinner() {
  return (
    <div className="h-4 w-4 animate-spin rounded-full border-2 border-[#CBD5E1] dark:border-[#334155] border-t-[#FF7222]" />
  );
}

export function StatCard({
  label,
  value,
  icon,
  accent,
}: {
  label: string;
  value: string | number;
  icon?: ReactNode;
  accent?: string;
}) {
  return (
    <Card className="p-5 flex items-center justify-between">
      <div>
        <span className="text-xs text-[#64748B] dark:text-[#8491A2] font-medium block">{label}</span>
        <span className={cn("text-2xl font-extrabold text-[#1E293B] dark:text-white tab-nums mt-1 block", accent)}>
          {value}
        </span>
      </div>
      {icon && (
        <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-[#F8FAFC] dark:bg-[#1E293B] border border-[#EAEFF5] dark:border-[#334155] text-[#FF7222]">
          {icon}
        </div>
      )}
    </Card>
  );
}
