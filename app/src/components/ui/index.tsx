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
        "rounded-card border border-line bg-surface p-5 text-fg shadow-card",
        "transition-[border-color,box-shadow,transform] duration-150 ease-out",
        onClick && "cursor-pointer hover:shadow-card-hover hover:border-fg-subtle/40 active:scale-[0.99]",
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
    <Card onClick={onClick} className={cn(elevated && "shadow-card-hover", className)}>
      {children}
    </Card>
  );
}

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
    "inline-flex shrink-0 items-center justify-center gap-2 whitespace-nowrap rounded-xl font-semibold select-none " +
    "transition-[transform,background-color,border-color,color,box-shadow] duration-100 ease-out " +
    "active:scale-[0.97] disabled:cursor-not-allowed disabled:opacity-45 disabled:active:scale-100";

  const sizes = {
    sm: "min-h-[34px] px-3 text-xs",
    md: "min-h-[40px] px-4 text-[13px]",
    lg: "min-h-[46px] px-6 text-sm",
  };

  const filled = "border border-transparent text-brand-ink bg-brand hover:bg-brand/90 shadow-sm";
  const variants = {
    default: "border border-line bg-surface-2 text-fg hover:bg-line/60",
    primary: filled,
    orange: filled,
    emerald: filled,
    blue: "border border-transparent bg-info text-white hover:bg-info/90 shadow-sm",
    danger: "border border-transparent bg-danger text-white hover:bg-danger/90 shadow-sm",
    outline: "border border-line bg-surface text-fg hover:bg-surface-2",
    ghost: "border border-transparent bg-transparent text-fg-muted hover:bg-surface-2 hover:text-fg",
  };

  return (
    <button className={cn(base, sizes[size], variants[variant], className)} disabled={disabled} {...rest}>
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
    ok: "bg-ok-soft text-ok border-ok/25",
    warn: "bg-warn-soft text-warn border-warn/25",
    accent: "bg-brand-soft text-brand border-brand/25",
    danger: "bg-danger-soft text-danger border-danger/25",
    blue: "bg-info-soft text-info border-info/25",
    cyan: "bg-info-soft text-info border-info/25",
    neutral: "bg-surface-2 text-fg-muted border-line",
    muted: "bg-surface-2 text-fg-subtle border-line",
  };
  return (
    <span
      className={cn(
        "inline-flex select-none items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold tabular-nums",
        colors[color],
        className
      )}
    >
      {children}
    </span>
  );
}

export function SectionTitle({ title, subtitle, action }: { title: string; subtitle?: string; action?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-fg [text-wrap:balance]">{title}</h1>
        {subtitle && (
          <p className="mt-1.5 max-w-2xl text-[13px] leading-relaxed text-fg-muted [text-wrap:pretty]">{subtitle}</p>
        )}
      </div>
      {action}
    </div>
  );
}

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
    <Card className="flex items-center justify-between p-4 sm:p-5">
      <div className="min-w-0 space-y-1">
        <div className="text-xs font-medium text-fg-muted">{label}</div>
        <div className={cn("text-2xl font-semibold tabular-nums text-fg", accent)}>
          {value !== undefined && value !== null ? value : "—"}
        </div>
        {detail && <div className="truncate text-[11px] text-fg-muted">{detail}</div>}
      </div>
      {icon && (
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-soft text-brand">
          {icon}
        </div>
      )}
    </Card>
  );
}

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
      aria-label={label}
      disabled={disabled}
      onClick={() => !disabled && onChange(!checked)}
      className={cn(
        "relative inline-flex h-6 w-11 shrink-0 rounded-full border-2 border-transparent transition-colors duration-150",
        checked ? "bg-brand" : "bg-line",
        disabled && "cursor-not-allowed opacity-45"
      )}
      title={label}
    >
      <span
        className={cn(
          "pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transition-transform duration-150",
          checked ? "translate-x-5" : "translate-x-0"
        )}
      />
    </button>
  );
}

export function Spinner() {
  return <div className="h-4 w-4 animate-spin rounded-full border-2 border-line border-t-brand" aria-label="Loading" />;
}

/** Empty state: what is missing and what to do about it. */
export function Empty({ icon, title, hint, action }: { icon?: ReactNode; title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      {icon && <div className="mb-1 flex h-12 w-12 items-center justify-center rounded-2xl bg-surface-2 text-fg-subtle">{icon}</div>}
      <div className="text-sm font-semibold text-fg">{title}</div>
      {hint && <div className="max-w-sm text-xs leading-relaxed text-fg-muted">{hint}</div>}
      {action && <div className="mt-2">{action}</div>}
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
  color,
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
  const effective = percent !== undefined ? percent : value !== undefined ? (value / max) * 100 : 0;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, effective));
  const offset = circumference - (clamped / 100) * circumference;

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={size} height={size} className="-rotate-90" aria-hidden>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="currentColor" strokeWidth={strokeWidth} className="text-surface-2" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color ?? "rgb(var(--brand))"}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-[stroke-dashoffset] duration-700 ease-out"
        />
      </svg>
      <div className="absolute flex flex-col items-center justify-center text-center">
        <span className="text-3xl font-semibold tabular-nums tracking-tight text-fg">{Math.round(clamped)}%</span>
        {label && <span className="mt-0.5 text-[11px] font-medium text-fg-muted">{label}</span>}
      </div>
    </div>
  );
}
export const RadialGauge = ProtectionGauge;
