import { cn } from "@/lib/utils";
import { motion } from "framer-motion";
import type { ButtonHTMLAttributes, ReactNode } from "react";

export function Card({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={cn("card p-5", className)}>{children}</div>;
}

export function Button({
  children,
  variant = "default",
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "primary" | "danger" | "ghost";
}) {
  const styles: Record<string, string> = {
    default:
      "bg-white/5 border border-border hover:border-accent hover:bg-white/10",
    primary:
      "bg-accent border border-transparent text-white hover:bg-accent-hover shadow-glow",
    danger: "bg-danger/90 border border-transparent text-white hover:bg-danger",
    ghost: "bg-transparent border border-transparent hover:bg-white/5",
  };
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm font-medium",
        "transition-all disabled:opacity-50 disabled:cursor-not-allowed",
        styles[variant],
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}

export function Badge({
  children,
  color = "muted",
}: {
  children: ReactNode;
  color?: "ok" | "warn" | "danger" | "crit" | "muted" | "accent";
}) {
  const map: Record<string, string> = {
    ok: "bg-ok/15 text-ok border-ok/30",
    warn: "bg-warn/15 text-warn border-warn/30",
    danger: "bg-danger/15 text-danger border-danger/30",
    crit: "bg-crit/15 text-crit border-crit/30",
    muted: "bg-white/5 text-muted border-border",
    accent: "bg-accent/15 text-accent border-accent/30",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold",
        map[color],
      )}
    >
      {children}
    </span>
  );
}

export function StatCard({
  label,
  value,
  accent,
  icon,
  delay = 0,
}: {
  label: string;
  value: ReactNode;
  accent?: string;
  icon?: ReactNode;
  delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay }}
      className="card p-5"
    >
      <div className="flex items-start justify-between">
        <div className={cn("text-3xl font-bold", accent)}>{value}</div>
        {icon && <div className="text-muted opacity-60">{icon}</div>}
      </div>
      <div className="mt-1 text-sm text-muted">{label}</div>
    </motion.div>
  );
}

export function Spinner() {
  return (
    <div className="h-4 w-4 animate-spin rounded-full border-2 border-white/20 border-t-accent" />
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
    <div className="mb-5 flex items-end justify-between">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}
