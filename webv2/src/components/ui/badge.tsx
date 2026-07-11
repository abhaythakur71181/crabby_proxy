import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { protocolLabel } from "@/lib/format";
import type { Role } from "@/lib/auth";

type Tone = "neutral" | "accent" | "success" | "warning" | "danger" | "info" | "brand";

const tones: Record<Tone, string> = {
  neutral: "bg-surface-3 text-fg-muted border-line-strong",
  accent: "bg-accent-soft text-accent border-accent/25",
  success: "bg-success-soft text-success border-success/25",
  warning: "bg-warning-soft text-warning border-warning/25",
  danger: "bg-danger-soft text-danger border-danger/25",
  info: "bg-info-soft text-info border-info/25",
  brand: "bg-brand-soft text-brand border-brand/25",
};

export function Pill({
  tone = "neutral",
  className,
  children,
}: {
  tone?: Tone;
  className?: string;
  children: ReactNode;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium leading-4",
        tones[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function RoleBadge({ role }: { role: Role | string }) {
  const tone: Tone = role === "root_admin" ? "brand" : role === "admin" ? "info" : "neutral";
  const label = role === "root_admin" ? "Root admin" : role === "admin" ? "Admin" : "User";
  return <Pill tone={tone}>{label}</Pill>;
}

export function ProtocolBadge({ protocol }: { protocol: string }) {
  return (
    <span className="inline-flex items-center rounded border border-line-strong bg-surface-2 px-1.5 py-px font-mono text-[10.5px] font-medium text-fg-muted">
      {protocolLabel(protocol)}
    </span>
  );
}

/** Status dot + label — never color-only. */
export function StatusPill({
  tone,
  label,
  pulse,
}: {
  tone: Tone;
  label: string;
  pulse?: boolean;
}) {
  return (
    <Pill tone={tone}>
      <span
        aria-hidden
        className={cn("size-1.5 rounded-full bg-current", pulse && "animate-pulse-dot")}
      />
      {label}
    </Pill>
  );
}
