import { cn } from "@/lib/utils";

type Variant = "default" | "violet" | "success" | "warning" | "danger" | "outline" | "mono";

export function Pill({
  children,
  variant = "default",
  className,
}: {
  children: React.ReactNode;
  variant?: Variant;
  className?: string;
}) {
  const cls: Record<Variant, string> = {
    default: "bg-white/[0.06] text-foreground/80 border-white/10",
    violet: "bg-[var(--accent-violet-soft)] text-[var(--accent-violet)] border-[var(--accent-violet)]/25",
    success: "bg-[var(--success)]/15 text-[var(--success)] border-[var(--success)]/30",
    warning: "bg-[var(--warning)]/15 text-[var(--warning)] border-[var(--warning)]/30",
    danger: "bg-[var(--danger)]/15 text-[var(--danger)] border-[var(--danger)]/30",
    outline: "bg-transparent text-foreground/70 border-white/10",
    mono: "bg-white/[0.04] text-foreground/85 border-white/10 font-mono-tight",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider",
        cls[variant],
        className,
      )}
    >
      {children}
    </span>
  );
}