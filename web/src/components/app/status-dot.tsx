import { cn } from "@/lib/utils";

type Tone = "success" | "warning" | "danger" | "muted" | "violet";

const map: Record<Tone, string> = {
  success: "bg-[var(--success)] shadow-[0_0_8px_var(--success)]",
  warning: "bg-[var(--warning)] shadow-[0_0_8px_var(--warning)]",
  danger: "bg-[var(--danger)] shadow-[0_0_8px_var(--danger)]",
  muted: "bg-white/30",
  violet: "bg-[var(--accent-violet)] shadow-[0_0_10px_var(--accent-violet)]",
};

export function StatusDot({
  tone = "success",
  pulse = true,
  className,
}: {
  tone?: Tone;
  pulse?: boolean;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-block size-1.5 rounded-full",
        map[tone],
        pulse && "pulse-dot",
        className,
      )}
    />
  );
}