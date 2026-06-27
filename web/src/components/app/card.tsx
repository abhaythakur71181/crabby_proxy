import { cn } from "@/lib/utils";
import { motion, type HTMLMotionProps } from "framer-motion";

type PanelProps = HTMLMotionProps<"div"> & { glow?: boolean };

export function Panel({ className, glow, ...props }: PanelProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className={cn(
        "relative rounded-2xl border border-white/[0.08] bg-[color-mix(in_oklab,var(--surface)_70%,transparent)] backdrop-blur-xl",
        "shadow-[0_1px_0_0_rgba(255,255,255,0.04)_inset,0_30px_60px_-30px_rgba(0,0,0,0.6)]",
        glow &&
          "before:pointer-events-none before:absolute before:inset-0 before:rounded-2xl before:bg-[radial-gradient(120%_60%_at_0%_0%,var(--accent-violet-soft),transparent_60%)] before:opacity-60",
        className,
      )}
      {...props}
    />
  );
}

export function PanelHeader({
  title,
  hint,
  action,
}: {
  title: React.ReactNode;
  hint?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-white/[0.06] px-5 py-4">
      <div className="min-w-0">
        <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">{title}</div>
        {hint && <div className="mt-1 text-xs text-muted-foreground/80">{hint}</div>}
      </div>
      {action}
    </div>
  );
}