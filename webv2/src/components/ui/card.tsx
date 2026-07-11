import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/utils";

/** Primary surface container. `glow` adds an accent halo for hero panels. */
export function Panel({
  className,
  glow,
  ...props
}: HTMLAttributes<HTMLDivElement> & { glow?: boolean }) {
  return (
    <div
      className={cn(
        "rounded-lg border border-line bg-surface-1 shadow-panel",
        glow && "relative overflow-hidden",
        className,
      )}
      {...props}
    >
      {glow && (
        <div
          aria-hidden
          className="pointer-events-none absolute -top-24 right-0 h-48 w-96 rounded-full bg-accent-soft blur-3xl"
        />
      )}
      {props.children}
    </div>
  );
}

export function PanelHeader({
  title,
  eyebrow,
  actions,
  className,
}: {
  title: ReactNode;
  eyebrow?: string;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-start justify-between gap-3 px-4 pt-4 pb-3", className)}>
      <div className="min-w-0">
        {eyebrow && <div className="eyebrow mb-0.5">{eyebrow}</div>}
        <h2 className="truncate text-[14px] font-semibold tracking-tight">{title}</h2>
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}
