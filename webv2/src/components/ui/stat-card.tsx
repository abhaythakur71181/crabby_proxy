import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { AnimatedNumber } from "@/components/motion";
import { Panel } from "./card";
import { Skeleton } from "./states";

/** KPI tile: eyebrow label, big animated numeral, optional trend slot. */
export function StatCard({
  label,
  value,
  format,
  icon: Icon,
  trend,
  hint,
  loading,
  className,
}: {
  label: string;
  value: number | string | null | undefined;
  format?: (n: number) => string;
  icon?: LucideIcon;
  /** Small chart / delta rendered bottom-right. */
  trend?: ReactNode;
  hint?: string;
  loading?: boolean;
  className?: string;
}) {
  return (
    <Panel className={cn("relative overflow-hidden p-4", className)}>
      <div className="flex items-center justify-between gap-2">
        <span className="eyebrow">{label}</span>
        {Icon && <Icon className="size-4 text-fg-faint" aria-hidden />}
      </div>
      <div className="mt-2 flex items-end justify-between gap-3">
        <div className="min-w-0">
          {loading ? (
            <Skeleton className="h-8 w-24" />
          ) : typeof value === "number" ? (
            <AnimatedNumber
              value={value}
              format={format}
              className="block font-mono num text-[26px] font-semibold leading-8 tracking-tight"
            />
          ) : (
            <span className="block truncate font-mono num text-[26px] font-semibold leading-8 tracking-tight">
              {value ?? "—"}
            </span>
          )}
          {hint && <div className="mt-1 text-[11.5px] text-fg-faint">{hint}</div>}
        </div>
        {trend && <div className="shrink-0 pb-0.5">{trend}</div>}
      </div>
    </Panel>
  );
}
