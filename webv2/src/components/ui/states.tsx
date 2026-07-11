// Empty / error / loading states — every list and panel uses these so a
// failed query never masquerades as "no data".
import type { LucideIcon } from "lucide-react";
import { AlertTriangle, Inbox, RefreshCw } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { Button } from "./button";

export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  action,
  className,
}: {
  icon?: LucideIcon;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-line-strong px-6 py-10 text-center",
        className,
      )}
    >
      <div className="grid size-10 place-items-center rounded-full bg-surface-2 text-fg-faint">
        <Icon className="size-5" aria-hidden />
      </div>
      <div className="text-[13.5px] font-medium">{title}</div>
      {description && <p className="max-w-sm text-[12.5px] text-fg-muted">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function ErrorState({
  title = "Couldn't load this",
  detail,
  onRetry,
  className,
}: {
  title?: string;
  detail?: string;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-2 rounded-lg border border-danger/25 bg-danger-soft/40 px-6 py-8 text-center",
        className,
      )}
      role="alert"
    >
      <AlertTriangle className="size-5 text-danger" aria-hidden />
      <div className="text-[13.5px] font-medium">{title}</div>
      {detail && <p className="max-w-md text-[12.5px] text-fg-muted break-words">{detail}</p>}
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry} className="mt-1.5">
          <RefreshCw className="size-3.5" aria-hidden /> Retry
        </Button>
      )}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("skeleton", className)} aria-hidden />;
}
