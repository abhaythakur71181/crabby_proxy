// Table primitives — semantic <table> markup (screen-reader friendly),
// keyboard-operable interactive rows, sticky header, horizontal scroll
// container so the page never scrolls sideways.
import type { HTMLAttributes, KeyboardEvent, ReactNode, TdHTMLAttributes, ThHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export function TableShell({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <div className={cn("overflow-x-auto", className)}>
      <table className="w-full border-collapse text-[13px]">{children}</table>
    </div>
  );
}

export function THead({ children }: { children: ReactNode }) {
  return (
    <thead className="sticky top-0 z-10">
      <tr className="border-b border-line bg-surface-1/95 backdrop-blur">{children}</tr>
    </thead>
  );
}

export function Th({ className, ...props }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      className={cn(
        "whitespace-nowrap px-3 py-2.5 text-left text-[11px] font-semibold uppercase tracking-[0.07em] text-fg-faint first:pl-4 last:pr-4",
        className,
      )}
      {...props}
    />
  );
}

export function Td({ className, ...props }: TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td
      className={cn("whitespace-nowrap px-3 py-2.5 first:pl-4 last:pr-4 align-middle", className)}
      {...props}
    />
  );
}

export function TRow({
  className,
  onActivate,
  entering,
  ...props
}: HTMLAttributes<HTMLTableRowElement> & {
  /** Makes the row an accessible button: click, Enter and Space activate. */
  onActivate?: () => void;
  /** Play the enter animation (new rows in live feeds). */
  entering?: boolean;
}) {
  const interactive = Boolean(onActivate);
  const onKeyDown = (e: KeyboardEvent<HTMLTableRowElement>) => {
    if (!interactive) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onActivate?.();
    }
  };
  return (
    <tr
      role={interactive ? "button" : undefined}
      tabIndex={interactive ? 0 : undefined}
      onClick={onActivate}
      onKeyDown={onKeyDown}
      className={cn(
        "border-b border-line/60 transition-colors duration-100 last:border-0",
        interactive && "cursor-pointer hover:bg-surface-2/70 focus-visible:bg-surface-2/70",
        entering && "animate-enter",
        className,
      )}
      {...props}
    />
  );
}

/** Skeleton rows while a table loads. */
export function TableSkeleton({ cols, rows = 6 }: { cols: number; rows?: number }) {
  return (
    <tbody aria-hidden>
      {Array.from({ length: rows }).map((_, r) => (
        <tr key={r} className="border-b border-line/60 last:border-0">
          {Array.from({ length: cols }).map((_, c) => (
            <Td key={c}>
              <div className="skeleton h-3.5" style={{ width: `${55 + ((r * 7 + c * 13) % 40)}%` }} />
            </Td>
          ))}
        </tr>
      ))}
    </tbody>
  );
}
