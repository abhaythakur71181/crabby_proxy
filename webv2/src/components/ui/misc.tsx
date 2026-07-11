// Small shared primitives: mono text, kbd, copy button, search input,
// pagination, progress bar, tooltip wrapper, switch wrapper, tabs wrapper.
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import * as SwitchPrimitive from "@radix-ui/react-switch";
import * as TabsPrimitive from "@radix-ui/react-tabs";
import { Check, ChevronLeft, ChevronRight, Copy, Search } from "lucide-react";
import { useState, type InputHTMLAttributes, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { Button } from "./button";

export function Mono({ className, children }: { className?: string; children: ReactNode }) {
  return <span className={cn("font-mono num text-[12.5px]", className)}>{children}</span>;
}

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded border border-line-strong bg-surface-2 px-1 font-mono text-[10.5px] text-fg-muted">
      {children}
    </kbd>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Tooltip content={copied ? "Copied!" : label}>
      <button
        type="button"
        aria-label={`${label}: ${value}`}
        onClick={(e) => {
          e.stopPropagation();
          navigator.clipboard.writeText(value).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          });
        }}
        className="inline-flex size-6 items-center justify-center rounded text-fg-faint transition-colors hover:bg-surface-3 hover:text-fg"
      >
        {copied ? <Check className="size-3.5 text-success" /> : <Copy className="size-3.5" />}
      </button>
    </Tooltip>
  );
}

/** Mono value + copy affordance, the standard treatment for IPs/IDs/keys. */
export function CopyableMono({ value, display }: { value: string; display?: ReactNode }) {
  return (
    <span className="group/copy inline-flex items-center gap-1">
      <Mono>{display ?? value}</Mono>
      <span className="opacity-0 transition-opacity group-hover/copy:opacity-100">
        <CopyButton value={value} />
      </span>
    </span>
  );
}

export function SearchInput({
  className,
  ...props
}: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div className={cn("relative", className)}>
      <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-fg-faint" aria-hidden />
      <input
        type="search"
        className="h-8.5 w-full rounded-md border border-line-strong bg-surface-1 pl-8 pr-3 text-[13px] placeholder:text-fg-faint focus:border-accent/60 focus:outline-none focus:ring-2 focus:ring-ring/40"
        {...props}
      />
    </div>
  );
}

export function Pagination({
  offset,
  limit,
  total,
  onOffsetChange,
}: {
  offset: number;
  limit: number;
  total: number;
  onOffsetChange: (offset: number) => void;
}) {
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  return (
    <div className="flex items-center justify-between gap-3 border-t border-line px-4 py-2.5 text-[12.5px] text-fg-muted">
      <span className="num">
        {total === 0 ? "0 results" : `${offset + 1}–${Math.min(offset + limit, total)} of ${total}`}
      </span>
      <div className="flex items-center gap-1.5">
        <Button
          variant="ghost"
          size="sm"
          disabled={offset === 0}
          onClick={() => onOffsetChange(Math.max(0, offset - limit))}
          aria-label="Previous page"
        >
          <ChevronLeft className="size-3.5" />
        </Button>
        <span className="num min-w-14 text-center">
          {page} / {pages}
        </span>
        <Button
          variant="ghost"
          size="sm"
          disabled={offset + limit >= total}
          onClick={() => onOffsetChange(offset + limit)}
          aria-label="Next page"
        >
          <ChevronRight className="size-3.5" />
        </Button>
      </div>
    </div>
  );
}

export function Progress({
  value,
  tone = "accent",
  className,
}: {
  /** 0–100 */
  value: number;
  tone?: "accent" | "success" | "warning" | "danger";
  className?: string;
}) {
  const clamped = Math.max(0, Math.min(100, value));
  const toneClass = {
    accent: "bg-accent",
    success: "bg-success",
    warning: "bg-warning",
    danger: "bg-danger",
  }[tone];
  return (
    <div
      role="progressbar"
      aria-valuenow={Math.round(clamped)}
      aria-valuemin={0}
      aria-valuemax={100}
      className={cn("h-1.5 w-full overflow-hidden rounded-full bg-surface-3", className)}
    >
      <div
        className={cn("h-full rounded-full transition-[width] duration-500 ease-out", toneClass)}
        style={{ width: `${clamped}%` }}
      />
    </div>
  );
}

export function Tooltip({ content, children }: { content: ReactNode; children: ReactNode }) {
  return (
    <TooltipPrimitive.Root delayDuration={250}>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content
          sideOffset={6}
          className="z-[60] rounded-md border border-line bg-surface-3 px-2 py-1 text-[11.5px] text-fg shadow-pop"
        >
          {content}
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}

export function TooltipProvider({ children }: { children: ReactNode }) {
  return <TooltipPrimitive.Provider delayDuration={250}>{children}</TooltipPrimitive.Provider>;
}

export function Switch({
  checked,
  onCheckedChange,
  disabled,
  "aria-label": ariaLabel,
}: {
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
  disabled?: boolean;
  "aria-label"?: string;
}) {
  return (
    <SwitchPrimitive.Root
      checked={checked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      aria-label={ariaLabel}
      className="relative h-5 w-9 shrink-0 cursor-pointer rounded-full border border-line-strong bg-surface-3 transition-colors data-[state=checked]:border-accent/50 data-[state=checked]:bg-accent disabled:opacity-50"
    >
      <SwitchPrimitive.Thumb className="block size-3.5 translate-x-0.5 rounded-full bg-fg shadow transition-transform data-[state=checked]:translate-x-[18px] data-[state=checked]:bg-bg" />
    </SwitchPrimitive.Root>
  );
}

export function Tabs({
  tabs,
  value,
  onValueChange,
  children,
}: {
  tabs: { value: string; label: ReactNode }[];
  value: string;
  onValueChange: (v: string) => void;
  children: ReactNode;
}) {
  return (
    <TabsPrimitive.Root value={value} onValueChange={onValueChange}>
      <TabsPrimitive.List className="mb-4 flex flex-wrap items-center gap-1 border-b border-line">
        {tabs.map((t) => (
          <TabsPrimitive.Trigger
            key={t.value}
            value={t.value}
            className="relative -mb-px rounded-t-md border-b-2 border-transparent px-3 py-2 text-[13px] font-medium text-fg-muted transition-colors hover:text-fg data-[state=active]:border-accent data-[state=active]:text-fg"
          >
            {t.label}
          </TabsPrimitive.Trigger>
        ))}
      </TabsPrimitive.List>
      {children}
    </TabsPrimitive.Root>
  );
}

export const TabPanel = TabsPrimitive.Content;
