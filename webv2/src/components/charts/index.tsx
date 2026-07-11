// Hand-built animated SVG charts — no chart library. Full control over
// motion (draw-in paths, springy bars) at zero dependency cost. All charts
// use currentColor/CSS variables so they re-theme automatically.
import { motion, useReducedMotion } from "motion/react";
import { useId, useMemo, useState } from "react";
import { cn } from "@/lib/utils";
import { formatBytes } from "@/lib/format";
import { Mono } from "@/components/ui/misc";

// ── Area chart (traffic over time) ────────────────────────────────
export interface AreaPoint {
  ts: number;
  value: number;
  /** Optional second series (e.g. received vs sent). */
  value2?: number;
}

export function AreaChart({
  points,
  height = 180,
  formatValue = formatBytes,
  labels = ["Sent", "Received"],
  className,
}: {
  points: AreaPoint[];
  height?: number;
  formatValue?: (n: number) => string;
  labels?: [string, string] | string[];
  className?: string;
}) {
  const reduced = useReducedMotion();
  const gid = useId();
  const [hover, setHover] = useState<number | null>(null);
  const W = 600;
  const H = height;
  const PAD = { top: 10, right: 6, bottom: 20, left: 6 };

  const { path1, path2, area1, max, xs } = useMemo(() => {
    const n = points.length;
    const max = Math.max(1, ...points.map((p) => Math.max(p.value, p.value2 ?? 0)));
    const iw = W - PAD.left - PAD.right;
    const ih = H - PAD.top - PAD.bottom;
    const x = (i: number) => PAD.left + (n <= 1 ? iw / 2 : (i / (n - 1)) * iw);
    const y = (v: number) => PAD.top + ih - (v / max) * ih;
    const line = (get: (p: AreaPoint) => number) =>
      points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(get(p)).toFixed(1)}`).join(" ");
    const p1 = line((p) => p.value);
    const hasSecond = points.some((p) => p.value2 != null);
    const p2 = hasSecond ? line((p) => p.value2 ?? 0) : null;
    const a1 = n > 0 ? `${p1} L${x(n - 1).toFixed(1)},${H - PAD.bottom} L${x(0).toFixed(1)},${H - PAD.bottom} Z` : "";
    return { path1: p1, path2: p2, area1: a1, max, xs: points.map((_, i) => x(i)) };
  }, [points, H]);

  if (points.length === 0) return null;
  const hovered = hover != null ? points[hover] : null;

  return (
    <div className={cn("relative", className)}>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="w-full"
        style={{ height }}
        role="img"
        aria-label="Traffic over time"
        onMouseLeave={() => setHover(null)}
        onMouseMove={(e) => {
          const rect = e.currentTarget.getBoundingClientRect();
          const px = ((e.clientX - rect.left) / rect.width) * W;
          let best = 0;
          let bestD = Infinity;
          xs.forEach((x, i) => {
            const d = Math.abs(x - px);
            if (d < bestD) {
              bestD = d;
              best = i;
            }
          });
          setHover(best);
        }}
      >
        <defs>
          <linearGradient id={`${gid}-fill`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.25" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {/* grid */}
        {[0.25, 0.5, 0.75].map((f) => (
          <line
            key={f}
            x1={PAD.left}
            x2={W - PAD.right}
            y1={PAD.top + (H - PAD.top - PAD.bottom) * f}
            y2={PAD.top + (H - PAD.top - PAD.bottom) * f}
            stroke="var(--chart-grid)"
            strokeWidth="1"
          />
        ))}
        <motion.path
          d={area1}
          fill={`url(#${gid}-fill)`}
          initial={reduced ? false : { opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.3 }}
        />
        <motion.path
          d={path1}
          fill="none"
          stroke="var(--accent)"
          strokeWidth="1.75"
          strokeLinejoin="round"
          initial={reduced ? false : { pathLength: 0 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 0.9, ease: "easeOut" }}
        />
        {path2 && (
          <motion.path
            d={path2}
            fill="none"
            stroke="var(--info)"
            strokeWidth="1.5"
            strokeDasharray="4 3"
            strokeLinejoin="round"
            initial={reduced ? false : { pathLength: 0 }}
            animate={{ pathLength: 1 }}
            transition={{ duration: 0.9, ease: "easeOut", delay: 0.15 }}
          />
        )}
        {hover != null && (
          <line
            x1={xs[hover]}
            x2={xs[hover]}
            y1={PAD.top}
            y2={H - PAD.bottom}
            stroke="var(--border-strong)"
            strokeWidth="1"
          />
        )}
      </svg>
      {hovered && (
        <div className="pointer-events-none absolute left-1/2 top-1 -translate-x-1/2 rounded-md border border-line bg-surface-3/95 px-2.5 py-1.5 text-[11.5px] shadow-pop backdrop-blur">
          <div className="text-fg-faint">
            {new Date(hovered.ts * 1000).toLocaleString(undefined, {
              month: "short",
              day: "numeric",
              hour: "2-digit",
              minute: "2-digit",
            })}
          </div>
          <div className="flex items-center gap-1.5">
            <span className="size-1.5 rounded-full bg-accent" /> {labels[0]}:{" "}
            <Mono>{formatValue(hovered.value)}</Mono>
          </div>
          {hovered.value2 != null && (
            <div className="flex items-center gap-1.5">
              <span className="size-1.5 rounded-full bg-info" /> {labels[1]}:{" "}
              <Mono>{formatValue(hovered.value2)}</Mono>
            </div>
          )}
        </div>
      )}
      <span className="sr-only">Peak {formatValue(max)}</span>
    </div>
  );
}

// ── Sparkline (tiny inline trend) ─────────────────────────────────
export function Sparkline({
  values,
  width = 96,
  height = 28,
  className,
}: {
  values: number[];
  width?: number;
  height?: number;
  className?: string;
}) {
  const reduced = useReducedMotion();
  const path = useMemo(() => {
    if (values.length < 2) return "";
    const max = Math.max(1, ...values);
    const x = (i: number) => (i / (values.length - 1)) * (width - 2) + 1;
    const y = (v: number) => height - 2 - (v / max) * (height - 4);
    return values.map((v, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  }, [values, width, height]);
  if (!path) return null;
  return (
    <svg width={width} height={height} className={cn("overflow-visible", className)} aria-hidden>
      <motion.path
        d={path}
        fill="none"
        stroke="var(--accent)"
        strokeWidth="1.5"
        strokeLinecap="round"
        initial={reduced ? false : { pathLength: 0, opacity: 0 }}
        animate={{ pathLength: 1, opacity: 1 }}
        transition={{ duration: 0.8, ease: "easeOut" }}
      />
    </svg>
  );
}

// ── Bar list (top users / reasons) ────────────────────────────────
export function BarList({
  items,
  formatValue = formatBytes,
  className,
}: {
  items: { label: React.ReactNode; value: number; key: string | number }[];
  formatValue?: (n: number) => string;
  className?: string;
}) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <div className={cn("space-y-2.5", className)}>
      {items.map((item, i) => (
        <div key={item.key} className="group">
          <div className="mb-1 flex items-baseline justify-between gap-3 text-[12.5px]">
            <span className="truncate font-medium">{item.label}</span>
            <Mono className="shrink-0 text-fg-muted">{formatValue(item.value)}</Mono>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-surface-3">
            <motion.div
              className="h-full rounded-full bg-accent group-hover:bg-accent-strong"
              initial={{ width: 0 }}
              animate={{ width: `${(item.value / max) * 100}%` }}
              transition={{ type: "spring", duration: 0.7, bounce: 0, delay: i * 0.05 }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Donut (protocol mix) ──────────────────────────────────────────
const DONUT_COLORS = ["var(--accent)", "var(--info)", "var(--brand)", "var(--success)", "var(--warning)", "var(--danger)"];

export function Donut({
  segments,
  size = 148,
  formatValue = (n) => n.toLocaleString("en-US"),
  className,
}: {
  segments: { label: string; value: number }[];
  size?: number;
  formatValue?: (n: number) => string;
  className?: string;
}) {
  const reduced = useReducedMotion();
  const total = segments.reduce((s, x) => s + x.value, 0);
  const R = 42;
  const C = 2 * Math.PI * R;
  let acc = 0;

  return (
    <div className={cn("flex items-center gap-5", className)}>
      <svg width={size} height={size} viewBox="0 0 100 100" role="img" aria-label="Protocol mix">
        <circle cx="50" cy="50" r={R} fill="none" stroke="var(--chart-grid)" strokeWidth="10" />
        {segments.map((seg, i) => {
          const frac = total > 0 ? seg.value / total : 0;
          const offset = acc;
          acc += frac;
          return (
            <motion.circle
              key={seg.label}
              cx="50"
              cy="50"
              r={R}
              fill="none"
              stroke={DONUT_COLORS[i % DONUT_COLORS.length]}
              strokeWidth="10"
              strokeLinecap="butt"
              strokeDasharray={`${(frac * C).toFixed(2)} ${C.toFixed(2)}`}
              strokeDashoffset={-offset * C}
              transform="rotate(-90 50 50)"
              initial={reduced ? false : { opacity: 0, strokeDasharray: `0 ${C.toFixed(2)}` }}
              animate={{ opacity: 1, strokeDasharray: `${(frac * C).toFixed(2)} ${C.toFixed(2)}` }}
              transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1], delay: i * 0.08 }}
            />
          );
        })}
        <text
          x="50"
          y="47"
          textAnchor="middle"
          className="fill-[var(--text)] font-mono"
          style={{ fontSize: 13, fontWeight: 600 }}
        >
          {formatValue(total)}
        </text>
        <text x="50" y="60" textAnchor="middle" className="fill-[var(--text-faint)]" style={{ fontSize: 7.5 }}>
          total
        </text>
      </svg>
      <div className="min-w-0 flex-1 space-y-1.5">
        {segments.map((seg, i) => (
          <div key={seg.label} className="flex items-center justify-between gap-3 text-[12.5px]">
            <span className="flex items-center gap-2 truncate">
              <span
                className="size-2 shrink-0 rounded-[3px]"
                style={{ background: DONUT_COLORS[i % DONUT_COLORS.length] }}
              />
              {seg.label}
            </span>
            <Mono className="text-fg-muted">{formatValue(seg.value)}</Mono>
          </div>
        ))}
        {segments.length === 0 && <p className="text-[12.5px] text-fg-faint">No traffic yet</p>}
      </div>
    </div>
  );
}
