import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Timeseries buckets with no traffic are omitted by the backend — fill the
 * gaps with zero points so charts show honest flat lines instead of skipping
 * time. `bucketSecs` comes from the API response. */
export function fillTimeseriesGaps<
  T extends { ts: number; bytes_sent: number; bytes_received: number; connections: number },
>(points: T[], bucketSecs: number, days: number): T[] {
  const now = Math.floor(Date.now() / 1000);
  const start = Math.floor((now - days * 86400) / bucketSecs) * bucketSecs;
  const byTs = new Map(points.map((p) => [p.ts, p]));
  const out: T[] = [];
  for (let ts = start; ts <= now; ts += bucketSecs) {
    out.push(
      byTs.get(ts) ??
        ({ ts, bytes_sent: 0, bytes_received: 0, connections: 0 } as T),
    );
  }
  return out;
}

/** Serialize rows to CSV and trigger a download. */
export function downloadCsv(filename: string, headers: string[], rows: (string | number)[][]) {
  const esc = (v: string | number) => {
    const s = String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const csv = [headers.map(esc).join(","), ...rows.map((r) => r.map(esc).join(","))].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
