// Formatting helpers — all machine data renders through these so the whole
// app agrees on units, precision and tone.

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB", "PB"];

export function formatBytes(n: number | null | undefined, digits = 1): string {
  if (n == null || Number.isNaN(n)) return "—";
  if (n < 0) return "—";
  if (n < 1024) return `${n} B`;
  let v = n;
  let i = 0;
  while (v >= 1024 && i < BYTE_UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : digits)} ${BYTE_UNITS[i]}`;
}

export function formatRate(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
}

export function formatNumber(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  return new Intl.NumberFormat("en-US").format(n);
}

export function formatCompact(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  return new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

/** Uptime / duration from seconds → "3d 4h", "2h 05m", "45s". */
export function formatDuration(secs: number | null | undefined): string {
  if (secs == null || secs < 0) return "—";
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = Math.floor(secs % 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${String(m).padStart(2, "0")}m`;
  if (m > 0) return `${m}m ${String(s).padStart(2, "0")}s`;
  return `${s}s`;
}

/** Unix seconds → relative time ("3m ago", "in 2h"). */
export function formatRelative(unixSecs: number | null | undefined): string {
  if (unixSecs == null) return "—";
  const delta = Math.round(Date.now() / 1000 - unixSecs);
  const abs = Math.abs(delta);
  const fmt = (v: number, unit: string) =>
    delta >= 0 ? `${v}${unit} ago` : `in ${v}${unit}`;
  if (abs < 5) return "just now";
  if (abs < 60) return fmt(abs, "s");
  if (abs < 3600) return fmt(Math.floor(abs / 60), "m");
  if (abs < 86400) return fmt(Math.floor(abs / 3600), "h");
  if (abs < 86400 * 30) return fmt(Math.floor(abs / 86400), "d");
  return new Date(unixSecs * 1000).toLocaleDateString();
}

export function formatDateTime(unixSecs: number | null | undefined): string {
  if (unixSecs == null) return "—";
  return new Date(unixSecs * 1000).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Backend protocol enum variants → display labels. */
export function protocolLabel(p: string): string {
  const u = p.toUpperCase();
  if (u === "HTTP2") return "HTTP/2";
  return u; // HTTP, HTTPS, SOCKS4, SOCKS5, TCP
}

/** Tunnel service_type arrives as a Rust Debug string:
 * "WebService" | "SshService" | "Database(Postgres)" | 'Custom("x")'. */
export function serviceTypeLabel(raw: string): string {
  if (raw === "WebService") return "Web";
  if (raw === "SshService") return "SSH";
  const db = raw.match(/^Database\((\w+)\)$/);
  if (db) return db[1];
  const custom = raw.match(/^Custom\("(.*)"\)$/);
  if (custom) return custom[1] || "Custom";
  return raw;
}

/** "10.2.3.4:52344" → { host, port } (IPv6-safe: split on last colon). */
export function splitHostPort(addr: string): { host: string; port: string } {
  const i = addr.lastIndexOf(":");
  if (i === -1) return { host: addr, port: "" };
  return { host: addr.slice(0, i), port: addr.slice(i + 1) };
}

/** Humanize audit action strings: "user_created" → "User created". */
export function humanizeAction(action: string): string {
  const s = action.replace(/[_.]/g, " ").trim();
  return s.charAt(0).toUpperCase() + s.slice(1);
}
