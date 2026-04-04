/**
 * Formatting utilities for the Crabby Proxy dashboard.
 *
 * Backend returns Unix timestamps (i64 seconds), so formatRelativeTime
 * accepts both numbers (Unix seconds) and Date/string.
 */

export function formatBytes(bytes: number | null | undefined): string {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (!seconds) return '0s';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  const parts: string[] = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  if (parts.length === 0) parts.push(`${s}s`);
  return parts.join(' ');
}

/**
 * Format a timestamp as relative time ("2m ago", "3h ago", etc.)
 * Accepts Unix seconds (number), Date, or ISO string.
 */
export function formatRelativeTime(value: number | Date | string | null | undefined): string {
  if (value == null) return 'Never';
  let d: Date;
  if (typeof value === 'number') {
    // Unix seconds → Date
    d = new Date(value * 1000);
  } else {
    d = new Date(value);
  }
  const now = new Date();
  const diff = Math.floor((now.getTime() - d.getTime()) / 1000);
  if (diff < 0) return 'just now';
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
  return d.toLocaleDateString();
}

/**
 * Format a Unix timestamp as a full date/time string.
 */
export function formatDateTime(value: number | null | undefined): string {
  if (value == null) return 'N/A';
  return new Date(value * 1000).toLocaleString();
}

export function truncateUuid(uuid: string): string {
  if (uuid.length <= 12) return uuid;
  return `${uuid.slice(0, 6)}…${uuid.slice(-4)}`;
}

export function formatNumber(n: number | null | undefined): string {
  if (n == null) return '0';
  return n.toLocaleString();
}
