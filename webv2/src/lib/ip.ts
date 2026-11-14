// Strict dotted-quad IPv4 check (each octet 0-255, no wildcards).
export function isIpv4(s: string): boolean {
  const m = s.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  return m.slice(1).every((o) => {
    const n = Number(o);
    return n >= 0 && n <= 255 && String(n) === o;
  });
}

function isIpv6(s: string): boolean {
  if (!s.includes(":") || !/^[0-9a-fA-F:.]+$/.test(s)) return false;
  try {
    new URL(`http://[${s}]/`);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate a reverse-tunnel target the way the admin API parses it (a Rust
 * `SocketAddr`): an IP literal plus port, `1.2.3.4:80` or `[2001:db8::1]:80`.
 * The API does not resolve hostnames, so they are rejected here too.
 * Returns an error message, or null when the address is acceptable.
 */
export function tunnelTargetError(raw: string): string | null {
  const s = raw.trim();
  if (!s) return "Target address is required";
  let host: string;
  let port: string;
  const v6 = s.match(/^\[([^\]]+)\]:(\d+)$/);
  if (v6) {
    [, host, port] = v6;
    if (!isIpv6(host)) return "Invalid IPv6 address";
  } else {
    const v4 = s.match(/^([^:]+):(\d+)$/);
    if (!v4) return "Use ip:port, e.g. 203.0.113.10:5432 or [2001:db8::1]:5432";
    [, host, port] = v4;
    if (!isIpv4(host)) return "Host must be an IP address (hostnames are not resolved)";
  }
  const p = Number(port);
  if (!Number.isInteger(p) || p < 1 || p > 65535 || String(p) !== port) {
    return "Port must be 1–65535";
  }
  return null;
}
