// Real API client for the Crabby Proxy admin backend (axum, :8081).
//
// Fetches the documented backend shapes and adapts them to the frontend
// `crabby.ts` types the pages render, so pages only swap their static mock
// imports for the query hooks in `queries.ts` — no per-page shape juggling.
//
// Base URL: VITE_API_BASE_URL (e.g. http://localhost:8081 in dev) or same
// origin in production (nginx proxies /api → backend).

import type {
  ApiKey,
  Approval,
  AuditEntry,
  Connection,
  Group,
  HealthComponent,
  Protocol,
  Role,
  SystemStats,
  Tunnel,
  User,
} from "@/types/crabby";
import { getToken, clearSession } from "./auth";

const BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "") ?? "";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init.headers as Record<string, string> | undefined),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, { ...init, headers });

  if (res.status === 401) {
    clearSession();
    if (typeof window !== "undefined") window.location.href = "/login";
    throw new ApiError(401, "Session expired");
  }
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      msg = body?.error ?? body?.detail ?? msg;
    } catch {
      /* non-json error body */
    }
    throw new ApiError(res.status, msg);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// ── time helpers: backend uses unix seconds, UI wants ISO strings ──
const iso = (unix: number | null | undefined): string | null =>
  unix == null ? null : new Date(unix * 1000).toISOString();
const isoReq = (unix: number | null | undefined): string =>
  iso(unix) ?? new Date(0).toISOString();

const protoUp = (p: string): Protocol => {
  const u = p.toUpperCase();
  if (u === "HTTP2" || u === "H2") return "H2";
  if (u === "HTTPS" || u === "SOCKS4" || u === "SOCKS5" || u === "HTTP") return u as Protocol;
  return "HTTP";
};

// ── Auth ──────────────────────────────────────────────────────────
export interface LoginResult {
  token: string;
  expires_in: number;
  role: Role;
}
export const login = (username: string, password: string) =>
  req<LoginResult>("/api/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });

// ── Users ─────────────────────────────────────────────────────────
interface BackendUser {
  id: number;
  username: string;
  role: Role;
  max_connections: number;
  bandwidth_limit_mb: number;
  is_active: boolean;
  created_at: number;
  last_login_at: number | null;
}
const adaptUser = (u: BackendUser): User => ({
  id: u.id,
  username: u.username,
  role: u.role,
  active: u.is_active,
  max_connections: u.max_connections,
  bandwidth_limit_mb: u.bandwidth_limit_mb,
  bandwidth_used_mb: 0, // populated from quota when a detail view needs it
  last_login_at: iso(u.last_login_at),
  created_at: isoReq(u.created_at),
  groups: [],
});

export async function listUsers(): Promise<User[]> {
  const r = await req<{ items: BackendUser[] }>("/api/users?limit=200&offset=0");
  return r.items.map(adaptUser);
}
export async function getUser(id: number): Promise<User> {
  return adaptUser(await req<BackendUser>(`/api/users/${id}`));
}
export const createUser = (body: {
  username: string;
  password: string;
  role: Role;
  max_connections?: number;
  bandwidth_limit_mb?: number;
}) => req<BackendUser>("/api/users", { method: "POST", body: JSON.stringify(body) });
export const updateUser = (
  id: number,
  body: Partial<{
    password: string;
    role: Role;
    max_connections: number;
    bandwidth_limit_mb: number;
    is_active: boolean;
  }>,
) => req<BackendUser>(`/api/users/${id}`, { method: "PUT", body: JSON.stringify(body) });
export const deleteUser = (id: number) =>
  req<void>(`/api/users/${id}`, { method: "DELETE" });

// ── API keys ──────────────────────────────────────────────────────
interface BackendApiKey {
  id: number;
  user_id: number;
  name: string;
  key_prefix: string;
  created_at: number;
  expires_at: number | null;
  last_used_at: number | null;
  is_active: boolean;
}
const adaptKey = (k: BackendApiKey, username: string): ApiKey => ({
  id: String(k.id),
  name: k.name,
  user_id: k.user_id,
  username,
  prefix: k.key_prefix,
  last_used_at: iso(k.last_used_at),
  created_at: isoReq(k.created_at),
  expires_at: iso(k.expires_at),
});
export async function listApiKeys(userId: number, username = ""): Promise<ApiKey[]> {
  const r = await req<BackendApiKey[]>(`/api/users/${userId}/api-keys`);
  return r.map((k) => adaptKey(k, username));
}
export const createApiKey = (
  userId: number,
  body: { name: string; expires_in_days?: number },
) =>
  req<{ key: string } & BackendApiKey>(`/api/users/${userId}/api-keys`, {
    method: "POST",
    body: JSON.stringify(body),
  });
export const revokeApiKey = (userId: number, keyId: string | number) =>
  req<void>(`/api/users/${userId}/api-keys/${keyId}`, { method: "DELETE" });

// ── Connections ───────────────────────────────────────────────────
interface BackendConn {
  id: string;
  client_addr: string;
  target_addr: string;
  protocol: string;
  state: string;
  user_id: number | null;
  bytes_sent: number;
  bytes_received: number;
  created_at: number;
}
function splitHostPort(addr: string): [string, number] {
  const i = addr.lastIndexOf(":");
  if (i === -1) return [addr, 0];
  return [addr.slice(0, i), Number(addr.slice(i + 1)) || 0];
}
const adaptConn = (c: BackendConn): Connection => {
  const [chost, cport] = splitHostPort(c.client_addr);
  const [thost, tport] = splitHostPort(c.target_addr);
  const state = c.state === "blocked" || c.state === "closed" ? c.state : "active";
  return {
    id: c.id,
    client_ip: chost,
    client_port: cport,
    target_host: thost,
    target_port: tport,
    protocol: protoUp(c.protocol),
    state: state as Connection["state"],
    user_id: c.user_id ?? 0,
    username: c.user_id ? `User #${c.user_id}` : "—",
    bytes_sent: c.bytes_sent,
    bytes_received: c.bytes_received,
    started_at: isoReq(c.created_at),
    latency_ms: 0, // backend doesn't expose per-connection latency
  };
};
export async function listConnections(): Promise<Connection[]> {
  return (await req<BackendConn[]>("/api/connections")).map(adaptConn);
}
export const connectionCount = () => req<number>("/api/connections/count");
export const terminateConnection = (id: string) =>
  req<void>(`/api/connections/${id}`, { method: "DELETE" });

// ── Tunnels ───────────────────────────────────────────────────────
interface BackendTunnel {
  tunnel_id: string;
  listen_port: number;
  target_addr: string;
  service_type: string;
  created_at: number;
  status: string;
  bytes_transferred: number;
  total_connections: number;
  active_connections: number;
}
const adaptTunnel = (t: BackendTunnel): Tunnel => ({
  id: t.tunnel_id,
  name: t.service_type,
  listen: `0.0.0.0:${t.listen_port}`,
  target: t.target_addr,
  protocol: "HTTP",
  status: t.status === "active" ? "running" : "stopped",
  active_connections: t.active_connections,
  bytes_total: t.bytes_transferred,
  latency_ms: 0,
});
export async function listTunnels(): Promise<Tunnel[]> {
  const r = await req<{ tunnels: BackendTunnel[] }>("/api/tunnels");
  return r.tunnels.map(adaptTunnel);
}
export const createTunnel = (body: {
  service_type: string;
  port?: number;
  target_addr?: string;
}) => req<BackendTunnel>("/api/tunnels", { method: "POST", body: JSON.stringify(body) });
export const closeTunnel = (port: number) =>
  req<void>(`/api/tunnels/${port}`, { method: "DELETE" });

// ── Approvals (requests workflow + active grants) ─────────────────
interface BackendApprovalRequest {
  id: number;
  user_id: number;
  username?: string;
  client_ip: string;
  duration_hours: number;
  reason: string | null;
  status: string;
  requested_at: number;
  decided_by: number | null;
  decided_at: number | null;
  decision_reason: string | null;
}
const adaptRequest = (r: BackendApprovalRequest): Approval => ({
  id: r.id,
  user_id: r.user_id,
  username: r.username ?? `User #${r.user_id}`,
  client_ip: r.client_ip,
  duration_hours: r.duration_hours,
  status: (["pending", "approved", "rejected", "expired"].includes(r.status)
    ? r.status
    : "pending") as Approval["status"],
  reason: r.reason,
  requested_at: isoReq(r.requested_at),
  decided_at: iso(r.decided_at),
  decided_by: r.decided_by != null ? `User #${r.decided_by}` : null,
});
export async function listApprovalRequests(): Promise<Approval[]> {
  return (await req<BackendApprovalRequest[]>("/api/approval-requests")).map(adaptRequest);
}
export const createApprovalRequest = (body: {
  client_ip: string;
  duration_hours: number;
  reason?: string;
}) => req<unknown>("/api/approval-requests", { method: "POST", body: JSON.stringify(body) });
export const approveRequest = (id: number, reason?: string) =>
  req<unknown>(`/api/approval-requests/${id}/approve`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });
export const rejectRequest = (id: number, reason?: string) =>
  req<unknown>(`/api/approval-requests/${id}/reject`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });

interface BackendApproval {
  id: number;
  user_id: number;
  client_ip: string;
  approved_by: number;
  approved_at: number;
  expires_at: number;
  reason: string | null;
  duration_hours: number;
}
export async function listApprovals(): Promise<Approval[]> {
  return (await req<BackendApproval[]>("/api/approvals")).map((a) => ({
    id: a.id,
    user_id: a.user_id,
    username: `User #${a.user_id}`,
    client_ip: a.client_ip,
    duration_hours: a.duration_hours,
    status: "approved" as const,
    reason: a.reason,
    requested_at: isoReq(a.approved_at),
    decided_at: iso(a.expires_at),
    decided_by: `User #${a.approved_by}`,
  }));
}
export const terminateApproval = (id: number, reason: string) =>
  req<void>(`/api/approvals/${id}`, { method: "DELETE", body: JSON.stringify({ reason }) });

// ── Groups ────────────────────────────────────────────────────────
interface BackendGroup {
  id: number;
  name: string;
  description: string | null;
  member_count?: number;
  created_at: number;
}
const adaptGroup = (g: BackendGroup): Group => ({
  id: g.id,
  name: g.name,
  description: g.description ?? "",
  member_count: g.member_count ?? 0,
  policies: [],
  created_at: isoReq(g.created_at),
});
export async function listGroups(): Promise<Group[]> {
  return (await req<BackendGroup[]>("/api/groups")).map(adaptGroup);
}
export const createGroup = (body: { name: string; description?: string }) =>
  req<unknown>("/api/groups", { method: "POST", body: JSON.stringify(body) });
export const deleteGroup = (id: number) =>
  req<void>(`/api/groups/${id}`, { method: "DELETE" });

// ── Audit ─────────────────────────────────────────────────────────
interface BackendAudit {
  id: number;
  user_id: number;
  action: string;
  target_type: string | null;
  target_id: string | null;
  details: string | null;
  ip_address: string | null;
  created_at: number;
}
const adaptAudit = (a: BackendAudit): AuditEntry => ({
  id: String(a.id),
  ts: isoReq(a.created_at),
  actor: `User #${a.user_id}`,
  action: a.action,
  target: [a.target_type, a.target_id].filter(Boolean).join(":") || "—",
  ip: a.ip_address ?? "—",
  outcome: a.action.includes("denied") || a.action.includes("reject") ? "denied" : "ok",
  details: a.details ?? "",
});
export async function listAudit(limit = 100): Promise<AuditEntry[]> {
  const r = await req<{ entries: BackendAudit[] }>(`/api/audit-log?limit=${limit}&offset=0`);
  return r.entries.map(adaptAudit);
}

// ── Usage / dashboard / health ────────────────────────────────────
export interface DashboardData {
  uptime_seconds: number;
  version: string;
  active_connections: number;
  total_connections: number;
  bytes_sent: number;
  bytes_received: number;
  bandwidth_24h: number | null;
  connections_24h: number | null;
  total_users: number;
  top_users_24h: { user_id: number; bandwidth: number; connections: number }[];
  active_tunnels: number;
}
export const getDashboard = () => req<DashboardData>("/api/dashboard");

export async function getSystemStats(): Promise<SystemStats> {
  const d = await getDashboard();
  return {
    uptime_seconds: d.uptime_seconds,
    active_connections: d.active_connections,
    total_connections: d.total_connections,
    bytes_sent_24h: d.bytes_sent,
    bytes_received_24h: d.bytes_received,
    total_users: d.total_users,
    active_tunnels: d.active_tunnels,
    version: d.version,
    healthy: true,
  };
}

export interface UsageSummary {
  period_days: number;
  total_connections: number;
  total_bytes_sent: number;
  total_bytes_received: number;
  total_bandwidth: number;
  unique_users: number;
  top_users: { user_id: number; total_bandwidth: number; connection_count: number }[];
}
export const getUsageSummary = () => req<UsageSummary>("/api/usage/summary");

export interface UsageTimeseries {
  period_days: number;
  bucket_secs: number;
  points: { ts: number; bytes_sent: number; bytes_received: number; connections: number }[];
}
export const getUsageTimeseries = (days = 7, bucket: "hour" | "day" = "day") =>
  req<UsageTimeseries>(`/api/usage/timeseries?days=${days}&bucket=${bucket}`);

interface BackendComponentHealth {
  status: string;
  detail?: string | null;
  latency_ms: number;
  checked_at: number;
}
interface BackendDeepHealth {
  status: string;
  uptime_seconds: number;
  version: string;
  checks: Record<string, BackendComponentHealth>;
}
export async function getHealthComponents(): Promise<HealthComponent[]> {
  const h = await req<BackendDeepHealth>("/health/deep");
  const tone = (s: string): HealthComponent["status"] =>
    s === "ok" ? "healthy" : s === "degraded" ? "degraded" : "down";
  return Object.entries(h.checks).map(([name, c]) => ({
    name,
    status: tone(c.status),
    latency_ms: c.latency_ms,
    last_check: isoReq(c.checked_at),
    detail: c.detail ?? "",
  }));
}

export interface ConfigResponse {
  server: { proxy_bind: string; admin_bind: string; max_connections: number };
  authentication: { enabled: boolean };
  features: { connection_approval: boolean; reverse_tunnels: boolean };
}
export const getConfig = () => req<ConfigResponse>("/api/config");
export const reloadConfig = () =>
  req<{ success: boolean; message: string }>("/api/config/reload", { method: "POST" });
