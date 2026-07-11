// Wire types — field-for-field mirrors of the Rust admin API structs on
// branch `bck` (src/admin/handlers/*). All timestamps are unix SECONDS.
// Do not "adapt" these into prettier shapes; pages consume them directly so
// there is exactly one source of truth per field.

import type { Role } from "@/lib/auth";
export type { Role };

// ── Auth ──────────────────────────────────────────────────────────
export interface LoginResponse {
  token: string;
  expires_in: number;
  role: Role;
}

// ── Users ─────────────────────────────────────────────────────────
export interface UserResponse {
  id: number;
  username: string;
  role: Role;
  max_connections: number;
  bandwidth_limit_mb: number;
  is_active: boolean;
  created_at: number;
  last_login_at: number | null;
}

export interface UsersListResponse {
  items: UserResponse[];
  total: number;
  limit: number;
  offset: number;
}

export interface CreateUserBody {
  username: string;
  password: string;
  role: Role;
  max_connections?: number;
  bandwidth_limit_mb?: number;
}

export interface UpdateUserBody {
  password?: string;
  role?: Role;
  max_connections?: number;
  bandwidth_limit_mb?: number;
  is_active?: boolean;
}

// ── API keys ──────────────────────────────────────────────────────
export interface ApiKeyResponse {
  id: number;
  name: string;
  prefix: string;
  created_at: number;
  last_used_at: number | null;
  expires_at: number | null;
  is_active: boolean;
}

export interface CreateApiKeyResponse {
  /** Full secret — shown exactly once. */
  key: string;
  details: ApiKeyResponse;
}

// ── Usage / quota ─────────────────────────────────────────────────
export interface UsageStatsResponse {
  user_id: number;
  period_days: number; // -1 = all-time
  connection_count: number;
  bytes_sent: number;
  bytes_received: number;
  total_bandwidth: number;
}

export interface UsageRecordResponse {
  id: number;
  connection_id: string;
  client_ip: string;
  target_host: string;
  protocol: string;
  started_at: number;
  ended_at: number | null;
  duration_seconds: number | null;
  bytes_sent: number;
  bytes_received: number;
  status: string;
}

export interface QuotaResponse {
  user_id: number;
  quota_bytes: number | null; // null = unlimited
  used_bytes: number;
  remaining_bytes: number | null;
  percentage_used: number | null;
}

export interface SystemUsageSummary {
  period_days: number;
  total_connections: number;
  total_bytes_sent: number;
  total_bytes_received: number;
  total_bandwidth: number;
  unique_users: number;
  top_users: { user_id: number; total_bandwidth: number; connection_count: number }[];
}

export interface TimeseriesPoint {
  ts: number;
  bytes_sent: number;
  bytes_received: number;
  connections: number;
}

export interface UsageTimeseries {
  period_days: number;
  bucket_secs: number;
  points: TimeseriesPoint[];
}

// ── Sessions ──────────────────────────────────────────────────────
export interface SessionInfo {
  id: number;
  user_id: number;
  created_at: number;
  expires_at: number;
  ip_address: string | null;
  user_agent: string | null;
}

// ── Connections ───────────────────────────────────────────────────
export type ConnectionState = "Pending" | "Approved" | "Rejected" | "Active" | "Closed";

export interface ConnectionInfo {
  id: string; // uuid
  client_addr: string; // "ip:port"
  target_addr: string;
  protocol: string; // "TCP"|"HTTP"|"HTTPS"|"HTTP2"|"SOCKS4"|"SOCKS5"
  state: ConnectionState;
  user_id: number | null;
  bytes_sent: number;
  bytes_received: number;
  created_at: number;
}

export interface LiveTicketResponse {
  ticket: string;
  expires_in: number; // 30s, single-use
}

/** The only frame type the live WebSocket sends (on 2s ticks, but ONLY when
 * the connection count changed — byte counters do not stream). */
export interface LiveSnapshotFrame {
  type: "connections";
  count: number;
  connections: ConnectionInfo[];
  timestamp: number;
}

// ── Tunnels ───────────────────────────────────────────────────────
export interface TunnelInfo {
  tunnel_id: string;
  listen_port: number;
  target_addr: string;
  /** Rust Debug string: "WebService" | "SshService" | "Database(Postgres)" | 'Custom("x")' */
  service_type: string;
  created_at: number;
  status: string;
  bytes_transferred: number;
  total_connections: number;
  active_connections: number;
}

export interface TunnelsListResponse {
  tunnels: TunnelInfo[];
  total: number;
}

// ── Approvals ─────────────────────────────────────────────────────
export interface ApprovalResponse {
  id: number;
  user_id: number;
  client_ip: string;
  approved_by: number;
  approved_at: number;
  expires_at: number;
  reason: string | null;
  duration_hours: number;
}

export type RequestStatus = "pending" | "approved" | "rejected";

export interface ApprovalRequestResponse {
  id: number;
  user_id: number;
  username: string | null;
  client_ip: string;
  duration_hours: number;
  reason: string | null;
  status: RequestStatus;
  requested_at: number;
  decided_by: number | null;
  decided_at: number | null;
  decision_reason: string | null;
}

// ── Groups ────────────────────────────────────────────────────────
export interface UserGroup {
  id: number;
  name: string;
  description: string | null;
  max_connections: number | null;
  bandwidth_limit_mb: number | null;
  rate_limit_rps: number | null;
  rate_limit_burst: number | null;
  allowed_protocols: string | null;
  allowed_targets: string | null;
  blocked_targets: string | null;
  access_schedule: string | null;
  created_at: number;
  updated_at: number;
}

export interface UserGroupWithCount extends UserGroup {
  member_count: number;
}

export interface GroupMemberDetail {
  user_id: number;
  username: string;
  role: string;
  joined_at: number;
}

export interface GroupMembersResponse {
  group_id: number;
  members: GroupMemberDetail[];
  total: number;
}

// ── Audit ─────────────────────────────────────────────────────────
export interface AuditEntry {
  id: number;
  user_id: number;
  action: string;
  target_type: string | null;
  target_id: string | null;
  details: string | null;
  ip_address: string | null;
  created_at: number;
}

export interface AuditLogResponse {
  entries: AuditEntry[];
  total: number;
  limit: number;
  offset: number;
}

// ── Health / telemetry ────────────────────────────────────────────
export interface HealthResponse {
  status: string;
  uptime_seconds: number;
  version: string;
}

export interface ComponentHealth {
  status: string; // "ok" | "error"
  detail?: string | null;
  latency_ms: number;
  checked_at: number;
}

export interface DeepHealthResponse {
  status: "healthy" | "degraded";
  uptime_seconds: number;
  version: string;
  checks: Record<string, ComponentHealth>;
}

export interface DashboardResponse {
  uptime_seconds: number;
  version: string;
  status: string;
  active_connections: number;
  total_connections: number;
  bytes_sent: number;
  bytes_received: number;
  total_bandwidth: number;
  bandwidth_24h: number | null;
  connections_24h: number | null;
  total_users: number;
  top_users_24h: { user_id: number; bandwidth: number; connections: number }[];
  active_tunnels: number;
}

export interface JsonMetricsResponse {
  active_by_protocol: Record<string, number>;
  bytes_transferred: { sent: number; received: number };
  requests_total: { success: number; failed: number };
  auth_failures_by_reason: Record<string, number>;
  ip_filter: { allowed: number; blocked: number };
  rate_limit_exceeded: { ip: number; user: number };
  connection_duration_p50: number;
  connection_duration_p95: number;
  connection_duration_p99: number;
  draining: boolean;
  draining_connections: number;
}

// ── Config ────────────────────────────────────────────────────────
export interface ConfigResponse {
  server: { proxy_bind: string; admin_bind: string; max_connections: number };
  authentication: { enabled: boolean };
  features: { connection_approval: boolean; reverse_tunnels: boolean };
}

export interface UpdateConfigBody {
  max_connections?: number;
  connection_approval?: boolean;
  reverse_tunnels?: boolean;
}
