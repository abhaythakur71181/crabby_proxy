/**
 * Type definitions matching the Crabby Proxy Rust backend API responses.
 *
 * Key differences from mock types:
 * - Timestamps are Unix seconds (i64), not ISO strings
 * - Some fields are nullable (Option<T> → T | null)
 */

export type UserRole = 'root_admin' | 'admin' | 'user';
export type Protocol = 'HTTP' | 'HTTPS' | 'SOCKS4' | 'SOCKS5' | 'HTTP2';

// ── Users ───────────────────────────────────────────────────────────

export interface User {
  id: number;
  username: string;
  role: UserRole;
  is_active: boolean;
  max_connections: number;
  bandwidth_limit_mb: number;
  last_login_at: number | null;  // Unix seconds
  created_at: number;            // Unix seconds
}

export interface PaginatedUsers {
  items: User[];
  total: number;
  limit: number;
  offset: number;
}

// ── Connections ─────────────────────────────────────────────────────

export interface Connection {
  id: string;         // UUID
  client_addr: string;
  target_addr: string;
  protocol: Protocol;
  state: string;
  user_id: number | null;
  bytes_sent: number;
  bytes_received: number;
  created_at: number; // Unix seconds
}

// ── Dashboard ───────────────────────────────────────────────────────

export interface DashboardData {
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
  top_users_24h: TopUser[];
  active_tunnels: number;
}

export interface TopUser {
  user_id: number;
  bandwidth: number;
  connections: number;
}

// ── API Keys ────────────────────────────────────────────────────────

export interface ApiKey {
  id: number;
  prefix: string;
  created_at: number;          // Unix seconds
  last_used_at: number | null; // Unix seconds
  expires_at: number | null;   // Unix seconds
  is_active: boolean;
}

export interface CreateApiKeyResponse {
  key: string;        // Full key, shown once
  details: ApiKey;
}

// ── Usage ───────────────────────────────────────────────────────────

export interface UsageStats {
  user_id: number;
  period_days: number;
  connection_count: number;
  bytes_sent: number;
  bytes_received: number;
  total_bandwidth: number;
}

export interface UsageRecord {
  id: number;
  connection_id: string;
  client_ip: string;
  target_host: string;
  protocol: string;
  started_at: number;             // Unix seconds
  ended_at: number | null;        // Unix seconds
  duration_seconds: number | null;
  bytes_sent: number;
  bytes_received: number;
  status: string;
}

// ── Quota ───────────────────────────────────────────────────────────

export interface Quota {
  user_id: number;
  quota_bytes: number | null;
  used_bytes: number;
  remaining_bytes: number | null;
  percentage_used: number | null;
}

// ── Groups ──────────────────────────────────────────────────────────

export interface Group {
  id: number;
  name: string;
  description: string | null;
  member_count: number;
  created_at: number; // Unix seconds
}

export interface GroupMember {
  user_id: number;
  username: string;
  role: UserRole;
  joined_at: number; // Unix seconds
}

export interface GroupMembersResponse {
  group_id: number;
  members: GroupMember[];
  total: number;
}

// ── Approvals ───────────────────────────────────────────────────────

export interface Approval {
  id: number;
  user_id: number;
  client_ip: string;
  approved_by: number;
  approved_at: number;  // Unix seconds
  expires_at: number;   // Unix seconds
  duration_hours: number;
  reason: string | null;
}

// ── Tunnels ─────────────────────────────────────────────────────────

export interface Tunnel {
  listen_port: number;
  service_type: string;
  target_addr: string;
  status: string;
  created_at: number; // Unix seconds
}

export interface TunnelsResponse {
  tunnels: Tunnel[];
  total: number;
}

// ── Audit Log ───────────────────────────────────────────────────────

export interface AuditEntry {
  id: number;
  user_id: number;
  action: string;
  target_type: string | null;
  target_id: string | null;
  details: string | null;
  ip_address: string | null;
  created_at: number; // Unix seconds
}

export interface AuditLogResponse {
  entries: AuditEntry[];
  total: number;
  limit: number;
  offset: number;
}

// ── Sessions ────────────────────────────────────────────────────────

export interface Session {
  id: number;
  user_id: number;
  created_at: number;  // Unix seconds
  expires_at: number;  // Unix seconds
  ip_address: string | null;
  user_agent: string | null;
}

// ── Health ──────────────────────────────────────────────────────────

export interface HealthCheck {
  status: string;
  uptime_seconds: number;
  version: string;
}

export interface DeepHealthCheck extends HealthCheck {
  checks: {
    database: { status: string; detail: string | null };
    state_backend: { status: string; detail: string | null };
    dns_cache: { status: string; detail: string | null };
  };
}

// ── Config ──────────────────────────────────────────────────────────

export interface ServerConfig {
  server: { proxy_bind: string; admin_bind: string; max_connections: number };
  authentication: { enabled: boolean };
  features: { connection_approval: boolean; reverse_tunnels: boolean };
}

// ── System Usage Summary ────────────────────────────────────────────

export interface SystemUsageSummary {
  period_days: number;
  total_connections: number;
  total_bytes_sent: number;
  total_bytes_received: number;
  total_bandwidth: number;
  unique_users: number;
  top_users: { user_id: number; total_bandwidth: number; connection_count: number }[];
}
