export type Role = "root_admin" | "admin" | "user";
export type Protocol = "HTTP" | "HTTPS" | "SOCKS4" | "SOCKS5" | "H2";
export type ConnectionState = "active" | "closed" | "blocked";

export interface User {
  id: number;
  username: string;
  role: Role;
  active: boolean;
  max_connections: number;
  bandwidth_limit_mb: number;
  bandwidth_used_mb: number;
  last_login_at: string | null;
  created_at: string;
  groups: string[];
}

export interface Connection {
  id: string;
  client_ip: string;
  client_port: number;
  target_host: string;
  target_port: number;
  protocol: Protocol;
  state: ConnectionState;
  user_id: number;
  username: string;
  bytes_sent: number;
  bytes_received: number;
  started_at: string;
  latency_ms: number;
}

export interface Group {
  id: number;
  name: string;
  description: string;
  member_count: number;
  policies: string[];
  created_at: string;
}

export interface ApiKey {
  id: string;
  name: string;
  user_id: number;
  username: string;
  prefix: string;
  last_used_at: string | null;
  created_at: string;
  expires_at: string | null;
}

export interface Approval {
  id: number;
  user_id: number;
  username: string;
  client_ip: string;
  duration_hours: number;
  status: "pending" | "approved" | "rejected" | "expired";
  reason: string | null;
  requested_at: string;
  decided_at: string | null;
  decided_by: string | null;
}

export interface Tunnel {
  id: string;
  name: string;
  listen: string;
  target: string;
  protocol: Protocol;
  status: "running" | "stopped" | "error";
  active_connections: number;
  bytes_total: number;
  latency_ms: number;
}

export interface AuditEntry {
  id: string;
  ts: string;
  actor: string;
  actor_id: number;
  action: string;
  target: string;
  ip: string;
  outcome: "ok" | "denied" | "error";
  details: string;
}

export interface HealthComponent {
  name: string;
  status: "healthy" | "degraded" | "down";
  latency_ms: number;
  last_check: string;
  detail: string;
}

export interface SystemStats {
  uptime_seconds: number;
  active_connections: number;
  total_connections: number;
  bytes_sent_24h: number;
  bytes_received_24h: number;
  total_users: number;
  active_tunnels: number;
  version: string;
  healthy: boolean;
}