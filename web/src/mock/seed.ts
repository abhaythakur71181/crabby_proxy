import type {
  ApiKey,
  Approval,
  AuditEntry,
  Connection,
  Group,
  HealthComponent,
  SystemStats,
  Tunnel,
  User,
} from "@/types/crabby";

function rand<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}
function rng(seed: number) {
  let s = seed;
  return () => {
    s = (s * 1664525 + 1013904223) % 4294967296;
    return s / 4294967296;
  };
}
const R = rng(42);

const targets = [
  "api.github.com",
  "registry.npmjs.org",
  "s3.amazonaws.com",
  "auth0.com",
  "stripe.com",
  "openai.com",
  "cloudflare.com",
  "googleapis.com",
  "raw.githubusercontent.com",
  "hub.docker.com",
  "pypi.org",
  "vercel.com",
  "linear.app",
];
const clientIps = [
  "10.0.4.15",
  "10.0.4.22",
  "10.0.4.103",
  "192.168.1.14",
  "192.168.1.42",
  "172.16.0.4",
  "103.57.84.238",
  "14.194.245.134",
  "152.58.116.10",
  "122.186.0.138",
];
const protocols: Connection["protocol"][] = ["HTTPS", "HTTP", "SOCKS5", "H2", "SOCKS4"];

export const users: User[] = [
  {
    id: 1,
    username: "root",
    role: "root_admin",
    active: true,
    max_connections: 100,
    bandwidth_limit_mb: 10000,
    bandwidth_used_mb: 412,
    last_login_at: new Date(Date.now() - 30 * 1000).toISOString(),
    created_at: "2026-04-02T10:14:00Z",
    groups: ["ops"],
  },
  {
    id: 2,
    username: "falcon",
    role: "admin",
    active: true,
    max_connections: 1000,
    bandwidth_limit_mb: 10000,
    bandwidth_used_mb: 8421,
    last_login_at: new Date(Date.now() - 6 * 86400 * 1000).toISOString(),
    created_at: "2026-05-12T08:00:00Z",
    groups: ["ops", "engineering"],
  },
  {
    id: 3,
    username: "rohitmittal",
    role: "user",
    active: false,
    max_connections: 100,
    bandwidth_limit_mb: 1000,
    bandwidth_used_mb: 612,
    last_login_at: "2026-06-20T11:32:00Z",
    created_at: "2026-06-15T14:00:00Z",
    groups: ["contractors"],
  },
  {
    id: 4,
    username: "ada.lovelace",
    role: "user",
    active: true,
    max_connections: 50,
    bandwidth_limit_mb: 2000,
    bandwidth_used_mb: 1240,
    last_login_at: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
    created_at: "2026-05-30T12:00:00Z",
    groups: ["engineering"],
  },
  {
    id: 5,
    username: "linus.t",
    role: "user",
    active: true,
    max_connections: 200,
    bandwidth_limit_mb: 5000,
    bandwidth_used_mb: 4810,
    last_login_at: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
    created_at: "2026-05-21T09:00:00Z",
    groups: ["engineering", "infra"],
  },
  {
    id: 6,
    username: "grace.h",
    role: "user",
    active: true,
    max_connections: 50,
    bandwidth_limit_mb: 1000,
    bandwidth_used_mb: 220,
    last_login_at: new Date(Date.now() - 4 * 3600 * 1000).toISOString(),
    created_at: "2026-06-02T15:30:00Z",
    groups: ["contractors"],
  },
  {
    id: 7,
    username: "k.mcclane",
    role: "user",
    active: true,
    max_connections: 50,
    bandwidth_limit_mb: 1500,
    bandwidth_used_mb: 980,
    last_login_at: new Date(Date.now() - 80 * 1000).toISOString(),
    created_at: "2026-06-10T11:00:00Z",
    groups: ["engineering"],
  },
];

export const groups: Group[] = [
  {
    id: 1,
    name: "ops",
    description: "Operations and SecOps. Full read of telemetry.",
    member_count: 2,
    policies: ["egress:*", "metrics:read", "audit:read"],
    created_at: "2026-04-02T10:14:00Z",
  },
  {
    id: 2,
    name: "engineering",
    description: "Engineering team — standard egress allowlist.",
    member_count: 4,
    policies: ["egress:allowlist.eng", "rate:standard"],
    created_at: "2026-04-10T10:14:00Z",
  },
  {
    id: 3,
    name: "infra",
    description: "Infrastructure — broad egress, no rate caps.",
    member_count: 1,
    policies: ["egress:*", "rate:unlimited"],
    created_at: "2026-04-12T10:14:00Z",
  },
  {
    id: 4,
    name: "contractors",
    description: "Contractor access — narrow allowlist, approval-gated.",
    member_count: 2,
    policies: ["egress:allowlist.ctr", "approval:required"],
    created_at: "2026-05-15T10:14:00Z",
  },
];

export const apiKeys: ApiKey[] = users.flatMap((u, i) => [
  {
    id: `key_${u.id}_a`,
    name: `${u.username}-cli`,
    user_id: u.id,
    username: u.username,
    prefix: `cbpx_${u.username.slice(0, 3)}${(1000 + i).toString(16)}`,
    last_used_at: new Date(Date.now() - (i + 1) * 3600 * 1000).toISOString(),
    created_at: u.created_at,
    expires_at: null,
  },
]);

export const tunnels: Tunnel[] = [
  {
    id: "tnl_ingress_01",
    name: "ingress-edge-01",
    listen: "0.0.0.0:8443",
    target: "internal-gw.cluster.local:443",
    protocol: "HTTPS",
    status: "running",
    active_connections: 412,
    bytes_total: 240_000_000_000,
    latency_ms: 12,
  },
  {
    id: "tnl_socks_dev",
    name: "socks-dev",
    listen: "0.0.0.0:1080",
    target: "*",
    protocol: "SOCKS5",
    status: "running",
    active_connections: 28,
    bytes_total: 14_200_000_000,
    latency_ms: 24,
  },
  {
    id: "tnl_legacy_http",
    name: "legacy-http",
    listen: "0.0.0.0:3128",
    target: "*",
    protocol: "HTTP",
    status: "stopped",
    active_connections: 0,
    bytes_total: 4_000_000_000,
    latency_ms: 0,
  },
];

export const approvals: Approval[] = [
  {
    id: 5,
    user_id: 6,
    username: "grace.h",
    client_ip: "103.57.84.238",
    duration_hours: 24,
    status: "pending",
    reason: "Need to test webhook integration with stripe.com",
    requested_at: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
    decided_at: null,
    decided_by: null,
  },
  {
    id: 4,
    user_id: 7,
    username: "k.mcclane",
    client_ip: "14.194.245.134",
    duration_hours: 8,
    status: "pending",
    reason: "Production hotfix — temporary access required",
    requested_at: new Date(Date.now() - 18 * 60 * 1000).toISOString(),
    decided_at: null,
    decided_by: null,
  },
  {
    id: 3,
    user_id: 6,
    username: "grace.h",
    client_ip: "192.168.10.4",
    duration_hours: 4,
    status: "pending",
    reason: null,
    requested_at: new Date(Date.now() - 42 * 60 * 1000).toISOString(),
    decided_at: null,
    decided_by: null,
  },
  {
    id: 2,
    user_id: 3,
    username: "rohitmittal",
    client_ip: "103.57.84.113",
    duration_hours: 24,
    status: "approved",
    reason: null,
    requested_at: "2026-06-20T11:00:00Z",
    decided_at: "2026-06-20T11:14:00Z",
    decided_by: "falcon",
  },
  {
    id: 1,
    user_id: 2,
    username: "falcon",
    client_ip: "14.194.245.134",
    duration_hours: 24,
    status: "approved",
    reason: "need to test",
    requested_at: "2026-06-16T08:00:00Z",
    decided_at: "2026-06-16T08:02:00Z",
    decided_by: "root",
  },
];

export function makeConnection(id: number): Connection {
  const user = rand(users);
  return {
    id: `cx_${Date.now().toString(36)}_${id.toString(36)}`,
    client_ip: rand(clientIps),
    client_port: 30000 + Math.floor(R() * 30000),
    target_host: rand(targets),
    target_port: rand([443, 443, 443, 80, 22, 5432]),
    protocol: rand(protocols),
    state: "active",
    user_id: user.id,
    username: user.username,
    bytes_sent: Math.floor(R() * 50_000),
    bytes_received: Math.floor(R() * 5_000_000),
    started_at: new Date(Date.now() - Math.floor(R() * 3 * 86400 * 1000)).toISOString(),
    latency_ms: Math.floor(4 + R() * 80),
  };
}

export const initialConnections: Connection[] = Array.from({ length: 17 }, (_, i) =>
  makeConnection(i),
);

export const auditEntries: AuditEntry[] = Array.from({ length: 60 }, (_, i) => {
  const actor = rand(users).username;
  const action = rand([
    "user.create",
    "user.update",
    "user.delete",
    "approval.grant",
    "approval.deny",
    "config.reload",
    "tunnel.start",
    "tunnel.stop",
    "apikey.create",
    "apikey.revoke",
    "auth.login",
    "auth.logout",
  ]);
  const outcome = R() > 0.92 ? "denied" : R() > 0.98 ? "error" : "ok";
  return {
    id: `ae_${(1000 + i).toString(36)}`,
    ts: new Date(Date.now() - i * 1000 * 60 * Math.floor(1 + R() * 30)).toISOString(),
    actor,
    action,
    target: action.startsWith("user")
      ? rand(users).username
      : action.startsWith("approval")
        ? `approval#${Math.floor(R() * 100)}`
        : action.startsWith("tunnel")
          ? rand(tunnels).name
          : "system",
    ip: rand(clientIps),
    outcome,
    details:
      action === "config.reload"
        ? "Reloaded 14 routes, 3 policies"
        : action.startsWith("approval")
          ? "24h grant"
          : action === "auth.login"
            ? "session opened"
            : "—",
  };
});

export const healthComponents: HealthComponent[] = [
  {
    name: "SQLite",
    status: "healthy",
    latency_ms: 0.4,
    last_check: new Date(Date.now() - 4000).toISOString(),
    detail: "WAL mode, 14 MB",
  },
  {
    name: "Redis",
    status: "healthy",
    latency_ms: 0.8,
    last_check: new Date(Date.now() - 4000).toISOString(),
    detail: "127.0.0.1:6379, 1.2 MB used",
  },
  {
    name: "Auth subsystem",
    status: "healthy",
    latency_ms: 2.1,
    last_check: new Date(Date.now() - 4000).toISOString(),
    detail: "JWT, HS256, key rotated 12d ago",
  },
  {
    name: "Proxy core",
    status: "healthy",
    latency_ms: 0.1,
    last_check: new Date(Date.now() - 1000).toISOString(),
    detail: "17 active, 3 listeners",
  },
  {
    name: "Metrics collector",
    status: "degraded",
    latency_ms: 142.0,
    last_check: new Date(Date.now() - 8000).toISOString(),
    detail: "proxy_usage_records_dropped_total = 12 (last 5m)",
  },
  {
    name: "Disk",
    status: "healthy",
    latency_ms: 0,
    last_check: new Date(Date.now() - 6000).toISOString(),
    detail: "/var/lib/crabby — 42% used",
  },
];

export const systemStats: SystemStats = {
  uptime_seconds: 4 * 86400 + 15 * 3600 + 37 * 60,
  active_connections: 17,
  total_connections: 19_306,
  bytes_sent_24h: 115_300_000,
  bytes_received_24h: 1_500_000_000,
  total_users: users.length,
  active_tunnels: tunnels.filter((t) => t.status === "running").length,
  version: "0.1.0",
  healthy: true,
};

export const configSections = [
  {
    id: "network",
    title: "Network",
    description: "Listeners and inbound interfaces.",
    fields: [
      { key: "listen.http", label: "HTTP listener", value: "0.0.0.0:8080", type: "text" },
      { key: "listen.https", label: "HTTPS listener", value: "0.0.0.0:8443", type: "text" },
      { key: "listen.socks", label: "SOCKS listener", value: "0.0.0.0:1080", type: "text" },
      { key: "listen.admin", label: "Admin API", value: "0.0.0.0:8081", type: "text" },
    ],
  },
  {
    id: "auth",
    title: "Authentication",
    description: "JWT, mTLS, session lifecycle.",
    fields: [
      { key: "jwt.alg", label: "JWT algorithm", value: "HS256", type: "text" },
      { key: "jwt.ttl", label: "Session TTL (min)", value: "60", type: "number" },
      { key: "mtls.required", label: "Require mTLS", value: "false", type: "switch" },
    ],
  },
  {
    id: "limits",
    title: "Limits",
    description: "Default quotas applied to new users.",
    fields: [
      { key: "limit.conn", label: "Max connections", value: "100", type: "number" },
      { key: "limit.bw", label: "Bandwidth (MB)", value: "1000", type: "number" },
      { key: "limit.rate", label: "Rate limit (req/s)", value: "200", type: "number" },
    ],
  },
  {
    id: "logging",
    title: "Logging",
    description: "Audit, retention, structured logs.",
    fields: [
      { key: "log.level", label: "Log level", value: "info", type: "text" },
      { key: "log.retention", label: "Retention (days)", value: "30", type: "number" },
      { key: "log.structured", label: "Structured JSON", value: "true", type: "switch" },
    ],
  },
];