import type {
  User, Connection, DashboardData, ApiKey, UsageStats, UsageRecord,
  Quota, Group, GroupMember, Approval, Tunnel, AuditEntry, Session,
  HealthCheck, DeepHealthCheck, ServerConfig
} from './types';

const now = new Date();
const ago = (s: number) => new Date(now.getTime() - s * 1000).toISOString();
const future = (s: number) => new Date(now.getTime() + s * 1000).toISOString();

export const mockUsers: User[] = [
  { id: 1, username: 'root_admin', role: 'root_admin', is_active: true, max_connections: 1000, bandwidth_limit_mb: 0, last_login_at: ago(120), created_at: ago(86400 * 90) },
  { id: 2, username: 'admin_jane', role: 'admin', is_active: true, max_connections: 500, bandwidth_limit_mb: 50000, last_login_at: ago(3600), created_at: ago(86400 * 60) },
  { id: 3, username: 'user_bob', role: 'user', is_active: true, max_connections: 10, bandwidth_limit_mb: 5000, last_login_at: ago(7200), created_at: ago(86400 * 30) },
  { id: 4, username: 'user_alice', role: 'user', is_active: true, max_connections: 15, bandwidth_limit_mb: 5000, last_login_at: ago(14400), created_at: ago(86400 * 20) },
  { id: 5, username: 'user_charlie', role: 'user', is_active: false, max_connections: 5, bandwidth_limit_mb: 1000, last_login_at: null, created_at: ago(86400 * 10) },
  { id: 6, username: 'admin_dave', role: 'admin', is_active: true, max_connections: 200, bandwidth_limit_mb: 20000, last_login_at: ago(86400), created_at: ago(86400 * 45) },
];

export const mockConnections: Connection[] = [
  { id: 'a32fb4e1-7c2d-4a89-b3e5-1f8d9c2e351a', client_addr: '192.168.1.100:45032', target_addr: 'api.github.com:443', protocol: 'HTTPS', state: 'Active', user_id: 3, bytes_sent: 1048576, bytes_received: 5242880, created_at: ago(120) },
  { id: 'b45ec7f2-8d3e-5b9a-c4f6-2a9e0d3f462b', client_addr: '10.0.0.55:38291', target_addr: 'google.com:443', protocol: 'HTTP2', state: 'Active', user_id: 4, bytes_sent: 524288, bytes_received: 2097152, created_at: ago(45) },
  { id: 'c58fd903-9e4f-6ca0-d507-3b0f1e4a573c', client_addr: '172.16.0.12:52100', target_addr: 'npmjs.org:443', protocol: 'HTTPS', state: 'Active', user_id: 2, bytes_sent: 2097152, bytes_received: 10485760, created_at: ago(300) },
  { id: 'd69ae014-af50-7db1-e618-4c1a2f5b684d', client_addr: '192.168.1.200:41000', target_addr: '93.184.216.34:80', protocol: 'HTTP', state: 'Active', user_id: null, bytes_sent: 4096, bytes_received: 32768, created_at: ago(10) },
  { id: 'e70bf125-b061-8ec2-f729-5d2b3a6c795e', client_addr: '10.0.0.100:60123', target_addr: 'ssh.example.com:22', protocol: 'SOCKS5', state: 'Active', user_id: 3, bytes_sent: 131072, bytes_received: 65536, created_at: ago(600) },
  { id: 'f81ca236-c172-9fd3-a830-6e3c4b7d806f', client_addr: '192.168.2.50:33445', target_addr: 'ftp.debian.org:21', protocol: 'SOCKS4', state: 'Active', user_id: 6, bytes_sent: 8192, bytes_received: 1073741824, created_at: ago(1800) },
  { id: 'a92db347-d283-0ae4-b941-7f4d5c8e917a', client_addr: '10.0.0.77:49200', target_addr: 'api.stripe.com:443', protocol: 'HTTPS', state: 'Pending', user_id: 4, bytes_sent: 0, bytes_received: 0, created_at: ago(2) },
  { id: 'b03ec458-e394-1bf5-ca52-8a5e6d9fa028', client_addr: '172.16.0.30:55678', target_addr: 'cdn.cloudflare.com:443', protocol: 'HTTP2', state: 'Active', user_id: 1, bytes_sent: 4194304, bytes_received: 16777216, created_at: ago(900) },
];

export const mockDashboard: DashboardData = {
  uptime_seconds: 228720,
  active_connections: 42,
  total_connections: 15234,
  bandwidth_24h: 4521844736,
  total_users: 6,
  active_tunnels: 3,
  bytes_sent: 1836484608,
  bytes_received: 2685360128,
  status: 'healthy',
  version: '0.1.0',
  top_users_24h: [
    { user_id: 3, username: 'user_bob', bandwidth: 1073741824, connections: 342 },
    { user_id: 4, username: 'user_alice', bandwidth: 858993459, connections: 256 },
    { user_id: 2, username: 'admin_jane', bandwidth: 536870912, connections: 189 },
    { user_id: 6, username: 'admin_dave', bandwidth: 268435456, connections: 95 },
    { user_id: 1, username: 'root_admin', bandwidth: 134217728, connections: 42 },
  ],
};

export const mockApiKeys: Record<number, ApiKey[]> = {
  1: [
    { id: 1, prefix: 'cp_r1a2', name: 'Main Admin Key', created_at: ago(86400 * 30), last_used_at: ago(60), expires_at: null, is_active: true },
    { id: 2, prefix: 'cp_r3b4', name: 'CI/CD Pipeline', created_at: ago(86400 * 10), last_used_at: ago(3600), expires_at: future(86400 * 60), is_active: true },
  ],
  3: [
    { id: 3, prefix: 'cp_u5c6', name: 'Personal Key', created_at: ago(86400 * 5), last_used_at: ago(7200), expires_at: future(86400 * 25), is_active: true },
    { id: 4, prefix: 'cp_u7d8', name: 'Old Key', created_at: ago(86400 * 60), last_used_at: ago(86400 * 30), expires_at: ago(86400), is_active: false },
  ],
};

export const mockUsageStats: Record<string, UsageStats> = {
  '3-30': { user_id: 3, period_days: 30, connection_count: 1234, bytes_sent: 5368709120, bytes_received: 10737418240, total_bandwidth: 16106127360 },
  '3-7': { user_id: 3, period_days: 7, connection_count: 342, bytes_sent: 1073741824, bytes_received: 2147483648, total_bandwidth: 3221225472 },
  '3-1': { user_id: 3, period_days: 1, connection_count: 48, bytes_sent: 134217728, bytes_received: 268435456, total_bandwidth: 402653184 },
};

export const mockRecentUsage: UsageRecord[] = [
  { connection_id: 'a32fb4e1-7c2d-4a89-b3e5-1f8d9c2e351a', client_ip: '192.168.1.100', target_host: 'api.github.com:443', protocol: 'HTTPS', duration_seconds: 45, bytes_sent: 1048576, bytes_received: 5242880, status: 'success', started_at: ago(120) },
  { connection_id: 'e70bf125-b061-8ec2-f729-5d2b3a6c795e', client_ip: '10.0.0.100', target_host: 'ssh.example.com:22', protocol: 'SOCKS5', duration_seconds: 600, bytes_sent: 131072, bytes_received: 65536, status: 'success', started_at: ago(600) },
  { connection_id: 'f81ca236-c172-9fd3-a830-6e3c4b7d806f', client_ip: '192.168.2.50', target_host: 'ftp.debian.org:21', protocol: 'SOCKS4', duration_seconds: 1800, bytes_sent: 8192, bytes_received: 1073741824, status: 'success', started_at: ago(1800) },
  { connection_id: '11111111-aaaa-bbbb-cccc-dddddddddddd', client_ip: '10.0.0.55', target_host: 'badsite.example:443', protocol: 'HTTPS', duration_seconds: 2, bytes_sent: 512, bytes_received: 0, status: 'error', started_at: ago(3600) },
  { connection_id: '22222222-aaaa-bbbb-cccc-dddddddddddd', client_ip: '172.16.0.12', target_host: 'slow-api.io:443', protocol: 'HTTP2', duration_seconds: 30, bytes_sent: 4096, bytes_received: 0, status: 'timeout', started_at: ago(5400) },
];

export const mockQuotas: Record<number, Quota> = {
  3: { user_id: 3, quota_bytes: 10737418240, used_bytes: 7516192768, remaining_bytes: 3221225472, percentage_used: 70 },
  4: { user_id: 4, quota_bytes: 10737418240, used_bytes: 2147483648, remaining_bytes: 8589934592, percentage_used: 20 },
  5: { user_id: 5, quota_bytes: 1073741824, used_bytes: 966367641, remaining_bytes: 107374183, percentage_used: 90 },
  1: { user_id: 1, quota_bytes: null, used_bytes: 53687091200, remaining_bytes: null, percentage_used: 0 },
  2: { user_id: 2, quota_bytes: 53687091200, used_bytes: 10737418240, remaining_bytes: 42949672960, percentage_used: 20 },
};

export const mockGroups: Group[] = [
  { id: 1, name: 'Engineering', description: 'Engineering team members', member_count: 3, created_at: ago(86400 * 60) },
  { id: 2, name: 'QA', description: 'Quality assurance team', member_count: 2, created_at: ago(86400 * 30) },
  { id: 3, name: 'External', description: 'External contractors', member_count: 1, created_at: ago(86400 * 10) },
];

export const mockGroupMembers: Record<number, GroupMember[]> = {
  1: [
    { user_id: 3, username: 'user_bob', role: 'user', joined_at: ago(86400 * 55) },
    { user_id: 4, username: 'user_alice', role: 'user', joined_at: ago(86400 * 50) },
    { user_id: 2, username: 'admin_jane', role: 'admin', joined_at: ago(86400 * 58) },
  ],
  2: [
    { user_id: 4, username: 'user_alice', role: 'user', joined_at: ago(86400 * 25) },
    { user_id: 6, username: 'admin_dave', role: 'admin', joined_at: ago(86400 * 28) },
  ],
  3: [
    { user_id: 5, username: 'user_charlie', role: 'user', joined_at: ago(86400 * 8) },
  ],
};

export const mockApprovals: Approval[] = [
  { id: 1, user_id: 3, username: 'user_bob', client_ip: '203.0.113.50', approved_by: 1, approved_at: ago(3600), expires_at: future(82800), duration_hours: 24, reason: 'Remote work access' },
  { id: 2, user_id: 4, username: 'user_alice', client_ip: '198.51.100.22', approved_by: 2, approved_at: ago(7200), expires_at: future(597600), duration_hours: 168, reason: 'VPN access for sprint' },
  { id: 3, user_id: 6, username: 'admin_dave', client_ip: '192.0.2.100', approved_by: 1, approved_at: ago(1800), expires_at: future(84600), duration_hours: 24, reason: 'Emergency maintenance' },
];

export const mockTunnels: Tunnel[] = [
  { listen_port: 10001, service_type: 'http', target_addr: '127.0.0.1:3000', status: 'active', created_at: ago(86400 * 5) },
  { listen_port: 10002, service_type: 'ssh', target_addr: '127.0.0.1:22', status: 'active', created_at: ago(86400 * 3) },
  { listen_port: 10003, service_type: 'postgres', target_addr: '127.0.0.1:5432', status: 'active', created_at: ago(86400) },
];

export const mockAuditLog: AuditEntry[] = [
  { id: 1, user_id: 1, username: 'root_admin', action: 'user.create', target_type: 'user', target_id: '5', details: 'Created user user_charlie', ip_address: '127.0.0.1', created_at: ago(86400 * 10) },
  { id: 2, user_id: 1, username: 'root_admin', action: 'user.update', target_type: 'user', target_id: '3', details: 'Updated bandwidth limit to 5000 MB', ip_address: '127.0.0.1', created_at: ago(86400 * 9) },
  { id: 3, user_id: 2, username: 'admin_jane', action: 'approval.create', target_type: 'approval', target_id: '1', details: 'Approved IP 203.0.113.50 for user_bob', ip_address: '10.0.0.1', created_at: ago(3600) },
  { id: 4, user_id: 1, username: 'root_admin', action: 'config.reload', target_type: 'config', target_id: '-', details: 'Configuration reloaded successfully', ip_address: '127.0.0.1', created_at: ago(7200) },
  { id: 5, user_id: 3, username: 'user_bob', action: 'apikey.create', target_type: 'api_key', target_id: '3', details: 'Created API key cp_u5c6', ip_address: '192.168.1.100', created_at: ago(86400 * 5) },
  { id: 6, user_id: 1, username: 'root_admin', action: 'tunnel.create', target_type: 'tunnel', target_id: '10001', details: 'Created HTTP tunnel on port 10001', ip_address: '127.0.0.1', created_at: ago(86400 * 5) },
  { id: 7, user_id: 2, username: 'admin_jane', action: 'group.create', target_type: 'group', target_id: '2', details: 'Created group QA', ip_address: '10.0.0.1', created_at: ago(86400 * 30) },
  { id: 8, user_id: 1, username: 'root_admin', action: 'user.delete', target_type: 'user', target_id: '7', details: 'Deleted user temp_user', ip_address: '127.0.0.1', created_at: ago(86400 * 2) },
  { id: 9, user_id: 6, username: 'admin_dave', action: 'approval.terminate', target_type: 'approval', target_id: '4', details: 'Terminated approval: Access no longer needed', ip_address: '172.16.0.30', created_at: ago(86400) },
  { id: 10, user_id: 1, username: 'root_admin', action: 'user.login', target_type: 'session', target_id: '1', details: 'Login from 127.0.0.1', ip_address: '127.0.0.1', created_at: ago(120) },
];

export const mockSessions: Record<number, Session[]> = {
  1: [
    { id: 'sess_a1b2c3', created_at: ago(120), expires_at: future(86280), ip_address: '127.0.0.1', user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)' },
  ],
  3: [
    { id: 'sess_d4e5f6', created_at: ago(7200), expires_at: future(79200), ip_address: '192.168.1.100', user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
    { id: 'sess_g7h8i9', created_at: ago(86400), expires_at: future(0), ip_address: '192.168.1.101', user_agent: 'curl/7.88.1' },
  ],
};

export const mockHealth: HealthCheck = {
  status: 'healthy', uptime_seconds: 228720, version: '0.1.0',
};

export const mockDeepHealth: DeepHealthCheck = {
  status: 'healthy', uptime_seconds: 228720, version: '0.1.0',
  checks: {
    database: { status: 'ok', detail: null },
    state_backend: { status: 'ok', detail: null },
    dns_cache: { status: 'ok', detail: '42 entries, 128 addresses cached' },
  },
};

export const mockConfig: ServerConfig = {
  server: { proxy_bind: '0.0.0.0:8080', admin_bind: '127.0.0.1:8081', max_connections: 10000 },
  authentication: { enabled: true },
  features: { connection_approval: true, reverse_tunnels: true },
};

export const mockUsageSummary = {
  total_connections: 15234,
  total_bandwidth: 4521844736,
  unique_users: 5,
  total_bytes_sent: 1836484608,
  total_bytes_received: 2685360128,
  top_users: mockDashboard.top_users_24h,
};

export const mockMetrics = {
  active_by_protocol: { HTTP: 5, HTTPS: 18, SOCKS4: 3, SOCKS5: 8, HTTP2: 8 },
  requests_total: { success: 14200, failed: 1034 },
  auth_total: { success: 12800, failed: 420 },
  bytes_transferred: { sent: 1836484608, received: 2685360128 },
  ip_filter: { allowed: 15000, blocked: 234 },
  rate_limit_exceeded: { ip: 45, user: 12 },
  auth_failures_by_reason: { invalid_credentials: 310, expired_token: 80, disabled_account: 30 },
  connection_duration_p50: 12.5,
  connection_duration_p95: 45.2,
  connection_duration_p99: 120.8,
  upstream_connect_p50: 0.05,
  upstream_connect_p95: 0.25,
  upstream_connect_p99: 1.2,
  draining: false,
  draining_connections: 0,
};
