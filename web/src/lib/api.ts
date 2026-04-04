/**
 * Crabby Proxy Admin API Client
 *
 * Real HTTP client that talks to the Rust backend.
 * In development, Vite proxies /api/* → http://127.0.0.1:8081
 */
import type { UserRole } from './types';

// ── Helpers ─────────────────────────────────────────────────────────

function getToken(): string | null {
  try {
    const stored = localStorage.getItem('crabby_auth');
    if (!stored) return null;
    return JSON.parse(stored).token;
  } catch {
    return null;
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(path, { ...options, headers });

  if (res.status === 401) {
    // Token expired or invalid – force re-login
    localStorage.removeItem('crabby_auth');
    window.location.href = '/login';
    throw new Error('Session expired');
  }

  if (res.status === 204) {
    return {} as T;
  }

  if (!res.ok) {
    let errorMessage = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      errorMessage = body.error || body.message || errorMessage;
    } catch { /* body not JSON */ }
    throw new Error(errorMessage);
  }

  // Some endpoints return plain text (e.g., /metrics)
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return res.json();
  }
  return (await res.text()) as unknown as T;
}

function get<T>(path: string): Promise<T> {
  return request<T>(path);
}

function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    body: body ? JSON.stringify(body) : undefined,
  });
}

function put<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: 'PUT',
    body: body ? JSON.stringify(body) : undefined,
  });
}

function del<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: 'DELETE',
    body: body ? JSON.stringify(body) : undefined,
  });
}

// ── API ─────────────────────────────────────────────────────────────

export const api = {
  // ── Auth ──
  async login(username: string, password: string) {
    const res = await request<{ token: string; expires_in: number; role: string }>('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
      // Don't send auth header for login
      headers: { 'Content-Type': 'application/json' },
    });
    // Backend returns { token, expires_in, role } — we need user_id too.
    // Decode from JWT payload (base64 middle segment)
    let user_id = 0;
    let uname = username;
    try {
      const payload = JSON.parse(atob(res.token.split('.')[1]));
      user_id = payload.user_id || payload.sub || 0;
      uname = payload.username || username;
    } catch { /* fallback */ }
    return {
      token: res.token,
      expires_in: res.expires_in,
      role: res.role as UserRole,
      user_id,
      username: uname,
    };
  },

  // ── Dashboard ──
  getDashboard: () => get<any>('/api/dashboard'),

  // ── Connections ──
  getConnections: () => get<any[]>('/api/connections'),
  getConnectionCount: () => get<number>('/api/connections/count'),

  // ── Users ──
  async getUsers(params?: { limit?: number; offset?: number }) {
    // Always send pagination params to get consistent { items, total, limit, offset } response
    const limit = params?.limit || 200;
    const offset = params?.offset || 0;
    const qs = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    return get<any>(`/api/users?${qs.toString()}`);
  },
  getUser: (id: number) => get<any>(`/api/users/${id}`),
  createUser: (data: { username: string; password: string; role: UserRole; max_connections?: number; bandwidth_limit_mb?: number }) =>
    post<any>('/api/users', data),
  updateUser: (id: number, data: Partial<{ password: string; role: UserRole; max_connections: number; bandwidth_limit_mb: number; is_active: boolean }>) =>
    put<any>(`/api/users/${id}`, data),
  deleteUser: (id: number) => del<any>(`/api/users/${id}`),

  // ── API Keys ──
  getUserApiKeys: (userId: number) => get<any[]>(`/api/users/${userId}/api-keys`),
  createApiKey: (userId: number, data: { name?: string; expires_in_days?: number }) =>
    post<any>(`/api/users/${userId}/api-keys`, data),
  revokeApiKey: (userId: number, keyId: number) =>
    del<any>(`/api/users/${userId}/api-keys/${keyId}`),

  // ── Usage ──
  getUserUsage: (userId: number, days = 30) =>
    get<any>(`/api/users/${userId}/usage?days=${days}`),
  getUserRecentUsage: (userId: number, limit = 100) =>
    get<any[]>(`/api/users/${userId}/usage/recent?limit=${limit}`),
  getUserAllTimeUsage: (userId: number) =>
    get<any>(`/api/users/${userId}/usage/all-time`),
  getUsageSummary: (days = 30, limit = 10) =>
    get<any>(`/api/usage/summary?days=${days}&limit=${limit}`),

  // ── Quota ──
  getUserQuota: (userId: number) =>
    get<any>(`/api/users/${userId}/quota`),
  updateUserQuota: (userId: number, quotaBytes: number | null) =>
    put<any>(`/api/users/${userId}/quota`, { quota_bytes: quotaBytes }),

  // ── Groups ──
  getGroups: () => get<any[]>('/api/groups'),
  getGroup: (id: number) => get<any>(`/api/groups/${id}`),
  createGroup: (data: { name: string; description?: string }) =>
    post<any>('/api/groups', data),
  deleteGroup: (id: number) => del<any>(`/api/groups/${id}`),
  getGroupMembers: (groupId: number) =>
    get<any>(`/api/groups/${groupId}/members`),
  addGroupMember: (groupId: number, userId: number) =>
    post<any>(`/api/groups/${groupId}/members`, { user_id: userId }),
  removeGroupMember: (groupId: number, userId: number) =>
    del<any>(`/api/groups/${groupId}/members/${userId}`),

  // ── Approvals ──
  getApprovals: () => get<any[]>('/api/approvals'),
  createApproval: (data: { user_id: number; client_ip: string; duration_hours: number; reason?: string }) =>
    post<any>('/api/approvals', data),
  terminateApproval: (id: number, reason: string) =>
    del<any>(`/api/approvals/${id}`, { reason }),
  getUserApprovals: (userId: number) =>
    get<any[]>(`/api/users/${userId}/approvals`),

  // ── Tunnels ──
  getTunnels: () => get<any>('/api/tunnels'),
  createTunnel: (data: { service_type: string; port?: number; target_addr?: string }) =>
    post<any>('/api/tunnels', data),
  closeTunnel: (port: number) => del<any>(`/api/tunnels/${port}`),

  // ── Config ──
  getConfig: () => get<any>('/api/config'),
  reloadConfig: () => post<any>('/api/config/reload'),

  // ── Audit Log ──
  async getAuditLog(params?: { limit?: number; offset?: number; action?: string; user_id?: number }) {
    const qs = new URLSearchParams();
    if (params?.limit) qs.set('limit', String(params.limit));
    if (params?.offset) qs.set('offset', String(params.offset));
    if (params?.action) qs.set('action', params.action);
    if (params?.user_id) qs.set('user_id', String(params.user_id));
    const query = qs.toString();
    return get<any>(`/api/audit-log${query ? `?${query}` : ''}`);
  },

  // ── Health ──
  getHealth: () => get<any>('/health'),
  getDeepHealth: () => get<any>('/health/deep'),

  // ── Metrics ──
  getMetrics: () => get<string>('/metrics'),

  // ── Sessions ──
  getUserSessions: (userId: number) =>
    get<any[]>(`/api/users/${userId}/sessions`),
  forceLogoutUser: (userId: number) =>
    del<any>(`/api/users/${userId}/sessions`),

  // ── User Groups ──
  getUserGroups: (userId: number) =>
    get<any[]>(`/api/users/${userId}/groups`),
};
