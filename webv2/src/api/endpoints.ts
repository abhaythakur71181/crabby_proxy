// One typed function per backend endpoint — full coverage of the admin API.
import { get, post, put, del } from "./http";
import type {
  ApiKeyResponse,
  ApprovalRequestResponse,
  ApprovalResponse,
  AuditLogResponse,
  ConfigResponse,
  ConnectionInfo,
  CreateApiKeyResponse,
  CreateUserBody,
  DashboardResponse,
  DeepHealthResponse,
  GroupMembersResponse,
  HealthResponse,
  JsonMetricsResponse,
  LiveTicketResponse,
  QuotaResponse,
  SessionInfo,
  SystemUsageSummary,
  TunnelInfo,
  TunnelsListResponse,
  UpdateConfigBody,
  UpdateUserBody,
  UsageRecordResponse,
  UsageStatsResponse,
  UsageTimeseries,
  UserGroup,
  UserGroupWithCount,
  UserResponse,
  UsersListResponse,
  LoginResponse,
} from "./types";

// ── Auth ──
export const login = (username: string, password: string) =>
  post<LoginResponse>("/api/login", { username, password });

// ── Health / telemetry ──
export const getHealth = () => get<HealthResponse>("/health");
export const getDeepHealth = () => get<DeepHealthResponse>("/health/deep");
export const getDashboard = () => get<DashboardResponse>("/api/dashboard");
export const getJsonMetrics = () => get<JsonMetricsResponse>("/api/metrics");

// ── Users ──
export const listUsers = (limit = 200, offset = 0) =>
  get<UsersListResponse>(`/api/users?limit=${limit}&offset=${offset}`);
export const getUser = (id: number) => get<UserResponse>(`/api/users/${id}`);
export const createUser = (body: CreateUserBody) => post<UserResponse>("/api/users", body);
export const updateUser = (id: number, body: UpdateUserBody) =>
  put<UserResponse>(`/api/users/${id}`, body);
export const deleteUser = (id: number) => del<void>(`/api/users/${id}`);

// ── API keys ──
export const listApiKeys = (userId: number) =>
  get<ApiKeyResponse[]>(`/api/users/${userId}/api-keys`);
export const createApiKey = (userId: number, body: { name?: string; expires_in_days?: number }) =>
  post<CreateApiKeyResponse>(`/api/users/${userId}/api-keys`, body);
export const revokeApiKey = (userId: number, keyId: number) =>
  del<void>(`/api/users/${userId}/api-keys/${keyId}`);

// ── Usage / quota ──
export const getUserUsage = (id: number, days = 30) =>
  get<UsageStatsResponse>(`/api/users/${id}/usage?days=${days}`);
export const getUserUsageRecent = (id: number, limit = 50) =>
  get<UsageRecordResponse[]>(`/api/users/${id}/usage/recent?limit=${limit}`);
export const getUserUsageAllTime = (id: number) =>
  get<UsageStatsResponse>(`/api/users/${id}/usage/all-time`);
export const getUsageSummary = (days = 30, limit = 10) =>
  get<SystemUsageSummary>(`/api/usage/summary?days=${days}&limit=${limit}`);
export const getUsageTimeseries = (days: number, bucket: "hour" | "day") =>
  get<UsageTimeseries>(`/api/usage/timeseries?days=${days}&bucket=${bucket}`);
export const getUserQuota = (id: number) => get<QuotaResponse>(`/api/users/${id}/quota`);
export const updateUserQuota = (id: number, quota_bytes: number | null) =>
  put<QuotaResponse>(`/api/users/${id}/quota`, { quota_bytes });

// ── Sessions ──
export const getUserSessions = (id: number) => get<SessionInfo[]>(`/api/users/${id}/sessions`);
export const deleteUserSessions = (id: number) =>
  del<{ deleted: number; user_id: number }>(`/api/users/${id}/sessions`);

// ── Connections ──
export const listConnections = () => get<ConnectionInfo[]>("/api/connections");
export const getConnectionCount = () => get<number>("/api/connections/count");
export const terminateConnection = (id: string) => del<void>(`/api/connections/${id}`);
export const issueLiveTicket = () => post<LiveTicketResponse>("/api/connections/live-ticket");

// ── Tunnels ──
export const listTunnels = () => get<TunnelsListResponse>("/api/tunnels");
export const createTunnel = (body: { service_type: string; port?: number; target_addr?: string }) =>
  post<TunnelInfo>("/api/tunnels", body);
export const closeTunnel = (port: number) => del<void>(`/api/tunnels/${port}`);

// ── Approvals (grants) ──
export const listApprovals = () => get<ApprovalResponse[]>("/api/approvals");
export const listUserApprovals = (userId: number) =>
  get<ApprovalResponse[]>(`/api/users/${userId}/approvals`);
export const createApproval = (body: {
  user_id: number;
  client_ip: string;
  duration_hours: number;
  reason?: string;
}) => post<ApprovalResponse>("/api/approvals", body);
/** Backend REQUIRES a JSON body with a reason on terminate. */
export const terminateApproval = (id: number, reason: string) =>
  del<void>(`/api/approvals/${id}`, { reason });

// ── Approval requests (workflow) ──
export const listApprovalRequests = (status?: string) =>
  get<ApprovalRequestResponse[]>(
    `/api/approval-requests${status ? `?status=${encodeURIComponent(status)}` : ""}`,
  );
export const createApprovalRequest = (body: {
  client_ip: string;
  duration_hours: number;
  reason?: string;
}) => post<{ id: number; user_id: number; status: string; requested_at: number }>(
  "/api/approval-requests",
  body,
);
export const approveRequest = (id: number, reason?: string) =>
  post<{ id: number; status: string; user_id: number }>(
    `/api/approval-requests/${id}/approve`,
    { reason: reason ?? null },
  );
export const rejectRequest = (id: number, reason?: string) =>
  post<{ id: number; status: string }>(`/api/approval-requests/${id}/reject`, {
    reason: reason ?? null,
  });

// ── Groups ──
export const listGroups = () => get<UserGroupWithCount[]>("/api/groups");
export const getGroup = (id: number) => get<UserGroup>(`/api/groups/${id}`);
export const createGroup = (body: { name: string; description?: string }) =>
  post<{ id: number; name: string }>("/api/groups", body);
export const deleteGroup = (id: number) => del<void>(`/api/groups/${id}`);
export const listGroupMembers = (id: number) =>
  get<GroupMembersResponse>(`/api/groups/${id}/members`);
export const addGroupMember = (groupId: number, userId: number) =>
  post<void>(`/api/groups/${groupId}/members`, { user_id: userId });
export const removeGroupMember = (groupId: number, userId: number) =>
  del<void>(`/api/groups/${groupId}/members/${userId}`);
export const listUserGroups = (userId: number) => get<UserGroup[]>(`/api/users/${userId}/groups`);

// ── Audit ──
export const listAuditLog = (opts: {
  limit?: number;
  offset?: number;
  user_id?: number;
  action?: string;
}) => {
  const p = new URLSearchParams();
  p.set("limit", String(opts.limit ?? 50));
  p.set("offset", String(opts.offset ?? 0));
  if (opts.user_id != null) p.set("user_id", String(opts.user_id));
  if (opts.action) p.set("action", opts.action);
  return get<AuditLogResponse>(`/api/audit-log?${p.toString()}`);
};

// ── Config ──
export const getConfig = () => get<ConfigResponse>("/api/config");
export const updateConfig = (body: UpdateConfigBody) => put<ConfigResponse>("/api/config", body);
export const reloadConfig = () =>
  post<{ success: boolean; message: string }>("/api/config/reload");
