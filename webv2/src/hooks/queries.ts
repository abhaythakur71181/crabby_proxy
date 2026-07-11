// TanStack Query hooks. Keys are namespaced tuples; pollers pause on hidden
// tabs (refetchIntervalInBackground stays false by default). Admin-only
// queries take an `enabled` flag so non-admin sessions never fire 403s.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSyncExternalStore } from "react";
import * as api from "@/api/endpoints";
import { getSession, isAdminRole, subscribeSession, type Session } from "@/lib/auth";

export function useSession(): Session | null {
  return useSyncExternalStore(subscribeSession, getSession, () => null);
}

export function useIsAdmin(): boolean {
  return isAdminRole(useSession()?.role);
}

export const keys = {
  dashboard: ["dashboard"] as const,
  metrics: ["metrics"] as const,
  health: ["health"] as const,
  deepHealth: ["health", "deep"] as const,
  users: (limit: number, offset: number) => ["users", limit, offset] as const,
  usersAll: ["users"] as const,
  user: (id: number) => ["user", id] as const,
  userQuota: (id: number) => ["user", id, "quota"] as const,
  userUsage: (id: number) => ["user", id, "usage"] as const,
  userUsageRecent: (id: number) => ["user", id, "usage-recent"] as const,
  userKeys: (id: number) => ["user", id, "api-keys"] as const,
  userGroups: (id: number) => ["user", id, "groups"] as const,
  userApprovals: (id: number) => ["user", id, "approvals"] as const,
  connections: ["connections"] as const,
  connectionCount: ["connections", "count"] as const,
  tunnels: ["tunnels"] as const,
  approvals: ["approvals"] as const,
  approvalRequests: ["approval-requests"] as const,
  groups: ["groups"] as const,
  group: (id: number) => ["group", id] as const,
  groupMembers: (id: number) => ["group", id, "members"] as const,
  audit: (limit: number, offset: number, userId?: number, action?: string) =>
    ["audit", limit, offset, userId ?? null, action ?? null] as const,
  usageSummary: (days: number) => ["usage-summary", days] as const,
  usageTimeseries: (days: number, bucket: string) => ["usage-ts", days, bucket] as const,
  config: ["config"] as const,
};

// ── Telemetry ──
export const useDashboard = (enabled = true) =>
  useQuery({ queryKey: keys.dashboard, queryFn: api.getDashboard, refetchInterval: 10_000, enabled });

export const useJsonMetrics = (enabled = true) =>
  useQuery({ queryKey: keys.metrics, queryFn: api.getJsonMetrics, refetchInterval: 10_000, enabled });

export const useDeepHealth = (enabled = true) =>
  useQuery({ queryKey: keys.deepHealth, queryFn: api.getDeepHealth, refetchInterval: 15_000, enabled });

// ── Users ──
export const useUsers = (limit = 50, offset = 0, enabled = true) =>
  useQuery({
    queryKey: keys.users(limit, offset),
    queryFn: () => api.listUsers(limit, offset),
    staleTime: 10_000,
    enabled,
    placeholderData: (prev) => prev, // keep page contents while paginating
  });

export const useUser = (id: number, enabled = true) =>
  useQuery({ queryKey: keys.user(id), queryFn: () => api.getUser(id), enabled: enabled && id > 0 });

/** Directory for resolving user_id → username in feeds/leaderboards.
 * Admin-only (regular users can't list users); falls back to "User #id". */
export function useUserDirectory(enabled = true) {
  const q = useQuery({
    queryKey: [...keys.usersAll, "directory"],
    queryFn: () => api.listUsers(200, 0),
    staleTime: 60_000,
    enabled,
  });
  const map = new Map<number, string>();
  q.data?.items.forEach((u) => map.set(u.id, u.username));
  return (id: number | null | undefined): string =>
    id == null ? "—" : (map.get(id) ?? `User #${id}`);
}

export const useUserQuota = (id: number, enabled = true) =>
  useQuery({ queryKey: keys.userQuota(id), queryFn: () => api.getUserQuota(id), enabled: enabled && id > 0 });

export const useUserUsage = (id: number, enabled = true) =>
  useQuery({ queryKey: keys.userUsage(id), queryFn: () => api.getUserUsage(id), enabled: enabled && id > 0 });

export const useUserUsageRecent = (id: number, enabled = true) =>
  useQuery({
    queryKey: keys.userUsageRecent(id),
    queryFn: () => api.getUserUsageRecent(id, 50),
    enabled: enabled && id > 0,
  });

export const useUserApiKeys = (id: number, enabled = true) =>
  useQuery({ queryKey: keys.userKeys(id), queryFn: () => api.listApiKeys(id), enabled: enabled && id > 0 });

export const useUserGroups = (id: number, enabled = true) =>
  useQuery({ queryKey: keys.userGroups(id), queryFn: () => api.listUserGroups(id), enabled: enabled && id > 0 });

export const useUserApprovals = (id: number, enabled = true) =>
  useQuery({
    queryKey: keys.userApprovals(id),
    queryFn: () => api.listUserApprovals(id),
    enabled: enabled && id > 0,
  });

// ── Traffic ──
export const useConnections = (enabled = true, pollMs: number | false = 3000) =>
  useQuery({
    queryKey: keys.connections,
    queryFn: api.listConnections,
    refetchInterval: pollMs,
    enabled,
  });

export const useTunnels = (enabled = true) =>
  useQuery({ queryKey: keys.tunnels, queryFn: api.listTunnels, refetchInterval: 10_000, enabled });

// ── Approvals ──
export const useApprovals = (enabled = true) =>
  useQuery({ queryKey: keys.approvals, queryFn: api.listApprovals, staleTime: 10_000, enabled });

export const useApprovalRequests = (enabled = true) =>
  useQuery({
    queryKey: keys.approvalRequests,
    queryFn: () => api.listApprovalRequests(),
    refetchInterval: 20_000,
    enabled,
  });

// ── Groups ──
export const useGroups = (enabled = true) =>
  useQuery({ queryKey: keys.groups, queryFn: api.listGroups, staleTime: 10_000, enabled });

export const useGroup = (id: number, enabled = true) =>
  useQuery({ queryKey: keys.group(id), queryFn: () => api.getGroup(id), enabled: enabled && id > 0 });

export const useGroupMembers = (id: number, enabled = true) =>
  useQuery({
    queryKey: keys.groupMembers(id),
    queryFn: () => api.listGroupMembers(id),
    enabled: enabled && id > 0,
  });

// ── Audit ──
export const useAuditLog = (
  opts: { limit: number; offset: number; user_id?: number; action?: string },
  enabled = true,
) =>
  useQuery({
    queryKey: keys.audit(opts.limit, opts.offset, opts.user_id, opts.action),
    queryFn: () => api.listAuditLog(opts),
    staleTime: 10_000,
    enabled,
    placeholderData: (prev) => prev,
  });

// ── Usage ──
export const useUsageSummary = (days = 30, enabled = true) =>
  useQuery({
    queryKey: keys.usageSummary(days),
    queryFn: () => api.getUsageSummary(days, 10),
    staleTime: 30_000,
    enabled,
  });

export const useUsageTimeseries = (days: number, bucket: "hour" | "day", enabled = true) =>
  useQuery({
    queryKey: keys.usageTimeseries(days, bucket),
    queryFn: () => api.getUsageTimeseries(days, bucket),
    staleTime: 30_000,
    enabled,
  });

// ── Config ──
export const useConfig = (enabled = true) =>
  useQuery({ queryKey: keys.config, queryFn: api.getConfig, staleTime: 30_000, enabled });

/** Invalidate by top-level namespace(s) — prefix matching handles sub-keys. */
export function useInvalidate() {
  const qc = useQueryClient();
  return (...prefixes: (readonly unknown[])[]) =>
    prefixes.forEach((p) => qc.invalidateQueries({ queryKey: p as unknown[] }));
}
