// React Query hooks over the real API client. Pages swap their static mock
// imports for these. Hooks return safe fallbacks (empty arrays) so existing
// page markup renders during load/error without per-page guards.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as api from "./api";

const LIST_STALE = 10_000;

export function useUsers() {
  const q = useQuery({ queryKey: ["users"], queryFn: api.listUsers, staleTime: LIST_STALE });
  return { ...q, users: q.data ?? [] };
}

/// id → username map for resolving the user_id-only fields on connections,
/// approvals, audit, usage, etc. into real names. Falls back to "User #<id>".
export function useUserMap() {
  const { users } = useUsers();
  const map = new Map<number, string>(users.map((u) => [u.id, u.username]));
  return (id: number | null | undefined): string =>
    id == null ? "—" : (map.get(id) ?? `User #${id}`);
}

export function useConnections(pollMs = 3000) {
  const q = useQuery({
    queryKey: ["connections"],
    queryFn: api.listConnections,
    refetchInterval: pollMs,
  });
  return { ...q, connections: q.data ?? [] };
}

export function useTunnels() {
  const q = useQuery({ queryKey: ["tunnels"], queryFn: api.listTunnels, staleTime: LIST_STALE });
  return { ...q, tunnels: q.data ?? [] };
}

export function useGroups() {
  const q = useQuery({ queryKey: ["groups"], queryFn: api.listGroups, staleTime: LIST_STALE });
  return { ...q, groups: q.data ?? [] };
}

export function useApprovalRequests() {
  const q = useQuery({
    queryKey: ["approval-requests"],
    queryFn: api.listApprovalRequests,
    staleTime: LIST_STALE,
  });
  return { ...q, requests: q.data ?? [] };
}

export function useApprovals() {
  const q = useQuery({
    queryKey: ["approvals"],
    queryFn: api.listApprovals,
    staleTime: LIST_STALE,
  });
  return { ...q, approvals: q.data ?? [] };
}

export function useAudit(limit = 100) {
  const q = useQuery({
    queryKey: ["audit", limit],
    queryFn: () => api.listAudit(limit),
    staleTime: LIST_STALE,
  });
  return { ...q, entries: q.data ?? [] };
}

export function useUsageSummary() {
  return useQuery({ queryKey: ["usage-summary"], queryFn: api.getUsageSummary });
}

export function useUsageTimeseries(days = 7, bucket: "hour" | "day" = "day") {
  return useQuery({
    queryKey: ["usage-ts", days, bucket],
    queryFn: () => api.getUsageTimeseries(days, bucket),
  });
}

export function useHealth(pollMs = 15000) {
  const q = useQuery({
    queryKey: ["health"],
    queryFn: api.getHealthComponents,
    refetchInterval: pollMs,
  });
  return { ...q, components: q.data ?? [] };
}

export function useConfig() {
  return useQuery({ queryKey: ["config"], queryFn: api.getConfig });
}

export function useDashboard(pollMs = 10000) {
  return useQuery({ queryKey: ["dashboard"], queryFn: api.getDashboard, refetchInterval: pollMs });
}

export function useSystemStats(pollMs = 10000) {
  return useQuery({
    queryKey: ["system-stats"],
    queryFn: api.getSystemStats,
    refetchInterval: pollMs,
  });
}

export function useApiKeys(userId: number, username = "") {
  const q = useQuery({
    queryKey: ["api-keys", userId],
    queryFn: () => api.listApiKeys(userId, username),
    enabled: Number.isFinite(userId) && userId > 0,
  });
  return { ...q, keys: q.data ?? [] };
}

// Generic invalidation helper for mutation onSuccess.
export function useInvalidate() {
  const qc = useQueryClient();
  return (keys: string[]) => keys.forEach((k) => qc.invalidateQueries({ queryKey: [k] }));
}

// Re-export the imperative mutation fns so pages can wire useMutation directly.
export { api, useMutation };
