import type { UserGroupWithCount } from "@/api/types";

/** Short labels for the policy fields a group sets (shown as chips). */
export function groupPolicyChips(g: UserGroupWithCount | Omit<UserGroupWithCount, "member_count">) {
  const chips: string[] = [];
  if (g.max_connections != null) chips.push(`${g.max_connections} conns`);
  if (g.bandwidth_limit_mb != null) chips.push(`${g.bandwidth_limit_mb} MB`);
  if (g.rate_limit_rps != null) chips.push(`${g.rate_limit_rps} rps`);
  if (g.allowed_protocols) chips.push("protocols");
  if (g.allowed_targets) chips.push("allow-list");
  if (g.blocked_targets) chips.push("block-list");
  if (g.access_schedule) chips.push("schedule");
  return chips;
}
