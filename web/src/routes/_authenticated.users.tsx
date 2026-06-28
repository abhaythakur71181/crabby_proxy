import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { Check, Copy, KeyRound, LogOut, Plus, RotateCcw, Search, Trash2, X } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Panel } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { Pill } from "@/components/app/badge";
import { StatusDot } from "@/components/app/status-dot";
import { Mono } from "@/components/app/mono";
import { DetailDrawer } from "@/components/app/detail-drawer";
import { api, useApiKeys, useInvalidate, useMutation, useUsers } from "@/lib/queries";
import { getSession } from "@/lib/auth";
import { fmtBytes, fmtRelative } from "@/lib/format";
import type { Role, User } from "@/types/crabby";

export const Route = createFileRoute("/_authenticated/users")({
  head: () => ({ meta: [{ title: "Users · Crabby Proxy" }] }),
  component: UsersPage,
});

const ROLES: ("ALL" | Role)[] = ["ALL", "root_admin", "admin", "user"];

// RBAC: can the viewer deactivate the target user?
//  - admin: only plain "user" rows.
//  - root_admin: anyone except other root_admin rows (incl. self).
function canDeactivate(viewer: Role | undefined, target: User): boolean {
  if (!viewer) return false;
  if (viewer === "root_admin") return target.role !== "root_admin";
  if (viewer === "admin") return target.role === "user";
  return false;
}

function roleVariant(role: Role) {
  return role === "root_admin" ? "danger" : role === "admin" ? "violet" : "outline";
}

function UsersPage() {
  const { users, isLoading } = useUsers();
  const [q, setQ] = useState("");
  const [role, setRole] = useState<(typeof ROLES)[number]>("ALL");
  const [openNew, setOpenNew] = useState(false);
  const [active, setActive] = useState<User | null>(null);

  const viewerRole = getSession()?.role;

  const filtered = useMemo(
    () =>
      users.filter((u) => {
        if (role !== "ALL" && u.role !== role) return false;
        if (!q.trim()) return true;
        return u.username.toLowerCase().includes(q.trim().toLowerCase());
      }),
    [users, role, q],
  );

  return (
    <div className="mx-auto w-full max-w-[1400px] px-6 py-8 lg:px-10">
      <PageHeader
        title="Users"
        subtitle="Provision identities, set per-user quotas, and gate access."
        action={
          <button
            onClick={() => setOpenNew(true)}
            className="group inline-flex h-10 items-center gap-2 rounded-xl bg-[var(--accent-violet)] px-4 text-sm font-semibold text-[var(--primary-foreground)] shadow-[0_10px_30px_-10px_var(--accent-violet)] transition hover:brightness-110"
          >
            <Plus className="size-4" />
            New user
          </button>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="flex h-10 flex-1 items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 transition focus-within:border-[var(--accent-violet)]/50">
          <Search className="size-4 text-muted-foreground" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search usernames…"
            className="h-full flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
        </div>
        <div className="flex h-10 items-center gap-1 rounded-xl border border-white/[0.08] bg-white/[0.02] p-1">
          {ROLES.map((r) => (
            <button
              key={r}
              onClick={() => setRole(r)}
              className={
                "rounded-lg px-3 text-[11px] font-medium uppercase tracking-wider transition " +
                (role === r ? "bg-white/[0.08] text-foreground" : "text-muted-foreground hover:text-foreground")
              }
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      <Panel>
        <div className="grid grid-cols-[40px_1.4fr_120px_110px_90px_100px_100px_88px] gap-3 border-b border-white/[0.06] px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          <span>#</span>
          <span>Username</span>
          <span>Role</span>
          <span>Status</span>
          <span className="text-right">Max Conn.</span>
          <span className="text-right">BW Limit</span>
          <span className="text-right">Last login</span>
          <span className="text-right">Actions</span>
        </div>
        <ul className="divide-y divide-white/[0.04]">
          {isLoading && !filtered.length && (
            <li className="px-5 py-8 text-center text-sm text-muted-foreground">Loading users…</li>
          )}
          {!isLoading && !filtered.length && (
            <li className="px-5 py-8 text-center text-sm text-muted-foreground">No users found.</li>
          )}
          {filtered.map((u, i) => (
            <UserRow key={u.id} user={u} index={i} viewerRole={viewerRole} onOpen={() => setActive(u)} />
          ))}
        </ul>
      </Panel>

      <UserDetail user={active} viewerRole={viewerRole} onClose={() => setActive(null)} />

      <CreateUserModal open={openNew} onClose={() => setOpenNew(false)} />
    </div>
  );
}

function UserRow({
  user,
  index,
  viewerRole,
  onOpen,
}: {
  user: User;
  index: number;
  viewerRole: Role | undefined;
  onOpen: () => void;
}) {
  const invalidate = useInvalidate();
  const deactivate = useMutation({
    mutationFn: (id: number) => api.deleteUser(id),
    onSuccess: () => {
      toast.success("User deactivated");
      invalidate(["users"]);
    },
    onError: (err: Error) => toast.error(err.message),
  });
  const reactivate = useMutation({
    mutationFn: (id: number) => api.updateUser(id, { is_active: true }),
    onSuccess: () => {
      toast.success("User reactivated");
      invalidate(["users"]);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const allowed = canDeactivate(viewerRole, user);

  return (
    <motion.li
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.03 }}
      onClick={onOpen}
      className="grid cursor-pointer grid-cols-[40px_1.4fr_120px_110px_90px_100px_100px_88px] items-center gap-3 px-5 py-3 text-sm transition hover:bg-white/[0.03]"
    >
      <Mono className="text-[11px] text-muted-foreground">{user.id}</Mono>
      <div className="flex items-center gap-3">
        <div className="grid size-7 place-items-center rounded-md bg-white/5 text-[10px] font-semibold uppercase">
          {user.username.slice(0, 2)}
        </div>
        <span className="font-medium">{user.username}</span>
      </div>
      <Pill variant={roleVariant(user.role)}>{user.role}</Pill>
      <span className="flex items-center gap-1.5 text-xs">
        <StatusDot tone={user.active ? "success" : "danger"} pulse={user.active} />
        {user.active ? "Active" : "Disabled"}
      </span>
      <Mono className="text-right text-xs">{user.max_connections.toLocaleString()}</Mono>
      <Mono className="text-right text-xs">{user.bandwidth_limit_mb.toLocaleString()} MB</Mono>
      <span className="text-right text-xs text-muted-foreground">{fmtRelative(user.last_login_at)}</span>
      <div className="flex items-center justify-end" onClick={(e) => e.stopPropagation()}>
        {user.active ? (
          allowed ? (
            <button
              aria-label="Deactivate user"
              title="Deactivate user"
              disabled={deactivate.isPending}
              onClick={() => deactivate.mutate(user.id)}
              className="grid size-7 place-items-center rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/10 text-[var(--danger)] transition hover:bg-[var(--danger)]/15 disabled:opacity-50"
            >
              <Trash2 className="size-3.5" />
            </button>
          ) : (
            <span className="text-[10px] text-muted-foreground">—</span>
          )
        ) : (
          <button
            aria-label="Reactivate user"
            title="Reactivate user"
            disabled={reactivate.isPending}
            onClick={() => reactivate.mutate(user.id)}
            className="grid size-7 place-items-center rounded-lg border border-[var(--success)]/30 bg-[var(--success)]/10 text-[var(--success)] transition hover:bg-[var(--success)]/15 disabled:opacity-50"
          >
            <RotateCcw className="size-3.5" />
          </button>
        )}
      </div>
    </motion.li>
  );
}

function UserDetail({
  user,
  viewerRole,
  onClose,
}: {
  user: User | null;
  viewerRole: Role | undefined;
  onClose: () => void;
}) {
  const invalidate = useInvalidate();
  const isRoot = viewerRole === "root_admin";

  const deactivate = useMutation({
    mutationFn: (id: number) => api.deleteUser(id),
    onSuccess: () => {
      toast.success("User deactivated");
      invalidate(["users"]);
      onClose();
    },
    onError: (err: Error) => toast.error(err.message),
  });
  const reactivate = useMutation({
    mutationFn: (id: number) => api.updateUser(id, { is_active: true }),
    onSuccess: () => {
      toast.success("User reactivated");
      invalidate(["users"]);
      onClose();
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const footerAllowed = user ? canDeactivate(viewerRole, user) : false;

  return (
    <DetailDrawer
      open={!!user}
      onClose={onClose}
      width={540}
      eyebrow={user ? `User #${user.id}` : ""}
      title={user?.username ?? ""}
      footer={
        user && (
          <div className="flex items-center justify-between">
            {user.active ? (
              footerAllowed ? (
                <button
                  disabled={deactivate.isPending}
                  onClick={() => deactivate.mutate(user.id)}
                  className="flex items-center gap-1.5 rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/10 px-3 py-1.5 text-xs font-medium text-[var(--danger)] hover:bg-[var(--danger)]/15 disabled:opacity-50"
                >
                  <Trash2 className="size-3.5" /> Deactivate
                </button>
              ) : (
                <span className="text-[11px] text-muted-foreground">No permission to deactivate this user</span>
              )
            ) : (
              <button
                disabled={reactivate.isPending}
                onClick={() => reactivate.mutate(user.id)}
                className="flex items-center gap-1.5 rounded-lg border border-[var(--success)]/30 bg-[var(--success)]/10 px-3 py-1.5 text-xs font-medium text-[var(--success)] hover:bg-[var(--success)]/15 disabled:opacity-50"
              >
                <RotateCcw className="size-3.5" /> Reactivate
              </button>
            )}
            <button
              onClick={onClose}
              className="rounded-lg bg-white/[0.06] px-4 py-1.5 text-xs font-semibold text-foreground hover:bg-white/[0.1]"
            >
              Close
            </button>
          </div>
        )
      }
    >
      {user && (
        <div className="space-y-6">
          <div className="flex gap-2">
            <Pill variant={roleVariant(user.role)}>{user.role}</Pill>
            <Pill variant={user.active ? "success" : "danger"}>
              <StatusDot tone={user.active ? "success" : "danger"} /> {user.active ? "Active" : "Disabled"}
            </Pill>
          </div>

          <EditSection user={user} isRoot={isRoot} />

          <QuotaSection user={user} isRoot={isRoot} />

          <UsageSection user={user} />

          <ApiKeysSection user={user} />

          <SessionsSection user={user} />

          <div>
            <SectionLabel>Groups</SectionLabel>
            <div className="flex flex-wrap gap-2">
              {user.groups.length ? (
                user.groups.map((g) => <Pill key={g}>{g}</Pill>)
              ) : (
                <span className="text-xs text-muted-foreground">None</span>
              )}
            </div>
          </div>
        </div>
      )}
    </DetailDrawer>
  );
}

// ── Editable core fields (root_admin only; read-only for plain admin) ──
function EditSection({ user, isRoot }: { user: User; isRoot: boolean }) {
  const invalidate = useInvalidate();
  const [role, setRole] = useState<Role>(user.role === "root_admin" ? "root_admin" : user.role);
  const [maxConn, setMaxConn] = useState(user.max_connections);
  const [bw, setBw] = useState(user.bandwidth_limit_mb);
  const [activeState, setActiveState] = useState(user.active);

  // Re-sync local state when a different user is opened.
  const [seenId, setSeenId] = useState(user.id);
  if (seenId !== user.id) {
    setSeenId(user.id);
    setRole(user.role === "root_admin" ? "root_admin" : user.role);
    setMaxConn(user.max_connections);
    setBw(user.bandwidth_limit_mb);
    setActiveState(user.active);
  }

  const save = useMutation({
    mutationFn: () =>
      api.updateUser(user.id, {
        // never send root_admin as a role change — not selectable
        ...(user.role !== "root_admin" ? { role } : {}),
        max_connections: maxConn,
        bandwidth_limit_mb: bw,
        is_active: activeState,
      }),
    onSuccess: () => {
      toast.success("User updated");
      invalidate(["users"]);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  if (!isRoot) {
    return (
      <div>
        <SectionLabel>Configuration (read-only)</SectionLabel>
        <div className="grid grid-cols-2 gap-3">
          <Stat label="Role" value={user.role} />
          <Stat label="Status" value={user.active ? "Active" : "Disabled"} />
          <Stat label="Max connections" value={user.max_connections.toLocaleString()} />
          <Stat label="Bandwidth limit" value={`${user.bandwidth_limit_mb.toLocaleString()} MB`} />
        </div>
        <p className="mt-2 text-[11px] text-muted-foreground">Only a root admin may change role, quota, or status.</p>
      </div>
    );
  }

  return (
    <div>
      <SectionLabel>Configuration</SectionLabel>
      <div className="space-y-4 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
        <div>
          <FieldLabel>Role</FieldLabel>
          {user.role === "root_admin" ? (
            <div className="text-xs text-muted-foreground">
              Root admin role cannot be changed.
            </div>
          ) : (
            <div className="flex gap-1 rounded-xl border border-white/[0.08] bg-white/[0.02] p-1">
              {(["user", "admin"] as Role[]).map((r) => (
                <button
                  key={r}
                  onClick={() => setRole(r)}
                  className={
                    "flex-1 rounded-lg px-3 py-1.5 text-[11px] font-medium uppercase tracking-wider transition " +
                    (role === r ? "bg-white/[0.08] text-foreground" : "text-muted-foreground hover:text-foreground")
                  }
                >
                  {r}
                </button>
              ))}
            </div>
          )}
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Input label="Max connections" value={String(maxConn)} onChange={(v) => setMaxConn(+v || 0)} mono />
          <Input label="Bandwidth (MB)" value={String(bw)} onChange={(v) => setBw(+v || 0)} mono />
        </div>
        <label className="flex cursor-pointer items-center justify-between rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2">
          <span className="text-xs font-medium">Active</span>
          <input
            type="checkbox"
            checked={activeState}
            onChange={(e) => setActiveState(e.target.checked)}
            className="size-4 accent-[var(--accent-violet)]"
          />
        </label>
        <button
          disabled={save.isPending}
          onClick={() => save.mutate()}
          className="w-full rounded-lg bg-[var(--accent-violet)] px-4 py-2 text-xs font-semibold text-[var(--primary-foreground)] hover:brightness-110 disabled:opacity-50"
        >
          Save changes
        </button>
      </div>
    </div>
  );
}

// ── Quota (used / limit / percentage bar + edit, root_admin only) ──
function QuotaSection({ user, isRoot }: { user: User; isRoot: boolean }) {
  const invalidate = useInvalidate();
  const quota = useQuery({
    queryKey: ["user-quota", user.id],
    queryFn: () => api.getUserQuota(user.id),
    enabled: user.id > 0,
  });
  const [limitGb, setLimitGb] = useState("");

  const update = useMutation({
    mutationFn: (bytes: number | null) => api.updateUserQuota(user.id, bytes),
    onSuccess: () => {
      toast.success("Quota updated");
      invalidate(["users"]);
      quota.refetch();
      setLimitGb("");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const q = quota.data;
  const pct = q?.percentage_used ?? null;

  return (
    <div>
      <SectionLabel>Quota</SectionLabel>
      <div className="space-y-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
        {quota.isLoading ? (
          <div className="text-xs text-muted-foreground">Loading quota…</div>
        ) : q ? (
          <>
            <div className="flex items-baseline justify-between text-xs">
              <span className="text-muted-foreground">Used</span>
              <Mono>
                {fmtBytes(q.used_bytes)}
                {q.quota_bytes != null ? ` / ${fmtBytes(q.quota_bytes)}` : " / unlimited"}
              </Mono>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-white/[0.06]">
              <div
                className="h-full rounded-full bg-[var(--accent-violet)] transition-all"
                style={{ width: `${Math.min(100, Math.max(0, pct ?? 0))}%` }}
              />
            </div>
            {pct != null && (
              <div className="text-right text-[11px] text-muted-foreground">{pct.toFixed(1)}% used</div>
            )}
          </>
        ) : (
          <div className="text-xs text-muted-foreground">No quota data.</div>
        )}

        {isRoot && (
          <div className="flex items-end gap-2 border-t border-white/[0.06] pt-3">
            <div className="flex-1">
              <Input
                label="Set limit (GB, blank = unlimited)"
                value={limitGb}
                onChange={setLimitGb}
                placeholder="e.g. 50"
                mono
              />
            </div>
            <button
              disabled={update.isPending}
              onClick={() => {
                const trimmed = limitGb.trim();
                if (trimmed === "") {
                  update.mutate(null);
                  return;
                }
                const gb = Number(trimmed);
                if (!Number.isFinite(gb) || gb < 0) {
                  toast.error("Enter a valid number of GB");
                  return;
                }
                update.mutate(Math.round(gb * 1024 * 1024 * 1024));
              }}
              className="h-10 shrink-0 rounded-xl bg-[var(--accent-violet)] px-4 text-xs font-semibold text-[var(--primary-foreground)] hover:brightness-110 disabled:opacity-50"
            >
              Set
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Recent usage (connections + total bandwidth) ──
function UsageSection({ user }: { user: User }) {
  const usage = useQuery({
    queryKey: ["user-usage", user.id],
    queryFn: () => api.getUserUsage(user.id),
    enabled: user.id > 0,
  });

  return (
    <div>
      <SectionLabel>Recent usage</SectionLabel>
      {usage.isLoading ? (
        <div className="text-xs text-muted-foreground">Loading usage…</div>
      ) : usage.data ? (
        <div className="grid grid-cols-2 gap-3">
          <Stat label="Connections" value={usage.data.connection_count.toLocaleString()} />
          <Stat label="Total bandwidth" value={fmtBytes(usage.data.total_bandwidth)} />
          <Stat label="Sent" value={fmtBytes(usage.data.bytes_sent)} />
          <Stat label="Received" value={fmtBytes(usage.data.bytes_received)} />
        </div>
      ) : (
        <div className="text-xs text-muted-foreground">No usage data.</div>
      )}
    </div>
  );
}

// ── API keys (list / generate with one-time reveal / revoke) ──
function ApiKeysSection({ user }: { user: User }) {
  const invalidate = useInvalidate();
  const { keys, isLoading } = useApiKeys(user.id, user.username);
  const [name, setName] = useState("");
  const [expiresDays, setExpiresDays] = useState("");
  const [revealed, setRevealed] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const create = useMutation({
    mutationFn: () => {
      const days = expiresDays.trim() === "" ? undefined : Number(expiresDays);
      return api.createApiKey(user.id, {
        name: name.trim() || "api-key",
        ...(days != null && Number.isFinite(days) && days > 0 ? { expires_in_days: days } : {}),
      });
    },
    onSuccess: (res) => {
      toast.success("API key created — copy it now");
      setRevealed(res.key);
      setCopied(false);
      setName("");
      setExpiresDays("");
      invalidate(["api-keys"]);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const revoke = useMutation({
    mutationFn: (keyId: string) => api.revokeApiKey(user.id, keyId),
    onSuccess: () => {
      toast.success("API key revoked");
      invalidate(["api-keys"]);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  function keyStatus(k: (typeof keys)[number]): { label: string; variant: "success" | "danger" } {
    if (k.expires_at && new Date(k.expires_at).getTime() < Date.now()) {
      return { label: "Expired", variant: "danger" };
    }
    return { label: "Active", variant: "success" };
  }

  return (
    <div>
      <SectionLabel>API keys</SectionLabel>
      <div className="space-y-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
        {revealed && (
          <div className="rounded-lg border border-[var(--warning)]/30 bg-[var(--warning)]/10 p-3">
            <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--warning)]">
              Copy now — shown only once
            </div>
            <div className="flex items-center gap-2">
              <Mono className="flex-1 break-all text-[11px]">{revealed}</Mono>
              <button
                aria-label="Copy key"
                onClick={() => {
                  navigator.clipboard?.writeText(revealed).then(
                    () => {
                      setCopied(true);
                      toast.success("Copied to clipboard");
                    },
                    () => toast.error("Could not copy"),
                  );
                }}
                className="grid size-7 shrink-0 place-items-center rounded-lg border border-white/10 bg-white/[0.04] text-foreground hover:bg-white/[0.08]"
              >
                {copied ? <Check className="size-3.5 text-[var(--success)]" /> : <Copy className="size-3.5" />}
              </button>
              <button
                aria-label="Dismiss"
                onClick={() => setRevealed(null)}
                className="grid size-7 shrink-0 place-items-center rounded-lg text-muted-foreground hover:bg-white/5 hover:text-foreground"
              >
                <X className="size-3.5" />
              </button>
            </div>
          </div>
        )}

        {isLoading ? (
          <div className="text-xs text-muted-foreground">Loading keys…</div>
        ) : keys.length ? (
          <ul className="space-y-2">
            {keys.map((k) => {
              const st = keyStatus(k);
              return (
                <li
                  key={k.id}
                  className="flex items-center justify-between gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <KeyRound className="size-3.5 shrink-0 text-muted-foreground" />
                      <span className="truncate text-xs font-medium">{k.name}</span>
                      <Pill variant={st.variant}>{st.label}</Pill>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-x-3 text-[10px] text-muted-foreground">
                      <Mono>{k.prefix}…</Mono>
                      <span>used {fmtRelative(k.last_used_at)}</span>
                      <span>{k.expires_at ? `expires ${fmtRelative(k.expires_at)}` : "no expiry"}</span>
                    </div>
                  </div>
                  <button
                    aria-label="Revoke key"
                    title="Revoke key"
                    disabled={revoke.isPending}
                    onClick={() => revoke.mutate(k.id)}
                    className="grid size-7 shrink-0 place-items-center rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/10 text-[var(--danger)] hover:bg-[var(--danger)]/15 disabled:opacity-50"
                  >
                    <Trash2 className="size-3.5" />
                  </button>
                </li>
              );
            })}
          </ul>
        ) : (
          <div className="text-xs text-muted-foreground">No API keys.</div>
        )}

        <div className="flex items-end gap-2 border-t border-white/[0.06] pt-3">
          <div className="flex-1">
            <Input label="Key name" value={name} onChange={setName} placeholder="ci-deploy" mono />
          </div>
          <div className="w-28">
            <Input label="Expires (days)" value={expiresDays} onChange={setExpiresDays} placeholder="∞" mono />
          </div>
          <button
            disabled={create.isPending}
            onClick={() => create.mutate()}
            className="flex h-10 shrink-0 items-center gap-1.5 rounded-xl bg-[var(--accent-violet)] px-3 text-xs font-semibold text-[var(--primary-foreground)] hover:brightness-110 disabled:opacity-50"
          >
            <Plus className="size-3.5" /> Generate
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Sessions (list + force logout) ──
function SessionsSection({ user }: { user: User }) {
  const invalidate = useInvalidate();
  const sessions = useQuery({
    queryKey: ["user-sessions", user.id],
    queryFn: () => api.getUserSessions(user.id),
    enabled: user.id > 0,
  });

  const logout = useMutation({
    mutationFn: () => api.deleteUserSessions(user.id),
    onSuccess: () => {
      toast.success("All sessions terminated");
      sessions.refetch();
      invalidate(["users"]);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const list = sessions.data ?? [];

  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <SectionLabel className="mb-0">Sessions</SectionLabel>
        {list.length > 0 && (
          <button
            disabled={logout.isPending}
            onClick={() => logout.mutate()}
            className="flex items-center gap-1.5 rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/10 px-2.5 py-1 text-[11px] font-medium text-[var(--danger)] hover:bg-[var(--danger)]/15 disabled:opacity-50"
          >
            <LogOut className="size-3" /> Force logout
          </button>
        )}
      </div>
      {sessions.isLoading ? (
        <div className="text-xs text-muted-foreground">Loading sessions…</div>
      ) : list.length ? (
        <ul className="space-y-2">
          {list.map((s) => (
            <li
              key={s.id}
              className="rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2 text-[11px]"
            >
              <div className="flex items-center justify-between">
                <Mono className="text-xs">{s.ip_address ?? "unknown IP"}</Mono>
                <span className="text-muted-foreground">
                  {fmtRelative(new Date(s.created_at * 1000).toISOString())}
                </span>
              </div>
              {s.user_agent && (
                <div className="mt-0.5 truncate text-[10px] text-muted-foreground">{s.user_agent}</div>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <div className="text-xs text-muted-foreground">No active sessions.</div>
      )}
    </div>
  );
}

function SectionLabel({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div
      className={
        "mb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground " + (className ?? "")
      }
    >
      {children}
    </div>
  );
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
      {children}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
      <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
      <Mono className="mt-1 text-sm">{value}</Mono>
    </div>
  );
}

function CreateUserModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  // root_admin is intentionally NOT offered — it cannot be created via the API.
  const [role, setRole] = useState<Role>("user");
  const [maxConn, setMaxConn] = useState(10);
  const [bw, setBw] = useState(1000);

  const invalidate = useInvalidate();
  const create = useMutation({
    mutationFn: () =>
      api.createUser({
        username: username.trim(),
        password,
        role,
        max_connections: maxConn,
        bandwidth_limit_mb: bw,
      }),
    onSuccess: () => {
      toast.success("User created");
      invalidate(["users"]);
      setUsername("");
      setPassword("");
      setRole("user");
      onClose();
    },
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50 grid place-items-center bg-black/55 px-4 backdrop-blur-md"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
        >
          <motion.div
            initial={{ opacity: 0, y: 10, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 6, scale: 0.98 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-md overflow-hidden rounded-2xl border border-white/10 bg-[var(--surface-2)] shadow-2xl"
          >
            <div className="flex items-center justify-between border-b border-white/10 px-5 py-4">
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                  Provision
                </div>
                <div className="text-base font-semibold">New user</div>
              </div>
              <button onClick={onClose} className="grid size-8 place-items-center rounded-lg text-muted-foreground hover:bg-white/5 hover:text-foreground">
                <X className="size-4" />
              </button>
            </div>
            <div className="space-y-4 px-5 py-5">
              <Input label="Username" value={username} onChange={setUsername} placeholder="ada.lovelace" mono />
              <Input label="Password" value={password} onChange={setPassword} placeholder="••••••••" type="password" />
              <div>
                <FieldLabel>Role</FieldLabel>
                <div className="flex gap-1 rounded-xl border border-white/[0.08] bg-white/[0.02] p-1">
                  {(["user", "admin"] as Role[]).map((r) => (
                    <button
                      key={r}
                      onClick={() => setRole(r)}
                      className={
                        "flex-1 rounded-lg px-3 py-1.5 text-[11px] font-medium uppercase tracking-wider transition " +
                        (role === r ? "bg-white/[0.08] text-foreground" : "text-muted-foreground hover:text-foreground")
                      }
                    >
                      {r}
                    </button>
                  ))}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Input label="Max connections" value={String(maxConn)} onChange={(v) => setMaxConn(+v || 0)} mono />
                <Input label="Bandwidth (MB)" value={String(bw)} onChange={(v) => setBw(+v || 0)} mono />
              </div>
            </div>
            <div className="flex items-center justify-end gap-2 border-t border-white/10 bg-white/[0.02] px-5 py-3">
              <button onClick={onClose} className="rounded-lg px-3 py-1.5 text-xs text-muted-foreground hover:bg-white/5 hover:text-foreground">
                Cancel
              </button>
              <button
                disabled={!username.trim() || !password || create.isPending}
                onClick={() => create.mutate()}
                className="rounded-lg bg-[var(--accent-violet)] px-4 py-1.5 text-xs font-semibold text-[var(--primary-foreground)] disabled:opacity-50"
              >
                Create user
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function Input({
  label,
  value,
  onChange,
  placeholder,
  mono,
  type,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  mono?: boolean;
  type?: string;
}) {
  return (
    <label className="block">
      <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={
          "h-10 w-full rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 text-sm outline-none transition focus:border-[var(--accent-violet)]/50 focus:bg-white/[0.05] " +
          (mono ? "font-mono-tight" : "")
        }
      />
    </label>
  );
}
