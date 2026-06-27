import { createFileRoute } from "@tanstack/react-router";
import { AnimatePresence, motion } from "framer-motion";
import { Plus, Search, Trash2, X } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Panel } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { Pill } from "@/components/app/badge";
import { StatusDot } from "@/components/app/status-dot";
import { Mono } from "@/components/app/mono";
import { DetailDrawer } from "@/components/app/detail-drawer";
import { api, useInvalidate, useMutation, useUsers } from "@/lib/queries";
import { fmtRelative } from "@/lib/format";
import type { Role, User } from "@/types/crabby";

export const Route = createFileRoute("/_authenticated/users")({
  head: () => ({ meta: [{ title: "Users · Crabby Proxy" }] }),
  component: UsersPage,
});

const ROLES: ("ALL" | Role)[] = ["ALL", "root_admin", "admin", "user"];

function UsersPage() {
  const { users, isLoading } = useUsers();
  const [q, setQ] = useState("");
  const [role, setRole] = useState<(typeof ROLES)[number]>("ALL");
  const [openNew, setOpenNew] = useState(false);
  const [active, setActive] = useState<User | null>(null);

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
        <div className="grid grid-cols-[40px_1.4fr_120px_110px_100px_110px_110px] gap-3 border-b border-white/[0.06] px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          <span>#</span>
          <span>Username</span>
          <span>Role</span>
          <span>Status</span>
          <span className="text-right">Max Conn.</span>
          <span className="text-right">BW Limit</span>
          <span className="text-right">Last login</span>
        </div>
        <ul className="divide-y divide-white/[0.04]">
          {isLoading && !filtered.length && (
            <li className="px-5 py-8 text-center text-sm text-muted-foreground">Loading users…</li>
          )}
          {!isLoading && !filtered.length && (
            <li className="px-5 py-8 text-center text-sm text-muted-foreground">No users found.</li>
          )}
          {filtered.map((u, i) => (
            <motion.li
              key={u.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.03 }}
              onClick={() => setActive(u)}
              className="grid cursor-pointer grid-cols-[40px_1.4fr_120px_110px_100px_110px_110px] items-center gap-3 px-5 py-3 text-sm transition hover:bg-white/[0.03]"
            >
              <Mono className="text-[11px] text-muted-foreground">{u.id}</Mono>
              <div className="flex items-center gap-3">
                <div className="grid size-7 place-items-center rounded-md bg-white/5 text-[10px] font-semibold uppercase">
                  {u.username.slice(0, 2)}
                </div>
                <span className="font-medium">{u.username}</span>
              </div>
              <Pill variant={u.role === "root_admin" ? "danger" : u.role === "admin" ? "violet" : "outline"}>
                {u.role}
              </Pill>
              <span className="flex items-center gap-1.5 text-xs">
                <StatusDot tone={u.active ? "success" : "danger"} pulse={u.active} />
                {u.active ? "Active" : "Disabled"}
              </span>
              <Mono className="text-right text-xs">{u.max_connections.toLocaleString()}</Mono>
              <Mono className="text-right text-xs">{u.bandwidth_limit_mb.toLocaleString()} MB</Mono>
              <span className="text-right text-xs text-muted-foreground">{fmtRelative(u.last_login_at)}</span>
            </motion.li>
          ))}
        </ul>
      </Panel>

      <UserDetail user={active} onClose={() => setActive(null)} />

      <CreateUserModal open={openNew} onClose={() => setOpenNew(false)} />
    </div>
  );
}

function UserDetail({ user, onClose }: { user: User | null; onClose: () => void }) {
  const invalidate = useInvalidate();
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

  return (
    <DetailDrawer
      open={!!user}
      onClose={onClose}
      eyebrow={user ? `User #${user.id}` : ""}
      title={user?.username ?? ""}
      footer={
        user && (
          <div className="flex items-center justify-between">
            {user.active ? (
              <button
                disabled={deactivate.isPending}
                onClick={() => deactivate.mutate(user.id)}
                className="flex items-center gap-1.5 rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/10 px-3 py-1.5 text-xs font-medium text-[var(--danger)] hover:bg-[var(--danger)]/15 disabled:opacity-50"
              >
                <Trash2 className="size-3.5" /> Deactivate
              </button>
            ) : (
              <button
                disabled={reactivate.isPending}
                onClick={() => reactivate.mutate(user.id)}
                className="flex items-center gap-1.5 rounded-lg border border-[var(--success)]/30 bg-[var(--success)]/10 px-3 py-1.5 text-xs font-medium text-[var(--success)] hover:bg-[var(--success)]/15 disabled:opacity-50"
              >
                <StatusDot tone="success" /> Reactivate
              </button>
            )}
            <button className="rounded-lg bg-[var(--accent-violet)] px-4 py-1.5 text-xs font-semibold text-[var(--primary-foreground)] hover:brightness-110">
              Edit user
            </button>
          </div>
        )
      }
    >
      {user && (
        <div className="space-y-5">
          <div className="flex gap-2">
            <Pill variant={user.role === "root_admin" ? "danger" : user.role === "admin" ? "violet" : "outline"}>
              {user.role}
            </Pill>
            <Pill variant={user.active ? "success" : "danger"}>
              <StatusDot tone={user.active ? "success" : "danger"} /> {user.active ? "Active" : "Disabled"}
            </Pill>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Stat label="Max connections" value={user.max_connections} />
            <Stat label="Bandwidth limit" value={`${user.bandwidth_limit_mb.toLocaleString()} MB`} />
            <Stat label="Used (24h)" value={`${user.bandwidth_used_mb.toLocaleString()} MB`} />
            <Stat label="Last login" value={fmtRelative(user.last_login_at)} />
          </div>
          <div>
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
              Groups
            </div>
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
                <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Role</div>
                <div className="flex gap-1 rounded-xl border border-white/[0.08] bg-white/[0.02] p-1">
                  {(["user", "admin", "root_admin"] as Role[]).map((r) => (
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