// Users directory — server-side pagination, search, role filter, create
// dialog (root_admin). ?new=1 from the command palette opens the dialog.
import { Plus, UsersRound } from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { createUser } from "@/api/endpoints";
import type { Role } from "@/api/types";
import { formatRelative } from "@/lib/format";
import { useInvalidate, useSession, useUsers, keys } from "@/hooks/queries";
import { Modal } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Panel } from "@/components/ui/card";
import { Field, Input, Select } from "@/components/ui/input";
import { Mono, Pagination, SearchInput } from "@/components/ui/misc";
import { RoleBadge, StatusPill } from "@/components/ui/badge";
import { TableShell, THead, Th, Td, TRow, TableSkeleton } from "@/components/ui/table";
import { EmptyState, ErrorState } from "@/components/ui/states";

const PAGE_SIZE = 50;

export function UsersPage() {
  const navigate = useNavigate();
  const session = useSession();
  const [params, setParams] = useSearchParams();
  const [offset, setOffset] = useState(0);
  const [query, setQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState<"all" | Role>("all");
  const users = useUsers(PAGE_SIZE, offset);
  const isRoot = session?.role === "root_admin";
  const createOpen = params.get("new") === "1";
  const setCreateOpen = (open: boolean) => {
    const next = new URLSearchParams(params);
    if (open) next.set("new", "1");
    else next.delete("new");
    setParams(next, { replace: true });
  };

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (users.data?.items ?? []).filter((u) => {
      if (roleFilter !== "all" && u.role !== roleFilter) return false;
      if (q && !u.username.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [users.data, query, roleFilter]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-[13px] text-fg-muted">
          Accounts, roles and per-user limits. Open a user for quotas, keys and usage.
        </p>
        <div className="ml-auto flex w-full flex-wrap items-center gap-2 sm:w-auto">
          <SearchInput
            placeholder="Search username…"
            aria-label="Search users"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full sm:w-56"
          />
          <Select
            aria-label="Filter by role"
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value as typeof roleFilter)}
            className="w-36"
          >
            <option value="all">All roles</option>
            <option value="root_admin">Root admin</option>
            <option value="admin">Admin</option>
            <option value="user">User</option>
          </Select>
          {isRoot && (
            <Button variant="primary" onClick={() => setCreateOpen(true)}>
              <Plus className="size-3.5" /> New user
            </Button>
          )}
        </div>
      </div>

      <Panel>
        {users.isError ? (
          <ErrorState
            title="Couldn't load users"
            detail={(users.error as Error)?.message}
            onRetry={() => users.refetch()}
            className="m-4 border-0"
          />
        ) : (
          <>
            <TableShell>
              <THead>
                <Th>User</Th>
                <Th>Role</Th>
                <Th>Status</Th>
                <Th className="text-right">Max conns</Th>
                <Th className="text-right">Bandwidth limit</Th>
                <Th>Last login</Th>
                <Th>Created</Th>
              </THead>
              {users.isLoading ? (
                <TableSkeleton cols={7} />
              ) : (
                <tbody>
                  {rows.map((u) => (
                    <TRow key={u.id} onActivate={() => navigate(`/users/${u.id}`)}>
                      <Td>
                        <div className="flex items-center gap-2.5">
                          <span className="grid size-6 place-items-center rounded-full bg-surface-3 font-mono text-[10px] font-semibold uppercase text-fg-muted">
                            {u.username.slice(0, 2)}
                          </span>
                          <span className="font-medium">{u.username}</span>
                          {u.id === session?.userId && (
                            <span className="rounded bg-accent-soft px-1.5 text-[10.5px] font-medium text-accent">
                              you
                            </span>
                          )}
                        </div>
                      </Td>
                      <Td>
                        <RoleBadge role={u.role} />
                      </Td>
                      <Td>
                        <StatusPill
                          tone={u.is_active ? "success" : "neutral"}
                          label={u.is_active ? "Active" : "Disabled"}
                        />
                      </Td>
                      <Td className="text-right">
                        <Mono>{u.max_connections}</Mono>
                      </Td>
                      <Td className="text-right">
                        <Mono>{u.bandwidth_limit_mb > 0 ? `${u.bandwidth_limit_mb} MB` : "∞"}</Mono>
                      </Td>
                      <Td className="text-fg-faint">{formatRelative(u.last_login_at)}</Td>
                      <Td className="text-fg-faint">{formatRelative(u.created_at)}</Td>
                    </TRow>
                  ))}
                </tbody>
              )}
            </TableShell>
            {!users.isLoading && rows.length === 0 && (
              <EmptyState
                icon={UsersRound}
                title={query || roleFilter !== "all" ? "No matching users" : "No users yet"}
                description={
                  query || roleFilter !== "all"
                    ? "Adjust the search or role filter."
                    : "Create the first account to hand out proxy access."
                }
                action={
                  isRoot && !query && roleFilter === "all" ? (
                    <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}>
                      <Plus className="size-3.5" /> Create user
                    </Button>
                  ) : undefined
                }
                className="m-4 border-0"
              />
            )}
            {users.data && (
              <Pagination
                offset={offset}
                limit={PAGE_SIZE}
                total={users.data.total}
                onOffsetChange={setOffset}
              />
            )}
          </>
        )}
      </Panel>

      <CreateUserDialog open={createOpen} onOpenChange={setCreateOpen} />
    </div>
  );
}

function CreateUserDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const invalidate = useInvalidate();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("user");
  const [maxConns, setMaxConns] = useState("10");
  const [bwLimit, setBwLimit] = useState("0");

  // Mirror backend rules so errors surface before the request.
  const usernameError =
    username && !/^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(username)
      ? "Letters, digits, _ and -, starting with a letter or digit"
      : username.length > 64
        ? "64 characters max"
        : null;
  const passwordError =
    password && (password.length < 8 || !/[a-zA-Z]/.test(password) || !/\d/.test(password))
      ? "8+ characters with at least one letter and one digit"
      : null;

  const create = useMutation({
    mutationFn: () =>
      createUser({
        username: username.trim(),
        password,
        role,
        max_connections: Number(maxConns) || undefined,
        bandwidth_limit_mb: Number(bwLimit) || undefined,
      }),
    onSuccess: (u) => {
      toast.success(`User ${u.username} created`);
      invalidate(keys.usersAll);
      onOpenChange(false);
      setUsername("");
      setPassword("");
      navigate(`/users/${u.id}`);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!usernameError && !passwordError && username && password) create.mutate();
  };

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Create user"
      description="Only root admins can create accounts."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={create.isPending}
            disabled={!username || !password || !!usernameError || !!passwordError}
            onClick={() => create.mutate()}
          >
            Create user
          </Button>
        </>
      }
    >
      <form onSubmit={submit} className="space-y-4">
        <Field label="Username" error={usernameError}>
          {(id) => (
            <Input
              id={id}
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="alice"
              autoComplete="off"
            />
          )}
        </Field>
        <Field label="Password" error={passwordError} hint="Min 8 chars, one letter + one digit">
          {(id) => (
            <Input
              id={id}
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
            />
          )}
        </Field>
        <div className="grid grid-cols-3 gap-3">
          <Field label="Role">
            {(id) => (
              <Select id={id} value={role} onChange={(e) => setRole(e.target.value as Role)}>
                <option value="user">User</option>
                <option value="admin">Admin</option>
              </Select>
            )}
          </Field>
          <Field label="Max conns">
            {(id) => (
              <Input
                id={id}
                type="number"
                min={1}
                value={maxConns}
                onChange={(e) => setMaxConns(e.target.value)}
              />
            )}
          </Field>
          <Field label="BW limit (MB)" hint="0 = unlimited">
            {(id) => (
              <Input
                id={id}
                type="number"
                min={0}
                value={bwLimit}
                onChange={(e) => setBwLimit(e.target.value)}
              />
            )}
          </Field>
        </div>
        {/* Allow Enter-to-submit */}
        <button type="submit" className="hidden" aria-hidden />
      </form>
    </Modal>
  );
}
