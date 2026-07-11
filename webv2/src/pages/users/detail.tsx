// User detail — deep-linkable /users/:id (the old UI only had an
// ephemeral drawer). Self-or-admin: regular users can open their own page.
// Edit (root_admin), deactivate/reactivate, quota, keys, usage, approvals,
// groups (admin-only endpoint).
import { ArrowLeft, Pencil, ShieldOff, ShieldCheck as ShieldOn } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { deleteUser, updateUser } from "@/api/endpoints";
import type { Role } from "@/api/types";
import { formatDateTime, formatRelative } from "@/lib/format";
import {
  keys,
  useInvalidate,
  useIsAdmin,
  useSession,
  useUser,
  useUserGroups,
} from "@/hooks/queries";
import { Stagger, StaggerItem } from "@/components/motion";
import { ConfirmDialog, Modal } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Panel, PanelHeader } from "@/components/ui/card";
import { Field, Input, Select } from "@/components/ui/input";
import { Mono } from "@/components/ui/misc";
import { Pill, RoleBadge, StatusPill } from "@/components/ui/badge";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";
import {
  ApiKeysSection,
  QuotaSection,
  RecentUsageSection,
  UsageStatsSection,
  UserApprovalsSection,
} from "./sections";

export function UserDetailPage() {
  const params = useParams<{ id: string }>();
  const id = Number(params.id) || 0;
  const session = useSession();
  const isAdmin = useIsAdmin();
  const isRoot = session?.role === "root_admin";
  const isSelf = session?.userId === id;

  const user = useUser(id, isAdmin || isSelf);
  const groups = useUserGroups(id, isAdmin); // admin-only endpoint
  const invalidate = useInvalidate();
  const [editOpen, setEditOpen] = useState(false);
  const [confirmToggle, setConfirmToggle] = useState(false);

  const toggleActive = useMutation({
    mutationFn: async () => {
      if (user.data!.is_active) {
        await deleteUser(id); // backend delete = deactivate + revoke keys/sessions
      } else {
        await updateUser(id, { is_active: true });
      }
    },
    onSuccess: () => {
      toast.success(user.data!.is_active ? "User deactivated" : "User reactivated");
      setConfirmToggle(false);
      invalidate(keys.usersAll, keys.user(id));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  if (!isAdmin && !isSelf) {
    return <ErrorState title="You don't have access to this user" />;
  }
  if (user.isError) {
    return (
      <ErrorState
        title="Couldn't load user"
        detail={(user.error as Error)?.message}
        onRetry={() => user.refetch()}
      />
    );
  }

  const u = user.data;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3">
        {isAdmin && (
          <Link
            to="/users"
            className="grid size-8 place-items-center rounded-md text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg"
            aria-label="Back to users"
          >
            <ArrowLeft className="size-4" />
          </Link>
        )}
        {user.isLoading ? (
          <Skeleton className="h-10 w-64" />
        ) : u ? (
          <>
            <div className="grid size-10 place-items-center rounded-full bg-surface-3 font-mono text-[13px] font-semibold uppercase text-fg-muted">
              {u.username.slice(0, 2)}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-[17px] font-semibold tracking-tight">{u.username}</h2>
                <RoleBadge role={u.role} />
                <StatusPill
                  tone={u.is_active ? "success" : "neutral"}
                  label={u.is_active ? "Active" : "Disabled"}
                />
              </div>
              <div className="mt-0.5 text-[12px] text-fg-faint">
                <Mono>#{u.id}</Mono> · created {formatDateTime(u.created_at)} · last login{" "}
                {formatRelative(u.last_login_at)}
              </div>
            </div>
            <div className="ml-auto flex gap-2">
              {(isRoot || isSelf) && (
                <Button variant="outline" size="sm" onClick={() => setEditOpen(true)}>
                  <Pencil className="size-3.5" /> Edit
                </Button>
              )}
              {isRoot && !isSelf && (
                <Button
                  variant={u.is_active ? "danger" : "primary"}
                  size="sm"
                  onClick={() => setConfirmToggle(true)}
                >
                  {u.is_active ? (
                    <>
                      <ShieldOff className="size-3.5" /> Deactivate
                    </>
                  ) : (
                    <>
                      <ShieldOn className="size-3.5" /> Reactivate
                    </>
                  )}
                </Button>
              )}
            </div>
          </>
        ) : null}
      </div>

      {u && (
        <Stagger className="space-y-4">
          {/* Limits + quota + usage */}
          <StaggerItem className="grid gap-4 lg:grid-cols-3">
            <Panel>
              <PanelHeader eyebrow="profile" title="Limits" />
              <dl className="space-y-2.5 px-4 pb-4 text-[13px]">
                <div className="flex justify-between">
                  <dt className="text-fg-faint">Max concurrent connections</dt>
                  <dd>
                    <Mono>{u.max_connections}</Mono>
                  </dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-fg-faint">Bandwidth limit</dt>
                  <dd>
                    <Mono>{u.bandwidth_limit_mb > 0 ? `${u.bandwidth_limit_mb} MB` : "unlimited"}</Mono>
                  </dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-fg-faint">Role</dt>
                  <dd>
                    <RoleBadge role={u.role} />
                  </dd>
                </div>
                {isAdmin && (
                  <div className="flex items-start justify-between gap-3">
                    <dt className="text-fg-faint">Groups</dt>
                    <dd className="flex flex-wrap justify-end gap-1">
                      {groups.isLoading ? (
                        <Skeleton className="h-5 w-20" />
                      ) : (groups.data?.length ?? 0) === 0 ? (
                        <span className="text-fg-faint">None</span>
                      ) : (
                        groups.data!.map((g) => (
                          <Link key={g.id} to={`/groups/${g.id}`}>
                            <Pill tone="accent" className="hover:bg-accent/20">
                              {g.name}
                            </Pill>
                          </Link>
                        ))
                      )}
                    </dd>
                  </div>
                )}
              </dl>
            </Panel>
            <QuotaSection userId={id} canEdit={isAdmin} />
            <UsageStatsSection userId={id} />
          </StaggerItem>

          <StaggerItem>
            <ApiKeysSection userId={id} username={u.username} />
          </StaggerItem>

          <StaggerItem className="grid gap-4 lg:grid-cols-[2fr_1fr]">
            <RecentUsageSection userId={id} />
            <UserApprovalsSection userId={id} />
          </StaggerItem>
        </Stagger>
      )}

      {user.isLoading && (
        <div className="grid gap-4 lg:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-44" />
          ))}
        </div>
      )}
      {!user.isLoading && !u && <EmptyState title="User not found" />}

      {/* Edit dialog */}
      {u && (
        <EditUserDialog
          open={editOpen}
          onOpenChange={setEditOpen}
          userId={id}
          current={{ role: u.role, max: u.max_connections, bw: u.bandwidth_limit_mb }}
          isRoot={isRoot}
          isSelf={isSelf}
          onSaved={() => invalidate(keys.usersAll, keys.user(id))}
        />
      )}

      <ConfirmDialog
        open={confirmToggle}
        onOpenChange={setConfirmToggle}
        title={u?.is_active ? "Deactivate user?" : "Reactivate user?"}
        description={
          u?.is_active
            ? "Sign-ins and proxy auth stop immediately; API keys are revoked. This is reversible."
            : "The account can sign in and proxy again."
        }
        confirmLabel={u?.is_active ? "Deactivate" : "Reactivate"}
        tone={u?.is_active ? "danger" : "primary"}
        loading={toggleActive.isPending}
        onConfirm={() => toggleActive.mutate()}
      />
    </div>
  );
}

function EditUserDialog({
  open,
  onOpenChange,
  userId,
  current,
  isRoot,
  isSelf,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  userId: number;
  current: { role: Role; max: number; bw: number };
  isRoot: boolean;
  isSelf: boolean;
  onSaved: () => void;
}) {
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>(current.role);
  const [max, setMax] = useState(String(current.max));
  const [bw, setBw] = useState(String(current.bw));

  const passwordError =
    password && (password.length < 8 || !/[a-zA-Z]/.test(password) || !/\d/.test(password))
      ? "8+ characters with at least one letter and one digit"
      : null;

  const save = useMutation({
    mutationFn: () => {
      const body: Parameters<typeof updateUser>[1] = {};
      if (password) body.password = password;
      if (isRoot) {
        if (role !== current.role) body.role = role;
        if (Number(max) !== current.max) body.max_connections = Number(max);
        if (Number(bw) !== current.bw) body.bandwidth_limit_mb = Number(bw);
      }
      return updateUser(userId, body);
    },
    onSuccess: () => {
      toast.success("User updated");
      onOpenChange(false);
      setPassword("");
      onSaved();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Edit user"
      description={
        isRoot
          ? "Root admins can change role, limits and password."
          : "You can change your password."
      }
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={save.isPending}
            disabled={!!passwordError}
            onClick={() => save.mutate()}
          >
            Save changes
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field
          label={isSelf ? "New password" : "Reset password"}
          hint="Leave empty to keep the current password"
          error={passwordError}
        >
          {(id) => (
            <Input
              id={id}
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          )}
        </Field>
        {isRoot && (
          <div className="grid grid-cols-3 gap-3">
            <Field label="Role">
              {(id) => (
                <Select
                  id={id}
                  value={role}
                  onChange={(e) => setRole(e.target.value as Role)}
                  disabled={current.role === "root_admin"}
                >
                  {current.role === "root_admin" && <option value="root_admin">Root admin</option>}
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </Select>
              )}
            </Field>
            <Field label="Max conns">
              {(id) => (
                <Input id={id} type="number" min={1} value={max} onChange={(e) => setMax(e.target.value)} />
              )}
            </Field>
            <Field label="BW limit (MB)">
              {(id) => (
                <Input id={id} type="number" min={0} value={bw} onChange={(e) => setBw(e.target.value)} />
              )}
            </Field>
          </div>
        )}
      </div>
    </Modal>
  );
}
