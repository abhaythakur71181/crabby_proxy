// Group detail — policy panel + member management with proper dialogs
// (the old UI used window.confirm()).
import { ArrowLeft, Plus, Trash2, UserMinus } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { addGroupMember, deleteGroup, removeGroupMember } from "@/api/endpoints";
import { formatDateTime, formatRelative } from "@/lib/format";
import {
  keys,
  useGroup,
  useGroupMembers,
  useInvalidate,
  useUsers,
} from "@/hooks/queries";
import { ConfirmDialog, Modal } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Panel, PanelHeader } from "@/components/ui/card";
import { Field, Select } from "@/components/ui/input";
import { Mono } from "@/components/ui/misc";
import { Pill, RoleBadge } from "@/components/ui/badge";
import { TableShell, THead, Th, Td, TRow, TableSkeleton } from "@/components/ui/table";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";

export function GroupDetailPage() {
  const params = useParams<{ id: string }>();
  const id = Number(params.id) || 0;
  const navigate = useNavigate();
  const invalidate = useInvalidate();
  const group = useGroup(id);
  const members = useGroupMembers(id);
  const users = useUsers(200, 0);
  const [addOpen, setAddOpen] = useState(false);
  const [removeTarget, setRemoveTarget] = useState<{ id: number; name: string } | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState("");

  const nonMembers = useMemo(() => {
    const memberIds = new Set((members.data?.members ?? []).map((m) => m.user_id));
    return (users.data?.items ?? []).filter((u) => !memberIds.has(u.id));
  }, [users.data, members.data]);

  const add = useMutation({
    mutationFn: (userId: number) => addGroupMember(id, userId),
    onSuccess: () => {
      toast.success("Member added");
      setAddOpen(false);
      setSelectedUser("");
      invalidate(keys.group(id), keys.groups);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const remove = useMutation({
    mutationFn: (userId: number) => removeGroupMember(id, userId),
    onSuccess: () => {
      toast.success("Member removed");
      setRemoveTarget(null);
      invalidate(keys.group(id), keys.groups);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const destroy = useMutation({
    mutationFn: () => deleteGroup(id),
    onSuccess: () => {
      toast.success("Group deleted");
      invalidate(keys.groups);
      navigate("/groups");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  if (group.isError) {
    return (
      <ErrorState
        title="Couldn't load group"
        detail={(group.error as Error)?.message}
        onRetry={() => group.refetch()}
      />
    );
  }

  const g = group.data;
  const policies: { label: string; value: string }[] = g
    ? [
        g.max_connections != null && { label: "Max connections", value: String(g.max_connections) },
        g.bandwidth_limit_mb != null && { label: "Bandwidth limit", value: `${g.bandwidth_limit_mb} MB` },
        g.rate_limit_rps != null && { label: "Rate limit", value: `${g.rate_limit_rps} rps` },
        g.rate_limit_burst != null && { label: "Burst", value: String(g.rate_limit_burst) },
        g.allowed_protocols && { label: "Allowed protocols", value: g.allowed_protocols },
        g.allowed_targets && { label: "Allowed targets", value: g.allowed_targets },
        g.blocked_targets && { label: "Blocked targets", value: g.blocked_targets },
        g.access_schedule && { label: "Access schedule", value: g.access_schedule },
      ].filter((x): x is { label: string; value: string } => Boolean(x))
    : [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Link
          to="/groups"
          className="grid size-8 place-items-center rounded-md text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg"
          aria-label="Back to groups"
        >
          <ArrowLeft className="size-4" />
        </Link>
        {group.isLoading ? (
          <Skeleton className="h-8 w-56" />
        ) : g ? (
          <>
            <div>
              <h2 className="text-[17px] font-semibold tracking-tight">{g.name}</h2>
              <div className="text-[12px] text-fg-faint">
                created {formatDateTime(g.created_at)} · updated {formatRelative(g.updated_at)}
              </div>
            </div>
            <div className="ml-auto flex gap-2">
              <Button variant="primary" size="sm" onClick={() => setAddOpen(true)}>
                <Plus className="size-3.5" /> Add member
              </Button>
              <Button variant="danger" size="sm" onClick={() => setDeleteOpen(true)}>
                <Trash2 className="size-3.5" /> Delete group
              </Button>
            </div>
          </>
        ) : null}
      </div>

      {g?.description && <p className="text-[13px] text-fg-muted">{g.description}</p>}

      <div className="grid gap-4 lg:grid-cols-[1fr_2fr]">
        {/* Policy */}
        <Panel className="h-fit">
          <PanelHeader eyebrow="applies to all members" title="Policy" />
          <div className="px-4 pb-4">
            {group.isLoading ? (
              <Skeleton className="h-24" />
            ) : policies.length === 0 ? (
              <EmptyState
                title="No policy overrides"
                description="Members use their individual limits."
                className="border-0 py-6"
              />
            ) : (
              <dl className="space-y-2.5 text-[13px]">
                {policies.map((p) => (
                  <div key={p.label} className="flex items-start justify-between gap-3">
                    <dt className="text-fg-faint">{p.label}</dt>
                    <dd className="text-right">
                      <Mono className="break-all">{p.value}</Mono>
                    </dd>
                  </div>
                ))}
              </dl>
            )}
          </div>
        </Panel>

        {/* Members */}
        <Panel>
          <PanelHeader
            eyebrow={`${members.data?.total ?? 0} total`}
            title="Members"
          />
          {members.isError ? (
            <ErrorState className="mx-4 mb-4 border-0" onRetry={() => members.refetch()} />
          ) : (
            <TableShell>
              <THead>
                <Th>User</Th>
                <Th>Role</Th>
                <Th>Joined</Th>
                <Th aria-label="Actions" />
              </THead>
              {members.isLoading ? (
                <TableSkeleton cols={4} rows={4} />
              ) : (
                <tbody>
                  {(members.data?.members ?? []).map((m) => (
                    <TRow key={m.user_id} onActivate={() => navigate(`/users/${m.user_id}`)}>
                      <Td className="font-medium">{m.username}</Td>
                      <Td>
                        <RoleBadge role={m.role} />
                      </Td>
                      <Td className="text-fg-faint">{formatRelative(m.joined_at)}</Td>
                      <Td className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          aria-label={`Remove ${m.username} from group`}
                          className="text-danger hover:bg-danger-soft"
                          onClick={(e) => {
                            e.stopPropagation();
                            setRemoveTarget({ id: m.user_id, name: m.username });
                          }}
                        >
                          <UserMinus className="size-3.5" />
                        </Button>
                      </Td>
                    </TRow>
                  ))}
                </tbody>
              )}
            </TableShell>
          )}
          {!members.isLoading && !members.isError && (members.data?.members.length ?? 0) === 0 && (
            <EmptyState
              title="No members yet"
              description="Add users so this policy applies to them."
              action={
                <Button variant="primary" size="sm" onClick={() => setAddOpen(true)}>
                  <Plus className="size-3.5" /> Add member
                </Button>
              }
              className="m-4 border-0"
            />
          )}
        </Panel>
      </div>

      {/* Add member */}
      <Modal
        open={addOpen}
        onOpenChange={setAddOpen}
        title="Add member"
        description={`Users inherit ${g?.name ?? "this group"}'s policy.`}
        footer={
          <>
            <Button variant="ghost" onClick={() => setAddOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              loading={add.isPending}
              disabled={!selectedUser}
              onClick={() => add.mutate(Number(selectedUser))}
            >
              Add member
            </Button>
          </>
        }
      >
        <Field label="User">
          {(fid) => (
            <Select id={fid} value={selectedUser} onChange={(e) => setSelectedUser(e.target.value)}>
              <option value="" disabled>
                {nonMembers.length === 0 ? "Everyone is already a member" : "Select a user…"}
              </option>
              {nonMembers.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.username} ({u.role})
                </option>
              ))}
            </Select>
          )}
        </Field>
      </Modal>

      <ConfirmDialog
        open={removeTarget != null}
        onOpenChange={(o) => !o && setRemoveTarget(null)}
        title={`Remove ${removeTarget?.name}?`}
        description="They keep their account but lose this group's policy."
        confirmLabel="Remove"
        loading={remove.isPending}
        onConfirm={() => removeTarget && remove.mutate(removeTarget.id)}
      />

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={`Delete group “${g?.name}”?`}
        description="Membership records are removed. User accounts are untouched."
        confirmLabel="Delete group"
        loading={destroy.isPending}
        onConfirm={() => destroy.mutate()}
      >
        {(members.data?.total ?? 0) > 0 && (
          <Pill tone="warning">{members.data!.total} members will be detached</Pill>
        )}
      </ConfirmDialog>
    </div>
  );
}
