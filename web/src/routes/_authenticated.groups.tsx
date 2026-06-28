import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { FolderTree, Plus, Trash2, UserPlus, Users, X } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Panel } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { Pill } from "@/components/app/badge";
import { EmptyState } from "@/components/app/empty";
import {
  api,
  useGroups,
  useInvalidate,
  useMutation,
  useUsers,
} from "@/lib/queries";
import { isAdmin } from "@/lib/auth";
import type { Group } from "@/types/crabby";

export const Route = createFileRoute("/_authenticated/groups")({
  head: () => ({ meta: [{ title: "Groups · Crabby Proxy" }] }),
  component: GroupsPage,
});

const inputCls =
  "h-10 w-full rounded-xl border border-white/[0.08] bg-white/[0.02] px-3 text-sm outline-none placeholder:text-muted-foreground focus:border-white/[0.16]";
const labelCls =
  "mb-1.5 block text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground";

function GroupsPage() {
  const { groups, isLoading } = useGroups();
  const invalidate = useInvalidate();
  const admin = isAdmin();

  const [createOpen, setCreateOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const selected = groups.find((g) => Number(g.id) === selectedId) ?? null;

  const createGroup = useMutation({
    mutationFn: (body: { name: string; description?: string }) => api.createGroup(body),
    onSuccess: () => {
      toast.success("Group created");
      setCreateOpen(false);
      invalidate(["groups"]);
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Failed to create group"),
  });

  const deleteGroup = useMutation({
    mutationFn: (id: number) => api.deleteGroup(id),
    onSuccess: () => {
      toast.success("Group deleted");
      setSelectedId(null);
      invalidate(["groups"]);
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Failed to delete group"),
  });

  return (
    <div className="mx-auto w-full max-w-[1400px] px-6 py-8 lg:px-10">
      <PageHeader
        title="Groups"
        subtitle="Shared policies — quotas, schedules, allow/deny lists — applied to many users at once."
        action={
          admin && (
            <button
              onClick={() => setCreateOpen(true)}
              className="inline-flex h-10 items-center gap-2 rounded-xl bg-[var(--accent-violet)] px-4 text-sm font-semibold text-[var(--primary-foreground)] shadow-[0_10px_30px_-10px_var(--accent-violet)] hover:brightness-110"
            >
              <Plus className="size-4" /> New group
            </button>
          )
        }
      />
      {isLoading ? (
        <EmptyState
          icon={<FolderTree className="size-4" />}
          title="Loading groups…"
          className="mt-2"
        />
      ) : groups.length === 0 ? (
        <EmptyState
          icon={<FolderTree className="size-4" />}
          title="No groups yet"
          description="Create a group to apply shared policies to many users at once."
          className="mt-2"
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {groups.map((g, i) => (
            <motion.div
              key={g.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
            >
              <Panel
                onClick={() => setSelectedId(Number(g.id))}
                className="group cursor-pointer overflow-hidden p-5 transition hover:border-white/15"
              >
                <div className="flex items-center justify-between">
                  <div className="grid size-10 place-items-center rounded-xl bg-[var(--accent-violet-soft)] text-[var(--accent-violet)]">
                    <FolderTree className="size-4" />
                  </div>
                  <Pill variant="outline">
                    <Users className="size-3" /> {g.member_count}
                  </Pill>
                </div>
                <div className="mt-4 text-base font-semibold tracking-tight">{g.name}</div>
                <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted-foreground">
                  {g.description || "No description."}
                </p>
                {g.policies.length > 0 && (
                  <div className="mt-4 flex flex-wrap items-center gap-1.5 border-t border-white/[0.06] pt-3">
                    {g.policies.slice(0, 3).map((p) => (
                      <Pill key={p} variant="mono">
                        {p}
                      </Pill>
                    ))}
                  </div>
                )}
              </Panel>
            </motion.div>
          ))}
        </div>
      )}

      <AnimatePresence>
        {createOpen && (
          <CreateGroupDialog
            pending={createGroup.isPending}
            onClose={() => setCreateOpen(false)}
            onSubmit={(b) => createGroup.mutate(b)}
          />
        )}
        {selected && (
          <GroupDetailDialog
            group={selected}
            admin={admin}
            deleting={deleteGroup.isPending}
            onDelete={() => {
              if (window.confirm(`Delete group "${selected.name}"? This cannot be undone.`)) {
                deleteGroup.mutate(Number(selected.id));
              }
            }}
            onClose={() => setSelectedId(null)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

function Modal({
  title,
  children,
  onClose,
  wide,
}: {
  title: string;
  children: React.ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  return (
    <motion.div
      className="fixed inset-0 z-50 grid place-items-center bg-black/50 p-4 backdrop-blur-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={onClose}
    >
      <motion.div
        onClick={(e) => e.stopPropagation()}
        initial={{ opacity: 0, scale: 0.96, y: 8 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.97 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
        className={
          "w-full rounded-2xl border border-white/[0.08] bg-[color-mix(in_oklab,var(--surface)_85%,transparent)] p-6 backdrop-blur-2xl " +
          (wide ? "max-w-[560px]" : "max-w-[440px]")
        }
      >
        <div className="mb-4 flex items-start justify-between gap-4">
          <div className="text-sm font-semibold">{title}</div>
          <button
            onClick={onClose}
            className="-mr-1 -mt-1 grid size-7 place-items-center rounded-lg text-muted-foreground transition hover:bg-white/[0.06] hover:text-foreground"
          >
            <X className="size-4" />
          </button>
        </div>
        {children}
      </motion.div>
    </motion.div>
  );
}

function CreateGroupDialog({
  pending,
  onClose,
  onSubmit,
}: {
  pending: boolean;
  onClose: () => void;
  onSubmit: (b: { name: string; description?: string }) => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const trimmed = name.trim();
  const valid = trimmed.length > 0;

  return (
    <Modal title="New group" onClose={onClose}>
      <div className="space-y-4">
        <div>
          <label className={labelCls}>Name</label>
          <input
            autoFocus
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. engineering"
            onKeyDown={(e) => {
              if (e.key === "Enter" && valid && !pending)
                onSubmit({ name: trimmed, description: description.trim() || undefined });
            }}
          />
          {name.length > 0 && !valid && (
            <p className="mt-1 text-[11px] text-[var(--danger)]">Name is required.</p>
          )}
        </div>
        <div>
          <label className={labelCls}>Description (optional)</label>
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="What is this group for?"
          />
        </div>
        <button
          disabled={pending || !valid}
          onClick={() =>
            onSubmit({ name: trimmed, description: description.trim() || undefined })
          }
          className="h-10 w-full rounded-xl bg-[var(--accent-violet)] text-sm font-semibold text-[var(--primary-foreground)] hover:brightness-110 disabled:opacity-50"
        >
          Create group
        </button>
      </div>
    </Modal>
  );
}

function GroupDetailDialog({
  group,
  admin,
  deleting,
  onDelete,
  onClose,
}: {
  group: Group;
  admin: boolean;
  deleting: boolean;
  onDelete: () => void;
  onClose: () => void;
}) {
  const gid = Number(group.id);
  const invalidate = useInvalidate();
  const { users } = useUsers();

  const {
    data: members,
    isLoading: membersLoading,
  } = useQuery({
    queryKey: ["group-members", gid],
    queryFn: () => api.listGroupMembers(gid),
    enabled: Number.isFinite(gid),
  });

  const refetchMembers = () => invalidate(["group-members"]);

  const addMember = useMutation({
    mutationFn: (userId: number) => api.addGroupMember(gid, userId),
    onSuccess: () => {
      toast.success("Member added");
      refetchMembers();
      invalidate(["groups"]);
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Failed to add member"),
  });

  const removeMember = useMutation({
    mutationFn: (userId: number) => api.removeGroupMember(gid, userId),
    onSuccess: () => {
      toast.success("Member removed");
      refetchMembers();
      invalidate(["groups"]);
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Failed to remove member"),
  });

  const memberIds = useMemo(
    () => new Set((members ?? []).map((m) => m.user_id)),
    [members],
  );
  const candidates = useMemo(
    () => users.filter((u) => !memberIds.has(u.id)),
    [users, memberIds],
  );

  const [addUserId, setAddUserId] = useState<number | "">("");

  return (
    <Modal title={group.name} onClose={onClose} wide>
      <div className="space-y-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
              Group #{group.id}
            </div>
            <p className="mt-1 text-sm leading-relaxed text-foreground/90">
              {group.description || (
                <span className="text-muted-foreground">No description.</span>
              )}
            </p>
          </div>
          <Pill variant="outline">
            <Users className="size-3" /> {members?.length ?? group.member_count}
          </Pill>
        </div>

        {admin && (
          <div>
            <label className={labelCls}>Add member</label>
            <div className="flex items-center gap-2">
              <select
                className={inputCls + " appearance-none"}
                value={addUserId}
                onChange={(e) => setAddUserId(e.target.value ? Number(e.target.value) : "")}
                disabled={candidates.length === 0}
              >
                <option value="">
                  {candidates.length === 0 ? "All users are members" : "Select a user…"}
                </option>
                {candidates.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.username} ({u.role})
                  </option>
                ))}
              </select>
              <button
                onClick={() => {
                  if (addUserId !== "") {
                    addMember.mutate(Number(addUserId));
                    setAddUserId("");
                  }
                }}
                disabled={addUserId === "" || addMember.isPending}
                className="inline-flex h-10 shrink-0 items-center gap-2 rounded-xl bg-[var(--accent-violet)] px-4 text-sm font-semibold text-[var(--primary-foreground)] hover:brightness-110 disabled:opacity-50"
              >
                <UserPlus className="size-4" /> Add
              </button>
            </div>
          </div>
        )}

        <div>
          <div className={labelCls}>Members</div>
          <div className="overflow-hidden rounded-xl border border-white/[0.06] bg-white/[0.02]">
            {membersLoading ? (
              <div className="px-4 py-6 text-center text-xs text-muted-foreground">
                Loading members…
              </div>
            ) : (members?.length ?? 0) === 0 ? (
              <div className="px-4 py-6 text-center text-xs text-muted-foreground">
                No members yet.
              </div>
            ) : (
              <ul className="divide-y divide-white/[0.04]">
                {members!.map((m) => (
                  <li key={m.user_id} className="flex items-center justify-between px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{m.username}</span>
                      <Pill variant="outline">{m.role}</Pill>
                    </div>
                    {admin && (
                      <button
                        onClick={() => removeMember.mutate(m.user_id)}
                        disabled={removeMember.isPending}
                        title="Remove from group"
                        className="grid size-7 place-items-center rounded-lg text-muted-foreground transition hover:bg-white/[0.06] hover:text-[var(--danger)] disabled:opacity-50"
                      >
                        <Trash2 className="size-3.5" />
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {admin && (
          <div className="flex justify-end border-t border-white/[0.06] pt-4">
            <button
              onClick={onDelete}
              disabled={deleting}
              className="inline-flex h-10 items-center gap-2 rounded-xl border border-[var(--danger)]/30 bg-[var(--danger)]/10 px-4 text-sm font-semibold text-[var(--danger)] hover:bg-[var(--danger)]/15 disabled:opacity-50"
            >
              <Trash2 className="size-4" /> Delete group
            </button>
          </div>
        )}
      </div>
    </Modal>
  );
}
