// Groups — card grid with member counts and the policy chips the old UI
// never rendered (the backend has always returned these fields).
import { ArrowLeftRight, Plus, UsersRound } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { createGroup } from "@/api/endpoints";
import type { UserGroupWithCount } from "@/api/types";
import { formatRelative } from "@/lib/format";
import { keys, useGroups, useInvalidate } from "@/hooks/queries";
import { Stagger, StaggerItem } from "@/components/motion";
import { Modal } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Panel } from "@/components/ui/card";
import { Field, Input, Textarea } from "@/components/ui/input";
import { Pill } from "@/components/ui/badge";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";

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

export function GroupsPage() {
  const groups = useGroups();
  const invalidate = useInvalidate();
  const navigate = useNavigate();
  const [createOpen, setCreateOpen] = useState(false);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-[13px] text-fg-muted">
          Group users to share connection limits, target policies and schedules.
        </p>
        <Button variant="primary" className="ml-auto" onClick={() => setCreateOpen(true)}>
          <Plus className="size-3.5" /> New group
        </Button>
      </div>

      {groups.isError ? (
        <ErrorState
          title="Couldn't load groups"
          detail={(groups.error as Error)?.message}
          onRetry={() => groups.refetch()}
        />
      ) : groups.isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-36" />
          ))}
        </div>
      ) : (groups.data?.length ?? 0) === 0 ? (
        <EmptyState
          icon={ArrowLeftRight}
          title="No groups yet"
          description="Create a group to apply shared policy to a set of users."
          action={
            <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="size-3.5" /> Create group
            </Button>
          }
        />
      ) : (
        <Stagger className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {groups.data!.map((g) => {
            const chips = groupPolicyChips(g);
            return (
              <StaggerItem key={g.id}>
                <Panel
                  role="button"
                  tabIndex={0}
                  onClick={() => navigate(`/groups/${g.id}`)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      navigate(`/groups/${g.id}`);
                    }
                  }}
                  className="cursor-pointer p-4 transition-all hover:-translate-y-0.5 hover:shadow-pop"
                >
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="truncate text-[14.5px] font-semibold">{g.name}</h3>
                    <Pill tone="accent">
                      <UsersRound className="size-3" /> {g.member_count}
                    </Pill>
                  </div>
                  <p className="mt-1 line-clamp-2 min-h-9 text-[12.5px] text-fg-muted">
                    {g.description || "No description."}
                  </p>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {chips.length > 0 ? (
                      chips.map((c) => (
                        <Pill key={c} tone="neutral">
                          {c}
                        </Pill>
                      ))
                    ) : (
                      <span className="text-[11.5px] text-fg-faint">No policy overrides</span>
                    )}
                  </div>
                  <div className="mt-3 border-t border-line pt-2.5 text-[11.5px] text-fg-faint">
                    created {formatRelative(g.created_at)}
                  </div>
                </Panel>
              </StaggerItem>
            );
          })}
        </Stagger>
      )}

      <CreateGroupDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={(id) => {
          invalidate(keys.groups);
          if (id) navigate(`/groups/${id}`);
        }}
      />
    </div>
  );
}

function CreateGroupDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onCreated: (id?: number) => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const create = useMutation({
    mutationFn: () => createGroup({ name: name.trim(), description: description.trim() || undefined }),
    onSuccess: (r) => {
      toast.success(`Group “${r.name}” created`);
      onOpenChange(false);
      setName("");
      setDescription("");
      onCreated(r.id);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Create group"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={create.isPending}
            disabled={!name.trim()}
            onClick={() => create.mutate()}
          >
            Create group
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Name">
          {(id) => (
            <Input id={id} autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="engineering" />
          )}
        </Field>
        <Field label="Description" hint="Optional">
          {(id) => (
            <Textarea
              id={id}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="What this group is for…"
            />
          )}
        </Field>
      </div>
    </Modal>
  );
}
