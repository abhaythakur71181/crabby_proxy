import { createFileRoute } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { FolderTree, Plus, Trash2, Users } from "lucide-react";
import { toast } from "sonner";
import { Panel } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { Pill } from "@/components/app/badge";
import { api, useGroups, useInvalidate, useMutation } from "@/lib/queries";

export const Route = createFileRoute("/_authenticated/groups")({
  head: () => ({ meta: [{ title: "Groups · Crabby Proxy" }] }),
  component: GroupsPage,
});

function GroupsPage() {
  const { groups, isLoading } = useGroups();
  const invalidate = useInvalidate();

  const createGroup = useMutation({
    mutationFn: () => {
      const name = window.prompt("New group name")?.trim();
      if (!name) return Promise.reject(new Error("cancelled"));
      const description = window.prompt("Description (optional)")?.trim() || undefined;
      return api.createGroup({ name, description });
    },
    onSuccess: () => {
      toast.success("Group created");
      invalidate(["groups"]);
    },
    onError: (e: Error) => {
      if (e.message !== "cancelled") toast.error(`Failed to create group: ${e.message}`);
    },
  });

  const deleteGroup = useMutation({
    mutationFn: (id: number) => api.deleteGroup(id),
    onSuccess: () => {
      toast.success("Group deleted");
      invalidate(["groups"]);
    },
    onError: (e: Error) => toast.error(`Failed to delete group: ${e.message}`),
  });

  return (
    <div className="mx-auto w-full max-w-[1400px] px-6 py-8 lg:px-10">
      <PageHeader
        title="Groups"
        subtitle="Shared policies — quotas, schedules, allow/deny lists — applied to many users at once."
        action={
          <button
            onClick={() => createGroup.mutate()}
            disabled={createGroup.isPending}
            className="inline-flex h-10 items-center gap-2 rounded-xl bg-[var(--accent-violet)] px-4 text-sm font-semibold text-[var(--primary-foreground)] shadow-[0_10px_30px_-10px_var(--accent-violet)] hover:brightness-110 disabled:opacity-60"
          >
            <Plus className="size-4" /> New group
          </button>
        }
      />
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading groups…</p>
      ) : groups.length === 0 ? (
        <p className="text-sm text-muted-foreground">No groups yet.</p>
      ) : (
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {groups.map((g, i) => (
          <motion.div
            key={g.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
          >
            <Panel className="group cursor-pointer overflow-hidden p-5 transition hover:border-white/15">
              <div className="flex items-center justify-between">
                <div className="grid size-10 place-items-center rounded-xl bg-[var(--accent-violet-soft)] text-[var(--accent-violet)]">
                  <FolderTree className="size-4" />
                </div>
                <div className="flex items-center gap-2">
                  <Pill variant="outline">
                    <Users className="size-3" /> {g.member_count}
                  </Pill>
                  <button
                    onClick={() => deleteGroup.mutate(Number(g.id))}
                    disabled={deleteGroup.isPending}
                    title="Delete group"
                    className="grid size-7 place-items-center rounded-lg text-muted-foreground transition hover:bg-white/[0.06] hover:text-foreground disabled:opacity-50"
                  >
                    <Trash2 className="size-3.5" />
                  </button>
                </div>
              </div>
              <div className="mt-4 text-base font-semibold tracking-tight">{g.name}</div>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{g.description}</p>
              <div className="mt-4 flex flex-wrap items-center gap-1.5 border-t border-white/[0.06] pt-3">
                {g.policies.slice(0, 3).map((p) => (
                  <Pill key={p} variant="mono">{p}</Pill>
                ))}
              </div>
            </Panel>
          </motion.div>
        ))}
      </div>
      )}
    </div>
  );
}
