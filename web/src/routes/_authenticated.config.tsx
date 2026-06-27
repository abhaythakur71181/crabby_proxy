import { createFileRoute } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { RefreshCw, Save, Lock } from "lucide-react";
import { useEffect, useState } from "react";
import { Panel, PanelHeader } from "@/components/app/card";
import { PageHeader } from "@/components/app/page-header";
import { api, useConfig, useInvalidate, useMutation } from "@/lib/queries";
import { getSession } from "@/lib/auth";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/config")({
  head: () => ({ meta: [{ title: "Configuration · Crabby Proxy" }] }),
  component: ConfigPage,
});

function ConfigPage() {
  const { data } = useConfig();
  const invalidate = useInvalidate();
  const isRoot = getSession()?.role === "root_admin";

  // Editable fields (mirror server state; reset when it loads/changes).
  const [maxConn, setMaxConn] = useState("");
  const [connApproval, setConnApproval] = useState(false);
  const [revTunnels, setRevTunnels] = useState(false);

  useEffect(() => {
    if (!data) return;
    setMaxConn(String(data.server.max_connections));
    setConnApproval(data.features.connection_approval);
    setRevTunnels(data.features.reverse_tunnels);
  }, [data]);

  const dirty =
    !!data &&
    (Number(maxConn) !== data.server.max_connections ||
      connApproval !== data.features.connection_approval ||
      revTunnels !== data.features.reverse_tunnels);

  const saveMut = useMutation({
    mutationFn: () =>
      api.updateConfig({
        max_connections: Number(maxConn),
        connection_approval: connApproval,
        reverse_tunnels: revTunnels,
      }),
    onSuccess: () => {
      toast.success("Configuration saved");
      invalidate(["config"]);
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Failed to save config"),
  });

  const reloadMutation = useMutation({
    mutationFn: () => api.reloadConfig(),
    onSuccess: (r) => {
      toast.success(r?.message || "Configuration reloaded");
      invalidate(["config"]);
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Failed to reload config"),
  });

  return (
    <div className="mx-auto w-full max-w-[1200px] px-6 py-8 lg:px-10">
      <PageHeader
        title="Configuration"
        subtitle={
          isRoot
            ? "Edit hot-reloadable settings. Binds and secrets need a restart."
            : "Live runtime settings (read-only — root_admin can edit)."
        }
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => reloadMutation.mutate()}
              disabled={reloadMutation.isPending}
              className="inline-flex h-10 items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-4 text-sm font-medium hover:bg-white/[0.08] disabled:opacity-50"
            >
              <RefreshCw className={"size-4 " + (reloadMutation.isPending ? "animate-spin" : "")} />
              {reloadMutation.isPending ? "Reloading…" : "Reload from file"}
            </button>
            {isRoot && (
              <button
                onClick={() => saveMut.mutate()}
                disabled={!dirty || saveMut.isPending}
                className="inline-flex h-10 items-center gap-2 rounded-xl bg-[var(--accent-violet)] px-4 text-sm font-semibold text-[var(--primary-foreground)] hover:brightness-110 disabled:opacity-40"
              >
                <Save className="size-4" /> {saveMut.isPending ? "Saving…" : "Save changes"}
              </button>
            )}
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Section title="Server" hint="Listeners and connection limits.">
          <ReadOnlyRow label="Proxy bind" hint="restart required" value={data?.server.proxy_bind ?? "—"} />
          <ReadOnlyRow label="Admin bind" hint="restart required" value={data?.server.admin_bind ?? "—"} />
          <NumberRow
            label="Max connections"
            value={maxConn}
            onChange={setMaxConn}
            editable={isRoot}
          />
        </Section>

        <Section title="Authentication" hint="Identity and access controls.">
          <ReadOnlyRow
            label="Authentication enabled"
            hint="restart required"
            value={String(data?.authentication.enabled ?? false)}
          />
        </Section>

        <Section title="Features" hint="Optional runtime capabilities.">
          <SwitchRow
            label="Connection approval"
            on={connApproval}
            onChange={setConnApproval}
            editable={isRoot}
          />
          <SwitchRow
            label="Reverse tunnels"
            on={revTunnels}
            onChange={setRevTunnels}
            editable={isRoot}
          />
        </Section>
      </div>
    </div>
  );
}

function Section({ title, hint, children }: { title: string; hint: string; children: React.ReactNode }) {
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <Panel>
        <PanelHeader title={title} hint={hint} />
        <div className="space-y-3 p-5">{children}</div>
      </Panel>
    </motion.div>
  );
}

function ReadOnlyRow({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <label className="block">
      <div className="mb-1 flex items-center justify-between">
        <span className="text-xs text-foreground">{label}</span>
        {hint && (
          <span className="inline-flex items-center gap-1 text-[10px] text-muted-foreground">
            <Lock className="size-3" /> {hint}
          </span>
        )}
      </div>
      <input
        value={value}
        readOnly
        className="h-10 w-full rounded-xl border border-white/[0.08] bg-white/[0.02] px-3 font-mono-tight text-sm text-muted-foreground outline-none"
      />
    </label>
  );
}

function NumberRow({
  label,
  value,
  onChange,
  editable,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  editable: boolean;
}) {
  return (
    <label className="block">
      <div className="mb-1 text-xs text-foreground">{label}</div>
      <input
        type="number"
        min={1}
        value={value}
        readOnly={!editable}
        onChange={(e) => onChange(e.target.value)}
        className={
          "h-10 w-full rounded-xl border border-white/[0.08] px-3 font-mono-tight text-sm outline-none transition focus:border-[var(--accent-violet)]/50 " +
          (editable ? "bg-white/[0.03] focus:bg-white/[0.05]" : "bg-white/[0.02] text-muted-foreground")
        }
      />
    </label>
  );
}

function SwitchRow({
  label,
  on,
  onChange,
  editable,
}: {
  label: string;
  on: boolean;
  onChange: (v: boolean) => void;
  editable: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-4 py-1">
      <div className="text-sm">{label}</div>
      <button
        aria-pressed={on}
        disabled={!editable}
        onClick={() => editable && onChange(!on)}
        className={
          "relative h-6 w-11 rounded-full border transition " +
          (editable ? "cursor-pointer" : "cursor-not-allowed") +
          (on ? " border-[var(--accent-violet)] bg-[var(--accent-violet)]/30" : " border-white/10 bg-white/[0.04]")
        }
      >
        <motion.span
          layout
          transition={{ type: "spring", stiffness: 500, damping: 30 }}
          className={"absolute top-0.5 size-5 rounded-full bg-white shadow " + (on ? "right-0.5" : "left-0.5")}
        />
      </button>
    </div>
  );
}
