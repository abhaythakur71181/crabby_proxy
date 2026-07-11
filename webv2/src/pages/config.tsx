// Configuration — redacted runtime config; root_admin edits the three
// mutable fields (max_connections, connection_approval, reverse_tunnels)
// with dirty-state tracking; reload re-reads the TOML + TLS certs.
import { RefreshCw, RotateCcw, Save, Server, ShieldCheck, ToggleRight } from "lucide-react";
import { useEffect, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { reloadConfig, updateConfig } from "@/api/endpoints";
import { keys, useConfig, useInvalidate, useSession } from "@/hooks/queries";
import { Stagger, StaggerItem } from "@/components/motion";
import { ConfirmDialog } from "@/components/ui/dialog";
import { Panel, PanelHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Mono, Switch } from "@/components/ui/misc";
import { Pill } from "@/components/ui/badge";
import { ErrorState, Skeleton } from "@/components/ui/states";

export function ConfigPage() {
  const config = useConfig();
  const session = useSession();
  const invalidate = useInvalidate();
  const isRoot = session?.role === "root_admin";

  const [maxConns, setMaxConns] = useState("");
  const [approval, setApproval] = useState(false);
  const [tunnels, setTunnels] = useState(false);
  const [reloadOpen, setReloadOpen] = useState(false);

  useEffect(() => {
    if (config.data) {
      setMaxConns(String(config.data.server.max_connections));
      setApproval(config.data.features.connection_approval);
      setTunnels(config.data.features.reverse_tunnels);
    }
  }, [config.data]);

  const dirty =
    config.data != null &&
    (Number(maxConns) !== config.data.server.max_connections ||
      approval !== config.data.features.connection_approval ||
      tunnels !== config.data.features.reverse_tunnels);

  const save = useMutation({
    mutationFn: () =>
      updateConfig({
        max_connections: Number(maxConns) !== config.data!.server.max_connections ? Number(maxConns) : undefined,
        connection_approval:
          approval !== config.data!.features.connection_approval ? approval : undefined,
        reverse_tunnels: tunnels !== config.data!.features.reverse_tunnels ? tunnels : undefined,
      }),
    onSuccess: () => {
      toast.success("Configuration saved and applied");
      invalidate(keys.config);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const reload = useMutation({
    mutationFn: reloadConfig,
    onSuccess: (r) => {
      toast.success(r.message);
      setReloadOpen(false);
      invalidate(keys.config);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  if (config.isError) {
    return (
      <ErrorState
        title="Couldn't load configuration"
        detail={(config.error as Error)?.message}
        onRetry={() => config.refetch()}
      />
    );
  }

  const c = config.data;

  return (
    <Stagger className="mx-auto max-w-3xl space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-[13px] text-fg-muted">
          Runtime configuration (secrets redacted). Binds and auth need a restart.
        </p>
        <Button variant="outline" className="ml-auto" onClick={() => setReloadOpen(true)}>
          <RefreshCw className="size-3.5" /> Reload from file
        </Button>
      </div>

      {/* Server */}
      <StaggerItem>
        <Panel>
          <PanelHeader
            eyebrow="restart required to change binds"
            title={
              <span className="flex items-center gap-2">
                <Server className="size-4 text-fg-faint" /> Server
              </span>
            }
          />
          <div className="space-y-3 px-4 pb-4">
            {config.isLoading ? (
              <Skeleton className="h-24" />
            ) : (
              <>
                <ReadOnlyRow label="Proxy bind" value={c?.server.proxy_bind} />
                <ReadOnlyRow label="Admin bind" value={c?.server.admin_bind} />
                <ReadOnlyRow
                  label="Proxy authentication"
                  value={c?.authentication.enabled ? "enabled" : "disabled"}
                  pill={c?.authentication.enabled ? "success" : "warning"}
                />
                <div className="flex items-center justify-between gap-4 pt-1">
                  <div>
                    <div className="text-[13px] font-medium">Max connections</div>
                    <div className="text-[11.5px] text-fg-faint">
                      Global concurrent connection ceiling
                    </div>
                  </div>
                  <Input
                    type="number"
                    min={1}
                    value={maxConns}
                    onChange={(e) => setMaxConns(e.target.value)}
                    disabled={!isRoot}
                    aria-label="Max connections"
                    className="w-32 text-right"
                  />
                </div>
              </>
            )}
          </div>
        </Panel>
      </StaggerItem>

      {/* Features */}
      <StaggerItem>
        <Panel>
          <PanelHeader
            eyebrow={isRoot ? "editable" : "root admin only"}
            title={
              <span className="flex items-center gap-2">
                <ToggleRight className="size-4 text-fg-faint" /> Features
              </span>
            }
          />
          <div className="space-y-4 px-4 pb-4">
            {config.isLoading ? (
              <Skeleton className="h-16" />
            ) : (
              <>
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <div className="text-[13px] font-medium">Connection approval</div>
                    <div className="text-[11.5px] text-fg-faint">
                      Non-admin users need an approved IP grant to proxy
                    </div>
                  </div>
                  <Switch
                    checked={approval}
                    onCheckedChange={setApproval}
                    disabled={!isRoot}
                    aria-label="Connection approval"
                  />
                </div>
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <div className="text-[13px] font-medium">Reverse tunnels</div>
                    <div className="text-[11.5px] text-fg-faint">
                      Allow publishing internal services on allocated ports
                    </div>
                  </div>
                  <Switch
                    checked={tunnels}
                    onCheckedChange={setTunnels}
                    disabled={!isRoot}
                    aria-label="Reverse tunnels"
                  />
                </div>
              </>
            )}
          </div>
        </Panel>
      </StaggerItem>

      {/* Save bar */}
      {isRoot && dirty && (
        <StaggerItem>
          <Panel className="sticky bottom-4 flex items-center gap-3 border-accent/30 bg-surface-1/95 px-4 py-3 shadow-pop backdrop-blur">
            <Pill tone="accent">Unsaved changes</Pill>
            <div className="ml-auto flex gap-2">
              <Button
                variant="ghost"
                onClick={() => {
                  setMaxConns(String(c!.server.max_connections));
                  setApproval(c!.features.connection_approval);
                  setTunnels(c!.features.reverse_tunnels);
                }}
              >
                <RotateCcw className="size-3.5" /> Discard
              </Button>
              <Button variant="primary" loading={save.isPending} onClick={() => save.mutate()}>
                <Save className="size-3.5" /> Save & apply
              </Button>
            </div>
          </Panel>
        </StaggerItem>
      )}

      {!isRoot && (
        <p className="flex items-center gap-2 text-[12px] text-fg-faint">
          <ShieldCheck className="size-3.5" /> Only root admins can edit these values.
        </p>
      )}

      <ConfirmDialog
        open={reloadOpen}
        onOpenChange={setReloadOpen}
        title="Reload configuration?"
        description="Re-reads the TOML file and TLS certificates. Security-critical fields are preserved."
        confirmLabel="Reload now"
        tone="primary"
        loading={reload.isPending}
        onConfirm={() => reload.mutate()}
      />
    </Stagger>
  );
}

function ReadOnlyRow({
  label,
  value,
  pill,
}: {
  label: string;
  value: string | undefined;
  pill?: "success" | "warning";
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-[13px] text-fg-muted">{label}</span>
      {pill ? (
        <Pill tone={pill}>{value ?? "—"}</Pill>
      ) : (
        <Mono className="text-fg">{value ?? "—"}</Mono>
      )}
    </div>
  );
}
