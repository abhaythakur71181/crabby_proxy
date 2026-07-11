// Reverse tunnels — telemetry cards (bytes, connection counts — previously
// unused backend fields) + create dialog + close with confirm.
import { Cable, Plus, X } from "lucide-react";
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { closeTunnel, createTunnel } from "@/api/endpoints";
import type { TunnelInfo } from "@/api/types";
import { formatBytes, formatRelative, serviceTypeLabel } from "@/lib/format";
import { keys, useConfig, useInvalidate, useTunnels } from "@/hooks/queries";
import { Stagger, StaggerItem, AnimatedNumber } from "@/components/motion";
import { ConfirmDialog, Modal } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Panel } from "@/components/ui/card";
import { Field, Input, Select } from "@/components/ui/input";
import { CopyableMono, Mono } from "@/components/ui/misc";
import { Pill, StatusPill } from "@/components/ui/badge";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/states";

const SERVICE_TYPES = [
  { value: "web", label: "Web (HTTP)" },
  { value: "ssh", label: "SSH" },
  { value: "postgres", label: "PostgreSQL" },
  { value: "mysql", label: "MySQL" },
  { value: "redis", label: "Redis" },
  { value: "mongodb", label: "MongoDB" },
  { value: "custom", label: "Custom" },
];

export function TunnelsPage() {
  const tunnels = useTunnels();
  const config = useConfig();
  const invalidate = useInvalidate();
  const [createOpen, setCreateOpen] = useState(false);
  const [closing, setClosing] = useState<TunnelInfo | null>(null);

  const close = useMutation({
    mutationFn: (port: number) => closeTunnel(port),
    onSuccess: () => {
      toast.success("Tunnel closed");
      setClosing(null);
      invalidate(keys.tunnels);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const featureDisabled = config.data ? !config.data.features.reverse_tunnels : false;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-[13px] text-fg-muted">
          Expose internal services through the proxy on allocated ports.
        </p>
        <Button
          variant="primary"
          className="ml-auto"
          onClick={() => setCreateOpen(true)}
          disabled={featureDisabled}
        >
          <Plus className="size-3.5" /> New tunnel
        </Button>
      </div>

      {featureDisabled && (
        <Panel className="border-warning/25 bg-warning-soft/40 px-4 py-3 text-[13px]">
          Reverse tunnels are disabled in configuration.{" "}
          <span className="text-fg-muted">Enable the feature flag on the Configuration page.</span>
        </Panel>
      )}

      {tunnels.isError ? (
        <ErrorState
          title="Couldn't load tunnels"
          detail={(tunnels.error as Error)?.message}
          onRetry={() => tunnels.refetch()}
        />
      ) : tunnels.isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-44" />
          ))}
        </div>
      ) : (tunnels.data?.tunnels.length ?? 0) === 0 ? (
        <EmptyState
          icon={Cable}
          title="No tunnels yet"
          description="Create a tunnel to publish an internal service through the proxy."
          action={
            !featureDisabled ? (
              <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}>
                <Plus className="size-3.5" /> Create tunnel
              </Button>
            ) : undefined
          }
        />
      ) : (
        <Stagger className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {tunnels.data!.tunnels.map((t) => (
            <StaggerItem key={t.tunnel_id}>
              <Panel className="group relative overflow-hidden p-4 transition-shadow hover:shadow-pop">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <div className="grid size-9 place-items-center rounded-lg bg-accent-soft text-accent">
                      <Cable className="size-4.5" />
                    </div>
                    <div>
                      <div className="text-[14px] font-semibold">
                        {serviceTypeLabel(t.service_type)}
                      </div>
                      <StatusPill
                        tone={t.status === "active" ? "success" : "neutral"}
                        label={t.status}
                        pulse={t.status === "active"}
                      />
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    aria-label={`Close tunnel on port ${t.listen_port}`}
                    className="text-danger opacity-0 transition-opacity focus-visible:opacity-100 group-hover:opacity-100 hover:bg-danger-soft"
                    onClick={() => setClosing(t)}
                  >
                    <X className="size-4" />
                  </Button>
                </div>

                <div className="mt-4 flex items-center gap-2 text-[13px]">
                  <Pill tone="accent" className="font-mono">
                    :{t.listen_port}
                  </Pill>
                  <span className="text-fg-faint" aria-hidden>
                    →
                  </span>
                  <CopyableMono value={t.target_addr} />
                </div>

                <div className="mt-4 grid grid-cols-3 gap-2 border-t border-line pt-3 text-center">
                  <div>
                    <div className="eyebrow">Active</div>
                    <AnimatedNumber
                      value={t.active_connections}
                      className="font-mono num text-[15px] font-semibold"
                    />
                  </div>
                  <div>
                    <div className="eyebrow">Total</div>
                    <AnimatedNumber
                      value={t.total_connections}
                      className="font-mono num text-[15px] font-semibold"
                    />
                  </div>
                  <div>
                    <div className="eyebrow">Moved</div>
                    <Mono className="text-[15px] font-semibold">
                      {formatBytes(t.bytes_transferred)}
                    </Mono>
                  </div>
                </div>

                <div className="mt-3 text-[11.5px] text-fg-faint">
                  created {formatRelative(t.created_at)}
                </div>
              </Panel>
            </StaggerItem>
          ))}
        </Stagger>
      )}

      <CreateTunnelDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={() => invalidate(keys.tunnels)}
      />

      <ConfirmDialog
        open={closing != null}
        onOpenChange={(o) => !o && setClosing(null)}
        title={`Close tunnel :${closing?.listen_port}?`}
        description="Active tunnel connections are dropped immediately."
        confirmLabel="Close tunnel"
        loading={close.isPending}
        onConfirm={() => closing && close.mutate(closing.listen_port)}
      />
    </div>
  );
}

function CreateTunnelDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onCreated: () => void;
}) {
  const [serviceType, setServiceType] = useState("web");
  const [port, setPort] = useState("");
  const [target, setTarget] = useState("");

  const portNum = port.trim() === "" ? undefined : Number(port);
  const portError =
    portNum !== undefined && (Number.isNaN(portNum) || portNum < 1024 || portNum > 65535)
      ? "Port must be 1024–65535 (or empty for auto-allocation)"
      : null;

  const create = useMutation({
    mutationFn: () =>
      createTunnel({
        service_type: serviceType,
        port: portNum,
        target_addr: target.trim() || undefined,
      }),
    onSuccess: (t) => {
      toast.success(`Tunnel listening on :${t.listen_port}`);
      onOpenChange(false);
      setPort("");
      setTarget("");
      onCreated();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Create tunnel"
      description="Allocates a listen port that forwards to your target."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={create.isPending}
            disabled={!!portError}
            onClick={() => create.mutate()}
          >
            Create tunnel
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Service type">
          {(id) => (
            <Select id={id} value={serviceType} onChange={(e) => setServiceType(e.target.value)}>
              {SERVICE_TYPES.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Listen port" hint="Empty = auto-allocate from the configured range" error={portError}>
          {(id) => (
            <Input
              id={id}
              type="number"
              min={1024}
              max={65535}
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder="auto"
            />
          )}
        </Field>
        <Field label="Target address" hint="host:port the tunnel forwards to">
          {(id) => (
            <Input
              id={id}
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="127.0.0.1:5432"
            />
          )}
        </Field>
      </div>
    </Modal>
  );
}
