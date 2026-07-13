// Approvals — request workflow + active grants, for both roles.
// Users: request access, watch their own requests. Admins: decide with a
// reason, create grants directly, terminate with a required reason.
// The request dialog best-effort auto-fills the client IP via api.ipify.org;
// the field stays editable and accepts wildcard/CIDR patterns.
import { CheckCircle2, Plus, ShieldCheck, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  approveRequest,
  createApproval,
  createApprovalRequest,
  rejectRequest,
  terminateApproval,
} from "@/api/endpoints";
import type { ApprovalRequestResponse, ApprovalResponse } from "@/api/types";
import { formatRelative } from "@/lib/format";
import { isIpv4 } from "@/lib/ip";
import {
  keys,
  useApprovalRequests,
  useApprovals,
  useInvalidate,
  useIsAdmin,
  useUserDirectory,
  useUsers,
} from "@/hooks/queries";
import { Modal } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Panel } from "@/components/ui/card";
import { Field, Input, Select, Textarea } from "@/components/ui/input";
import { Mono, Tabs, TabPanel } from "@/components/ui/misc";
import { Pill, StatusPill } from "@/components/ui/badge";
import { TableShell, THead, Th, Td, TRow, TableSkeleton } from "@/components/ui/table";
import { EmptyState, ErrorState } from "@/components/ui/states";

export function ApprovalsPage() {
  const isAdmin = useIsAdmin();
  const [params, setParams] = useSearchParams();
  const requests = useApprovalRequests();
  const grants = useApprovals(isAdmin);
  const resolveUser = useUserDirectory(isAdmin);
  const invalidate = useInvalidate();

  const [tab, setTab] = useState("pending");
  const [decide, setDecide] = useState<{ req: ApprovalRequestResponse; action: "approve" | "reject" } | null>(null);
  const [terminate, setTerminate] = useState<ApprovalResponse | null>(null);
  const [grantOpen, setGrantOpen] = useState(false);
  const requestOpen = params.get("request") === "1";
  const setRequestOpen = (open: boolean) => {
    const next = new URLSearchParams(params);
    if (open) next.set("request", "1");
    else next.delete("request");
    setParams(next, { replace: true });
  };

  const pending = useMemo(
    () => (requests.data ?? []).filter((r) => r.status === "pending"),
    [requests.data],
  );
  const decided = useMemo(
    () =>
      (requests.data ?? [])
        .filter((r) => r.status !== "pending")
        .sort((a, b) => (b.decided_at ?? 0) - (a.decided_at ?? 0)),
    [requests.data],
  );
  const now = Math.floor(Date.now() / 1000);
  const activeGrants = useMemo(
    () => (grants.data ?? []).filter((g) => g.expires_at > now).sort((a, b) => b.approved_at - a.approved_at),
    [grants.data, now],
  );

  const refresh = () => invalidate(keys.approvalRequests, keys.approvals);

  const tabs = [
    { value: "pending", label: <>Pending {pending.length > 0 && <Pill tone="warning" className="ml-1">{pending.length}</Pill>}</> },
    { value: "decided", label: "Decided" },
    ...(isAdmin ? [{ value: "grants", label: <>Active grants {activeGrants.length > 0 && <Pill tone="success" className="ml-1">{activeGrants.length}</Pill>}</> }] : []),
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-[13px] text-fg-muted">
          {isAdmin
            ? "Decide access requests and manage active IP grants."
            : "Request proxy access for your IP and track decisions."}
        </p>
        <div className="ml-auto flex gap-2">
          {isAdmin && (
            <Button variant="outline" onClick={() => setGrantOpen(true)}>
              <ShieldCheck className="size-3.5" /> Create grant
            </Button>
          )}
          <Button variant="primary" onClick={() => setRequestOpen(true)}>
            <Plus className="size-3.5" /> Request access
          </Button>
        </div>
      </div>

      <Tabs tabs={tabs} value={tab} onValueChange={setTab}>
        {/* Pending */}
        <TabPanel value="pending">
          <Panel>
            {requests.isError ? (
              <ErrorState className="m-4 border-0" onRetry={() => requests.refetch()} />
            ) : (
              <TableShell>
                <THead>
                  <Th>User</Th>
                  <Th>Client IP</Th>
                  <Th>Duration</Th>
                  <Th>Reason</Th>
                  <Th>Requested</Th>
                  {isAdmin && <Th aria-label="Actions" />}
                </THead>
                {requests.isLoading ? (
                  <TableSkeleton cols={isAdmin ? 6 : 5} />
                ) : (
                  <tbody>
                    {pending.map((r) => (
                      <TRow key={r.id}>
                        <Td className="font-medium">{r.username ?? resolveUser(r.user_id)}</Td>
                        <Td><Mono>{r.client_ip}</Mono></Td>
                        <Td><Mono>{r.duration_hours}h</Mono></Td>
                        <Td className="max-w-56 truncate text-fg-muted" title={r.reason ?? undefined}>
                          {r.reason || "—"}
                        </Td>
                        <Td className="text-fg-faint">{formatRelative(r.requested_at)}</Td>
                        {isAdmin && (
                          <Td className="text-right">
                            <div className="flex justify-end gap-1.5">
                              <Button
                                variant="primary"
                                size="sm"
                                onClick={() => setDecide({ req: r, action: "approve" })}
                              >
                                <CheckCircle2 className="size-3.5" /> Approve
                              </Button>
                              <Button
                                variant="danger"
                                size="sm"
                                onClick={() => setDecide({ req: r, action: "reject" })}
                              >
                                <XCircle className="size-3.5" /> Reject
                              </Button>
                            </div>
                          </Td>
                        )}
                      </TRow>
                    ))}
                  </tbody>
                )}
              </TableShell>
            )}
            {!requests.isLoading && !requests.isError && pending.length === 0 && (
              <EmptyState
                icon={ShieldCheck}
                title="No pending requests"
                description={isAdmin ? "New access requests land here." : "Request access to get started."}
                className="m-4 border-0"
              />
            )}
          </Panel>
        </TabPanel>

        {/* Decided */}
        <TabPanel value="decided">
          <Panel>
            {requests.isError ? (
              <ErrorState className="m-4 border-0" onRetry={() => requests.refetch()} />
            ) : (
              <TableShell>
                <THead>
                  <Th>User</Th>
                  <Th>Client IP</Th>
                  <Th>Status</Th>
                  <Th>Decided by</Th>
                  <Th>Decision reason</Th>
                  <Th>When</Th>
                </THead>
                {requests.isLoading ? (
                  <TableSkeleton cols={6} />
                ) : (
                  <tbody>
                    {decided.map((r) => (
                      <TRow key={r.id}>
                        <Td className="font-medium">{r.username ?? resolveUser(r.user_id)}</Td>
                        <Td><Mono>{r.client_ip}</Mono></Td>
                        <Td>
                          <StatusPill
                            tone={r.status === "approved" ? "success" : "danger"}
                            label={r.status}
                          />
                        </Td>
                        <Td className="text-fg-muted">{r.decided_by != null ? resolveUser(r.decided_by) : "—"}</Td>
                        <Td className="max-w-56 truncate text-fg-muted" title={r.decision_reason ?? undefined}>
                          {r.decision_reason || "—"}
                        </Td>
                        <Td className="text-fg-faint">{formatRelative(r.decided_at)}</Td>
                      </TRow>
                    ))}
                  </tbody>
                )}
              </TableShell>
            )}
            {!requests.isLoading && !requests.isError && decided.length === 0 && (
              <EmptyState title="No decided requests yet" className="m-4 border-0" />
            )}
          </Panel>
        </TabPanel>

        {/* Active grants (admin) */}
        {isAdmin && (
          <TabPanel value="grants">
            <Panel>
              {grants.isError ? (
                <ErrorState className="m-4 border-0" onRetry={() => grants.refetch()} />
              ) : (
                <TableShell>
                  <THead>
                    <Th>User</Th>
                    <Th>Client IP</Th>
                    <Th>Approved by</Th>
                    <Th>Expires</Th>
                    <Th>Reason</Th>
                    <Th aria-label="Actions" />
                  </THead>
                  {grants.isLoading ? (
                    <TableSkeleton cols={6} />
                  ) : (
                    <tbody>
                      {activeGrants.map((g) => (
                        <TRow key={g.id}>
                          <Td className="font-medium">{resolveUser(g.user_id)}</Td>
                          <Td><Mono>{g.client_ip}</Mono></Td>
                          <Td className="text-fg-muted">{resolveUser(g.approved_by)}</Td>
                          <Td>
                            <StatusPill tone="success" label={formatRelative(g.expires_at)} />
                          </Td>
                          <Td className="max-w-56 truncate text-fg-muted" title={g.reason ?? undefined}>
                            {g.reason || "—"}
                          </Td>
                          <Td className="text-right">
                            <Button
                              variant="danger"
                              size="sm"
                              onClick={() => setTerminate(g)}
                            >
                              Terminate
                            </Button>
                          </Td>
                        </TRow>
                      ))}
                    </tbody>
                  )}
                </TableShell>
              )}
              {!grants.isLoading && !grants.isError && activeGrants.length === 0 && (
                <EmptyState
                  title="No active grants"
                  description="Approve a request or create a grant directly."
                  className="m-4 border-0"
                />
              )}
            </Panel>
          </TabPanel>
        )}
      </Tabs>

      <RequestAccessDialog open={requestOpen} onOpenChange={setRequestOpen} onDone={refresh} />
      {isAdmin && <CreateGrantDialog open={grantOpen} onOpenChange={setGrantOpen} onDone={refresh} />}
      {decide && (
        <DecideDialog
          req={decide.req}
          action={decide.action}
          onClose={() => setDecide(null)}
          onDone={refresh}
        />
      )}
      {terminate && (
        <TerminateDialog grant={terminate} onClose={() => setTerminate(null)} onDone={refresh} />
      )}
    </div>
  );
}

function RequestAccessDialog({
  open,
  onOpenChange,
  onDone,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onDone: () => void;
}) {
  const [ip, setIp] = useState("");
  const [hours, setHours] = useState("24");
  const [reason, setReason] = useState("");

  useEffect(() => {
    if (!open) return;
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 3000);
    fetch("https://api.ipify.org?format=json", { signal: ac.signal })
      .then((r) => r.json())
      .then((d: { ip?: string }) => {
        if (d.ip && isIpv4(d.ip)) setIp((cur) => (cur.trim() ? cur : d.ip!));
      })
      .catch(() => {}) // best-effort; leave field empty on failure
      .finally(() => clearTimeout(t));
    return () => {
      clearTimeout(t);
      ac.abort();
    };
  }, [open]);

  const create = useMutation({
    mutationFn: () =>
      createApprovalRequest({
        client_ip: ip.trim(),
        duration_hours: Number(hours) || 24,
        reason: reason.trim() || undefined,
      }),
    onSuccess: (data) => {
      toast.success("Access request submitted");
      if (data?.warning) toast.warning(data.warning);
      onOpenChange(false);
      setIp("");
      setReason("");
      onDone();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Request access"
      description="An admin reviews the request; approval grants your IP proxy access."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={create.isPending} disabled={!ip.trim()} onClick={() => create.mutate()}>
            Submit request
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field
          label="Client IP"
          hint="Exact IP, or a pattern: * (any), 140.11.11.* , 140.*.*.* , CIDR 140.11.0.0/16, or IPv6."
        >
          {(id) => (
            <Input id={id} autoFocus value={ip} onChange={(e) => setIp(e.target.value)} placeholder="203.0.113.7" />
          )}
        </Field>
        <Field label="Duration (hours)">
          {(id) => (
            <Input id={id} type="number" min={1} max={720} value={hours} onChange={(e) => setHours(e.target.value)} />
          )}
        </Field>
        <Field label="Reason" hint="Helps the admin decide">
          {(id) => (
            <Textarea id={id} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why do you need access?" />
          )}
        </Field>
      </div>
    </Modal>
  );
}

function CreateGrantDialog({
  open,
  onOpenChange,
  onDone,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onDone: () => void;
}) {
  const users = useUsers(200, 0, open);
  const [userId, setUserId] = useState("");
  const [ip, setIp] = useState("");
  const [hours, setHours] = useState("24");
  const [reason, setReason] = useState("");

  const create = useMutation({
    mutationFn: () =>
      createApproval({
        user_id: Number(userId),
        client_ip: ip.trim(),
        duration_hours: Number(hours) || 24,
        reason: reason.trim() || undefined,
      }),
    onSuccess: (data) => {
      toast.success("Grant created");
      if (data?.warning) toast.warning(data.warning);
      onOpenChange(false);
      setIp("");
      setReason("");
      onDone();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Create grant"
      description="Skip the request step and grant an IP directly."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={create.isPending}
            disabled={!userId || !ip.trim()}
            onClick={() => create.mutate()}
          >
            Create grant
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="User">
          {(fid) => (
            <Select id={fid} value={userId} onChange={(e) => setUserId(e.target.value)}>
              <option value="" disabled>
                Select a user…
              </option>
              {(users.data?.items ?? []).map((u) => (
                <option key={u.id} value={u.id}>
                  {u.username}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field
          label="Client IP"
          hint="Exact IP, or a pattern: * (any), 140.11.11.* , 140.*.*.* , CIDR 140.11.0.0/16, or IPv6."
        >
          {(id) => <Input id={id} value={ip} onChange={(e) => setIp(e.target.value)} placeholder="203.0.113.7" />}
        </Field>
        <Field label="Duration (hours)">
          {(id) => (
            <Input id={id} type="number" min={1} max={720} value={hours} onChange={(e) => setHours(e.target.value)} />
          )}
        </Field>
        <Field label="Reason" hint="Optional, recorded in the audit log">
          {(id) => <Textarea id={id} value={reason} onChange={(e) => setReason(e.target.value)} />}
        </Field>
      </div>
    </Modal>
  );
}

function DecideDialog({
  req,
  action,
  onClose,
  onDone,
}: {
  req: ApprovalRequestResponse;
  action: "approve" | "reject";
  onClose: () => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  const decide = useMutation({
    mutationFn: () =>
      action === "approve" ? approveRequest(req.id, reason.trim() || undefined) : rejectRequest(req.id, reason.trim() || undefined),
    onSuccess: () => {
      toast.success(action === "approve" ? "Request approved — grant active" : "Request rejected");
      onClose();
      onDone();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Modal
      open
      onOpenChange={(o) => !o && onClose()}
      title={action === "approve" ? "Approve request" : "Reject request"}
      description={
        <>
          <Mono>{req.client_ip}</Mono> for {req.duration_hours}h
          {req.reason ? ` — “${req.reason}”` : ""}
        </>
      }
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant={action === "approve" ? "primary" : "danger"}
            loading={decide.isPending}
            onClick={() => decide.mutate()}
          >
            {action === "approve" ? "Approve" : "Reject"}
          </Button>
        </>
      }
    >
      <Field label="Decision reason" hint="Optional, shown to the requester and audited">
        {(id) => <Textarea id={id} autoFocus value={reason} onChange={(e) => setReason(e.target.value)} />}
      </Field>
    </Modal>
  );
}

function TerminateDialog({
  grant,
  onClose,
  onDone,
}: {
  grant: ApprovalResponse;
  onClose: () => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  const kill = useMutation({
    mutationFn: () => terminateApproval(grant.id, reason.trim()),
    onSuccess: () => {
      toast.success("Grant terminated");
      onClose();
      onDone();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Modal
      open
      onOpenChange={(o) => !o && onClose()}
      title="Terminate grant"
      description={
        <>
          <Mono>{grant.client_ip}</Mono> loses access immediately.
        </>
      }
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="danger" loading={kill.isPending} disabled={!reason.trim()} onClick={() => kill.mutate()}>
            Terminate grant
          </Button>
        </>
      }
    >
      <Field label="Reason" hint="Required — recorded in the audit log" error={reason.trim() === "" && kill.isError ? "Reason is required" : null}>
        {(id) => <Textarea id={id} autoFocus value={reason} onChange={(e) => setReason(e.target.value)} />}
      </Field>
    </Modal>
  );
}
