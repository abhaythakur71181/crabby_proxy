// Audit log — SERVER-side filtering (user_id, action) and pagination,
// which the backend always supported but the old UI ignored. Expandable
// rows for details, CSV export of the current page.
import { ChevronDown, Download, FileClock } from "lucide-react";
import { Fragment, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { downloadCsv } from "@/lib/utils";
import { formatDateTime, humanizeAction } from "@/lib/format";
import { useAuditLog, useUserDirectory } from "@/hooks/queries";
import { Panel } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Mono, Pagination, SearchInput } from "@/components/ui/misc";
import { Pill } from "@/components/ui/badge";
import { TableShell, THead, Th, Td, TRow, TableSkeleton } from "@/components/ui/table";
import { EmptyState, ErrorState } from "@/components/ui/states";
import { cn } from "@/lib/utils";

const PAGE_SIZE = 50;

export function AuditPage() {
  const [offset, setOffset] = useState(0);
  const [actionFilter, setActionFilter] = useState("");
  const [userIdFilter, setUserIdFilter] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);
  const resolveUser = useUserDirectory();

  // Debounce-lite: only apply the filter when the user pauses (onBlur/Enter)
  // — the applied values live separately from the inputs.
  const [applied, setApplied] = useState<{ action?: string; user_id?: number }>({});
  const apply = () => {
    setOffset(0);
    setApplied({
      action: actionFilter.trim() || undefined,
      user_id: userIdFilter.trim() ? Number(userIdFilter.trim()) : undefined,
    });
  };

  const audit = useAuditLog({ limit: PAGE_SIZE, offset, ...applied });

  const toneFor = (action: string) =>
    action.includes("delete") || action.includes("terminate") || action.includes("reject")
      ? "danger"
      : action.includes("create") || action.includes("approve")
        ? "success"
        : action.includes("update") || action.includes("reload")
          ? "info"
          : "neutral";

  const exportCsv = () => {
    if (!audit.data) return;
    downloadCsv(
      "crabby-audit.csv",
      ["id", "created_at", "actor", "action", "target_type", "target_id", "ip_address", "details"],
      audit.data.entries.map((e) => [
        e.id,
        new Date(e.created_at * 1000).toISOString(),
        resolveUser(e.user_id),
        e.action,
        e.target_type ?? "",
        e.target_id ?? "",
        e.ip_address ?? "",
        e.details ?? "",
      ]),
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-2.5">
        <p className="mr-auto text-[13px] text-fg-muted">
          Every admin action, recorded server-side. Filters run on the backend.
        </p>
        <SearchInput
          placeholder="Filter action… (e.g. user_created)"
          aria-label="Filter by action"
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          onBlur={apply}
          onKeyDown={(e) => e.key === "Enter" && apply()}
          className="w-60"
        />
        <Input
          type="number"
          placeholder="User ID"
          aria-label="Filter by user ID"
          value={userIdFilter}
          onChange={(e) => setUserIdFilter(e.target.value)}
          onBlur={apply}
          onKeyDown={(e) => e.key === "Enter" && apply()}
          className="w-28"
        />
        <Button variant="outline" size="md" onClick={exportCsv} disabled={!audit.data?.entries.length}>
          <Download className="size-3.5" /> Export
        </Button>
      </div>

      <Panel>
        {audit.isError ? (
          <ErrorState
            title="Couldn't load the audit log"
            detail={(audit.error as Error)?.message}
            onRetry={() => audit.refetch()}
            className="m-4 border-0"
          />
        ) : (
          <>
            <TableShell>
              <THead>
                <Th aria-label="Expand" />
                <Th>Action</Th>
                <Th>Actor</Th>
                <Th>Target</Th>
                <Th>IP</Th>
                <Th>When</Th>
              </THead>
              {audit.isLoading ? (
                <TableSkeleton cols={6} />
              ) : (
                <tbody>
                  {(audit.data?.entries ?? []).map((e) => {
                    const isOpen = expanded === e.id;
                    return (
                      <Fragment key={e.id}>
                        <TRow onActivate={() => setExpanded(isOpen ? null : e.id)}>
                          <Td className="w-8">
                            <ChevronDown
                              className={cn(
                                "size-3.5 text-fg-faint transition-transform",
                                isOpen && "rotate-180",
                              )}
                              aria-hidden
                            />
                          </Td>
                          <Td>
                            <Pill tone={toneFor(e.action)}>{humanizeAction(e.action)}</Pill>
                          </Td>
                          <Td className="font-medium">{resolveUser(e.user_id)}</Td>
                          <Td className="text-fg-muted">
                            {e.target_type ? (
                              <Mono>
                                {e.target_type}
                                {e.target_id ? `:${e.target_id}` : ""}
                              </Mono>
                            ) : (
                              "—"
                            )}
                          </Td>
                          <Td>
                            <Mono className="text-fg-faint">{e.ip_address ?? "—"}</Mono>
                          </Td>
                          <Td className="text-fg-faint">{formatDateTime(e.created_at)}</Td>
                        </TRow>
                        <AnimatePresence initial={false}>
                          {isOpen && (
                            <tr>
                              <td colSpan={6} className="border-b border-line/60 bg-surface-2/40 px-4">
                                <motion.div
                                  initial={{ height: 0, opacity: 0 }}
                                  animate={{ height: "auto", opacity: 1 }}
                                  exit={{ height: 0, opacity: 0 }}
                                  transition={{ duration: 0.2, ease: "easeOut" }}
                                  className="overflow-hidden"
                                >
                                  <div className="py-3 text-[12.5px]">
                                    <div className="eyebrow mb-1">Details</div>
                                    <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-[12px] leading-relaxed text-fg-muted">
                                      {e.details || "No additional details recorded."}
                                    </pre>
                                    <div className="mt-2 text-[11px] text-fg-faint">
                                      Entry <Mono>#{e.id}</Mono> · raw action <Mono>{e.action}</Mono>
                                    </div>
                                  </div>
                                </motion.div>
                              </td>
                            </tr>
                          )}
                        </AnimatePresence>
                      </Fragment>
                    );
                  })}
                </tbody>
              )}
            </TableShell>
            {!audit.isLoading && (audit.data?.entries.length ?? 0) === 0 && (
              <EmptyState
                icon={FileClock}
                title={applied.action || applied.user_id ? "No entries match the filter" : "No audit entries yet"}
                description={
                  applied.action || applied.user_id
                    ? "Try a different action string or user ID."
                    : "Admin actions are recorded here automatically."
                }
                className="m-4 border-0"
              />
            )}
            {audit.data && (
              <Pagination
                offset={offset}
                limit={PAGE_SIZE}
                total={audit.data.total}
                onOffsetChange={setOffset}
              />
            )}
          </>
        )}
      </Panel>
    </div>
  );
}
