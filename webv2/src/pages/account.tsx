// My account — self-service home for every role. Identity comes from the
// JWT (no admin endpoints needed), which fixes the old UI's API-keys page
// that was dead for regular users. ?new-key=1 (from ⌘K) opens key creation.
import { KeyRound, ShieldCheck } from "lucide-react";
import { Link, useSearchParams } from "react-router";
import { formatDateTime } from "@/lib/format";
import { useSession } from "@/hooks/queries";
import { Stagger, StaggerItem } from "@/components/motion";
import { Panel, PanelHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Mono } from "@/components/ui/misc";
import { RoleBadge } from "@/components/ui/badge";
import {
  ApiKeysSection,
  QuotaSection,
  RecentUsageSection,
  UsageStatsSection,
  UserApprovalsSection,
} from "./users/sections";

export function AccountPage() {
  const session = useSession();
  const [params] = useSearchParams();
  if (!session) return null;

  return (
    <Stagger className="space-y-4">
      {/* Identity header */}
      <StaggerItem>
        <Panel glow className="flex flex-wrap items-center gap-4 px-5 py-4">
          <div className="grid size-12 place-items-center rounded-full bg-surface-3 font-mono text-[15px] font-semibold uppercase text-fg-muted">
            {session.username.slice(0, 2)}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="text-[17px] font-semibold tracking-tight">{session.username}</h2>
              <RoleBadge role={session.role} />
            </div>
            <div className="mt-0.5 text-[12px] text-fg-faint">
              User <Mono>#{session.userId}</Mono> · session expires{" "}
              {formatDateTime(session.expiresAt)}
            </div>
          </div>
          <div className="ml-auto flex gap-2">
            <Link to="/approvals">
              <Button variant="outline" size="sm">
                <ShieldCheck className="size-3.5" /> Request access
              </Button>
            </Link>
            <Link to={`/users/${session.userId}`}>
              <Button variant="outline" size="sm">
                <KeyRound className="size-3.5" /> Full profile
              </Button>
            </Link>
          </div>
        </Panel>
      </StaggerItem>

      <StaggerItem className="grid gap-4 lg:grid-cols-2">
        <QuotaSection userId={session.userId} canEdit={false} />
        <UsageStatsSection userId={session.userId} />
      </StaggerItem>

      <StaggerItem>
        <ApiKeysSection
          userId={session.userId}
          username={session.username}
          autoOpenCreate={params.get("new-key") === "1"}
        />
      </StaggerItem>

      <StaggerItem className="grid gap-4 lg:grid-cols-[2fr_1fr]">
        <RecentUsageSection userId={session.userId} />
        <div className="space-y-4">
          <UserApprovalsSection userId={session.userId} />
          <Panel>
            <PanelHeader eyebrow="how to connect" title="Proxy usage" />
            <div className="space-y-2 px-4 pb-4 text-[12.5px] text-fg-muted">
              <p>
                Authenticate with <Mono>{session.username}@&lt;api-key&gt;</Mono> as the proxy
                username and the key as the password, e.g.
              </p>
              <pre className="overflow-x-auto rounded-md border border-line bg-surface-2 p-2.5 font-mono text-[11.5px] leading-relaxed">
{`curl -x http://HOST:8080 \\
  -U '${session.username}@<key>:<key>' \\
  https://example.com`}
              </pre>
              <p>HTTP, HTTPS, SOCKS4 and SOCKS5 are auto-detected on the same port.</p>
            </div>
          </Panel>
        </div>
      </StaggerItem>
    </Stagger>
  );
}
