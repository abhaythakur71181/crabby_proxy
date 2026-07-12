# Wildcard IP patterns in approvals — design

Date: 2026-07-12
Status: approved, ready for implementation plan

## Problem

Connection approvals are keyed on `client_ip`, matched exactly. Mobile clients
(the FCM/push traffic seen in production) rotate source IPs constantly
(`14.194.x`, `103.57.x`, `152.58.x` — Indian mobile ISPs). Every new IP needs a
fresh admin approval, which is unworkable at scale.

Let a user request approval for an IP *pattern* — `*`, `140.*.*.*`,
`140.11.11.*`, CIDR, IPv6 — so a whole range is approved once.

## Scope

- `client_ip` in approval requests and approvals accepts a **pattern**, not just
  an exact IP.
- Supported syntax: octet wildcards, CIDR, IPv6 (exact + CIDR).
- Backward compatible: an exact IP is a degenerate pattern (`Exact`), matched
  identically to today.
- No database schema change.

Out of scope: changing the approval *workflow* (admin still reviews and approves
every request), UI work beyond surfacing the broad-pattern warning, per-octet
IPv6 wildcards.

## 1. Pattern model — new module `src/ip_pattern.rs`

```rust
enum IpPattern {
    Any,                      // "*"  — matches every IP (v4 and v6)
    V4Octets([Option<u8>; 4]),// "140.*.*.*", "140.11.11.*"  — None = wildcard octet
    Cidr(ipnet::IpNet),       // "140.11.0.0/16", "2401:4900::/32"
    Exact(std::net::IpAddr),  // "140.11.11.5", "2401:4900::1234"
}
```

`ipnet` is already a dependency (used in `listener::peer_is_trusted_proxy`).

### Parsing — `IpPattern::parse(s: &str) -> Result<IpPattern, IpPatternError>`

Precedence (first match wins):

| Input shape | Result |
|-------------|--------|
| `*` | `Any` |
| contains `/` | `Cidr` — `s.parse::<ipnet::IpNet>()` (v4 or v6) |
| contains `:` | IPv6 `Exact` — `s.parse::<Ipv6Addr>()` |
| exactly 4 `.`-separated parts, each `*` or `0..=255` | `V4Octets` |
| otherwise parses as `Ipv4Addr` | `Exact` |
| else | `Err(IpPatternError)` |

Notes:
- `*.*.*.*` normalizes to `Any` (all four octets wildcard).
- Input is trimmed. Empty string is an error.
- The octet form requires exactly 4 parts; `140.11.*` (3 parts) is an error to
  avoid ambiguity. The only shorthand for "everything" is `*`.

### Matching — `IpPattern::matches(&self, ip: IpAddr) -> bool`

- `Any` → true for any `ip`.
- `V4Octets(pat)` → only matches `IpAddr::V4`; each fixed octet must equal the
  corresponding octet, wildcard octets always match. Never matches IPv6.
- `Cidr(net)` → `net.contains(&ip)`; a v4 net never matches a v6 ip (ipnet
  enforces family).
- `Exact(a)` → `a == ip` (family-sensitive by definition).

An IPv4 pattern never matches an IPv6 connection and vice versa.

### Broad detection — `IpPattern::is_broad(&self) -> bool`

Advisory only (see §3). True when the pattern approves a very large space:
- `Any`
- `V4Octets` with **≤ 1** fixed octet (≥ /8-sized space)
- `Cidr` v4 with prefix length **≤ 8**
- `Cidr` v6 with prefix length **≤ 32**

## 2. Matching in the validation hot path

`db::approvals::is_ip_approved(pool, user_id, client_ip)` currently runs:

```sql
SELECT COUNT(*) FROM approvals
WHERE user_id = ? AND client_ip = ? AND expires_at > ? AND is_expired = 0 AND is_terminated = 0
```

Exact `client_ip = ?` cannot match a stored wildcard. Change it to:

1. Fetch the user's active patterns:
   ```sql
   SELECT client_ip FROM approvals
   WHERE user_id = ? AND expires_at > ? AND is_expired = 0 AND is_terminated = 0
   ```
2. In Rust, parse each stored `client_ip` into an `IpPattern` and test
   `pattern.matches(connecting_ip)`. Return true on first match.
3. A stored pattern that fails to parse (corrupt row) is skipped and logged at
   `warn` — fail-closed for that row, not for the whole check.

Row count per user is small, and this only runs on a cache miss.

### Cache unchanged

`AppState::cached_ip_approved(user_id, concrete_ip) -> bool` keeps its
`(user_id, IpAddr) -> (bool, Instant)` in-memory cache and the Redis
`get/set_ip_approved(user_id, ip_str)` layer. Both key on the **concrete**
connecting IP and store the resolved boolean, so the per-connection path stays
O(1). Creating/approving an approval already invalidates the user's approval
cache (`invalidate_approval_cache` / `invalidate_approvals_for_user`), so a new
wildcard grant clears any cached negatives for that user.

## 3. Input validation + broad-pattern warning

Policy: **warn but allow** broad patterns.

Both entry points — `create_request` (user-submitted) and `create_approval`
(admin) — currently accept `client_ip` as unvalidated free text. Add:

1. **Validate**: `IpPattern::parse(&payload.client_ip)`. On error return
   `400 Bad Request` with the parse message. (Strict improvement — today garbage
   is stored silently.)
2. **Broad warning**: if `pattern.is_broad()`:
   - Add `broad_pattern=true` to the audit-log detail for the action.
   - Include a `warning` string in the JSON response (e.g.
     `"pattern '*' approves this user from any IP address"`), so an admin
     approving the request/creating the approval sees it.
   - Still create the row (allow).

Non-broad patterns behave exactly as today plus the new validation.

## 4. No schema change

`approvals.client_ip` and `approval_requests.client_ip` stay `TEXT`. Existing
exact-IP rows parse as `Exact` and match unchanged.

## 5. Testing

- **`ip_pattern` unit tests**: parse success/failure for each syntax (`*`,
  octet wildcard, v4/v6 CIDR, v6 exact, invalid); `matches` truth table
  including v4-pattern-vs-v6-ip (and reverse) non-match; `is_broad` boundaries
  (`/8` vs `/9`, 1 vs 2 fixed octets).
- **`is_ip_approved` integration** (sqlite): a `140.11.11.*` approval matches
  `140.11.11.5` and rejects `140.11.12.5`; expired / terminated rows never
  match; a corrupt pattern row is skipped without failing the check.
- **Handler validation**: `create_request` / `create_approval` reject an invalid
  pattern with 400; a broad pattern returns the `warning` field and still
  creates the row.

## Files touched

- `src/ip_pattern.rs` — new module (model, parse, matches, is_broad) + unit tests.
- `src/main.rs` — add `mod ip_pattern;`.
- `src/db/approvals.rs` — `is_ip_approved` fetch-and-match; keep signature.
- `src/admin/handlers/approval_requests.rs` — validate + warn in `create_request`.
- `src/admin/handlers/approvals.rs` — validate + warn in `create_approval`.

## Non-goals / risks

- A broad pattern (`*`, `/0`) effectively disables IP approval for that user. By
  policy this is allowed but surfaced via the warning + audit tag; the admin
  approval step is the real gate.
- Per-group/segment IPv6 wildcards are not supported (only exact + CIDR for v6);
  add later if mobile IPv6 needs it.
