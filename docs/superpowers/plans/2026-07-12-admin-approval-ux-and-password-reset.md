# Admin/Approval UX + Password Reset Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Seven cohesive enhancements — wildcard IP in the approval UI, IPv4 auto-fill, admin user-create, generated passwords + credential handout, self-service and admin password reset.

**Architecture:** Backend adds three thin handlers whose authorization decisions live in pure, unit-tested functions. Frontend (`webv2`) adds three pure helpers (password generator, CSV download, IPv4 check) tested with `bun test`, then wires existing dialogs/pages to them.

**Tech Stack:** Rust (axum, sqlx/sqlite), React 19 + React Router 7 + TanStack Query v5 + Radix/Tailwind + `sonner`, bun.

## Global Constraints

- Backend is a binary crate; Rust tests run via `cargo test --bin crabby_proxy <filter>`.
- Backend handler authorization must be expressed as pure functions and unit-tested (handlers have no AppState test harness). Follow the existing `peer_is_trusted_proxy` pure-fn + test pattern.
- `Role` (`src/db/models.rs`) = `RootAdmin | Admin | User`, derives `PartialEq, Eq`. `User::get_role() -> Role`.
- `db::users::verify_password(pool, username, password) -> Result<Option<User>, sqlx::Error>` (Some = correct).
- `validation::validate_password(&str) -> Result<(), String>`; map errors with `ApiError::bad_request`.
- `db::users::update_user(pool, id, password: Option<&str>, role, max_conns, bw, is_active) -> Result<User>`.
- After any password change call `state.invalidate_all_for_user(id, Some(&username)).await`.
- Frontend: `webv2/` uses bun. Pure-logic tests are `*.test.ts` run with `bun test <path>`. UI changes are verified with `bun run typecheck` (`tsc -b`) and `bun run build`. No component test runner exists — do not add one.
- Frontend API goes through `src/api/http.ts` (`get/post/put/del`), typed in `src/api/endpoints.ts` + `src/api/types.ts`; server state via hooks in `src/hooks/queries.ts`; session/role via `src/lib/auth.ts` (`useSession`, `isAdminRole`, `Role = "root_admin" | "admin" | "user"`).
- Reuse UI primitives from `webv2/src/components/ui/`: `Modal`, `Button`, `Input`/`Textarea`/`Select`/`Field`, `CopyButton`, `CopyableMono`; `toast` from `sonner`.
- End every commit message with: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: Backend authorization helpers + relax `create_user`

**Files:**
- Modify: `src/admin/handlers/users.rs` (add three pure `authz` fns + their tests; wire `create_user`)

**Interfaces:**
- Produces (used by Tasks 2 & 3):
  - `fn authorize_create_user(caller: &Role, requested: &Role) -> Result<(), String>`
  - `fn authorize_admin_reset(caller: &Role, target: &Role) -> Result<(), String>`
  - `fn self_reset_allowed(caller: &Role) -> bool`

- [ ] **Step 1: Write the failing tests**

At the bottom of `src/admin/handlers/users.rs`, add (or extend) a test module:

```rust
#[cfg(test)]
mod authz_tests {
    use super::{authorize_admin_reset, authorize_create_user, self_reset_allowed};
    use crate::db::models::Role;

    #[test]
    fn create_user_matrix() {
        // root_admin can create anything
        assert!(authorize_create_user(&Role::RootAdmin, &Role::User).is_ok());
        assert!(authorize_create_user(&Role::RootAdmin, &Role::Admin).is_ok());
        assert!(authorize_create_user(&Role::RootAdmin, &Role::RootAdmin).is_ok());
        // admin can create only regular users
        assert!(authorize_create_user(&Role::Admin, &Role::User).is_ok());
        assert!(authorize_create_user(&Role::Admin, &Role::Admin).is_err());
        assert!(authorize_create_user(&Role::Admin, &Role::RootAdmin).is_err());
        // plain user cannot create
        assert!(authorize_create_user(&Role::User, &Role::User).is_err());
    }

    #[test]
    fn admin_reset_matrix() {
        // root_admin can reset anyone
        assert!(authorize_admin_reset(&Role::RootAdmin, &Role::User).is_ok());
        assert!(authorize_admin_reset(&Role::RootAdmin, &Role::Admin).is_ok());
        assert!(authorize_admin_reset(&Role::RootAdmin, &Role::RootAdmin).is_ok());
        // admin can reset only regular users
        assert!(authorize_admin_reset(&Role::Admin, &Role::User).is_ok());
        assert!(authorize_admin_reset(&Role::Admin, &Role::Admin).is_err());
        assert!(authorize_admin_reset(&Role::Admin, &Role::RootAdmin).is_err());
        // plain user cannot reset others
        assert!(authorize_admin_reset(&Role::User, &Role::User).is_err());
    }

    #[test]
    fn self_reset_excludes_root_admin() {
        assert!(self_reset_allowed(&Role::User));
        assert!(self_reset_allowed(&Role::Admin));
        assert!(!self_reset_allowed(&Role::RootAdmin));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --bin crabby_proxy authz_tests::`
Expected: FAIL — functions not defined.

- [ ] **Step 3: Add the three pure functions**

In `src/admin/handlers/users.rs`, near the top of the file (after the `use` block, before `create_user`), add:

```rust
/// Authorize creating a user with `requested` role, for a caller of `caller` role.
/// root_admin may create any role; admin may create only regular users; a plain
/// user may not create users.
fn authorize_create_user(caller: &Role, requested: &Role) -> Result<(), String> {
    match caller {
        Role::RootAdmin => Ok(()),
        Role::Admin => {
            if *requested == Role::User {
                Ok(())
            } else {
                Err("Admins can only create regular users".to_string())
            }
        }
        Role::User => Err("Only admins can create users".to_string()),
    }
}

/// Authorize an admin resetting `target`'s password (no current password needed).
/// root_admin may reset anyone; admin may reset only regular users; a plain user
/// may not reset others.
fn authorize_admin_reset(caller: &Role, target: &Role) -> Result<(), String> {
    match caller {
        Role::RootAdmin => Ok(()),
        Role::Admin => {
            if *target == Role::User {
                Ok(())
            } else {
                Err("Admins can only reset regular users' passwords".to_string())
            }
        }
        Role::User => Err("Only admins can reset other users' passwords".to_string()),
    }
}

/// Whether `caller` may use the self-service (current-password) reset. root_admin
/// is excluded — it changes its own password via the admin-reset endpoint.
fn self_reset_allowed(caller: &Role) -> bool {
    !matches!(caller, Role::RootAdmin)
}
```

- [ ] **Step 4: Wire `create_user` to `authorize_create_user`**

In `src/admin/handlers/users.rs`, replace the current gate in `create_user`:

```rust
    if current_user.get_role() != Role::RootAdmin {
        return Err(ApiError::forbidden("Only root_admin can create users"));
    }
```

with:

```rust
    authorize_create_user(&current_user.get_role(), &request.role)
        .map_err(ApiError::forbidden)?;
```

- [ ] **Step 5: Run tests + build**

Run: `cargo test --bin crabby_proxy authz_tests:: && cargo build --bin crabby_proxy`
Expected: 3 tests pass; build succeeds.

- [ ] **Step 6: Commit**

```bash
git add src/admin/handlers/users.rs
git commit -m "feat(users): admin can create regular users; authz helpers

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Self-service password reset endpoint + close `update_user` gap

**Files:**
- Modify: `src/admin/handlers/models.rs` (add `ChangeOwnPasswordRequest`)
- Modify: `src/admin/handlers/users.rs` (add `change_own_password`; guard `update_user`)
- Modify: `src/admin/server.rs` (route)

**Interfaces:**
- Consumes: `self_reset_allowed` (Task 1); `verify_password`, `validate_password`, `update_user`, `invalidate_all_for_user`.
- Produces: `POST /api/users/me/password` handler `change_own_password`.

- [ ] **Step 1: Add the request payload struct**

In `src/admin/handlers/models.rs`, add:

```rust
#[derive(Debug, serde::Deserialize)]
pub struct ChangeOwnPasswordRequest {
    pub current_password: String,
    pub new_password: String,
}
```

- [ ] **Step 2: Add the `change_own_password` handler**

In `src/admin/handlers/users.rs`, add:

```rust
/// POST /api/users/me/password — self-service password change.
/// Requires the caller's current password. root_admin is not allowed here
/// (it resets via the admin endpoint); available to `user` and `admin`.
pub async fn change_own_password(
    State(state): State<Arc<AppState>>,
    Extension(current_user_id): Extension<i64>,
    Json(request): Json<super::models::ChangeOwnPasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Invalid session"))?;

    if !self_reset_allowed(&current_user.get_role()) {
        return Err(ApiError::forbidden(
            "root_admin changes password via the admin reset flow",
        ));
    }

    // Authenticate with the current password.
    let ok = users::verify_password(
        &state.db_pool,
        &current_user.username,
        &request.current_password,
    )
    .await?
    .is_some();
    if !ok {
        return Err(ApiError::unauthorized("Current password is incorrect"));
    }

    crate::validation::validate_password(&request.new_password).map_err(ApiError::bad_request)?;

    let updated = users::update_user(
        &state.db_pool,
        current_user_id,
        Some(&request.new_password),
        None,
        None,
        None,
        None,
    )
    .await?;

    state
        .invalidate_all_for_user(current_user_id, Some(&updated.username))
        .await;

    let _ = crate::db::audit_log::log_action(
        &state.db_pool,
        current_user_id,
        "password_self_reset",
        Some("user"),
        Some(&current_user_id.to_string()),
        None,
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
```

- [ ] **Step 3: Close the `update_user` self-password gap**

In `src/admin/handlers/users.rs`, inside `update_user`, immediately after the block:

```rust
    let is_self = current_user_id == user_id;
    let is_root_admin = current_user.get_role() == Role::RootAdmin;

    // Regular users can only update their own password
    if !is_root_admin && !is_self {
        return Err(ApiError::forbidden("Cannot modify other users"));
    }
```

add:

```rust
    // Self password changes must go through the current-password-verified
    // endpoint (POST /api/users/me/password), not this profile update.
    if request.password.is_some() && is_self && !is_root_admin {
        return Err(ApiError::forbidden(
            "Use the change-password endpoint to change your own password",
        ));
    }
```

- [ ] **Step 4: Add the route**

In `src/admin/server.rs`, next to the other `/api/users` routes, add:

```rust
        .route(
            "/api/users/me/password",
            post(handlers::users::change_own_password),
        )
```

- [ ] **Step 5: Build**

Run: `cargo build --bin crabby_proxy && cargo test --bin crabby_proxy authz_tests::`
Expected: builds; Task 1 tests still pass. (Handler behavior is covered by the `self_reset_allowed` unit test from Task 1; the handler is a thin wrapper.)

- [ ] **Step 6: Commit**

```bash
git add src/admin/handlers/users.rs src/admin/handlers/models.rs src/admin/server.rs
git commit -m "feat(users): self-service password reset with current-password auth

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Admin-reset another user's password

**Files:**
- Modify: `src/admin/handlers/models.rs` (add `AdminResetPasswordRequest`)
- Modify: `src/admin/handlers/users.rs` (add `admin_reset_password`)
- Modify: `src/admin/server.rs` (route)

**Interfaces:**
- Consumes: `authorize_admin_reset` (Task 1); `get_user_by_id`, `validate_password`, `update_user`, `invalidate_all_for_user`.
- Produces: `POST /api/users/:id/password` handler `admin_reset_password`.

- [ ] **Step 1: Add the request payload struct**

In `src/admin/handlers/models.rs`, add:

```rust
#[derive(Debug, serde::Deserialize)]
pub struct AdminResetPasswordRequest {
    pub new_password: String,
}
```

- [ ] **Step 2: Add the `admin_reset_password` handler**

In `src/admin/handlers/users.rs`, add:

```rust
/// POST /api/users/:id/password — admin resets another user's password (no
/// current password). root_admin may target anyone; admin may target only
/// regular users.
pub async fn admin_reset_password(
    State(state): State<Arc<AppState>>,
    Extension(current_user_id): Extension<i64>,
    Path(user_id): Path<i64>,
    Json(request): Json<super::models::AdminResetPasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user = users::get_user_by_id(&state.db_pool, current_user_id)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Invalid session"))?;
    let target = users::get_user_by_id(&state.db_pool, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;

    authorize_admin_reset(&current_user.get_role(), &target.get_role())
        .map_err(ApiError::forbidden)?;

    crate::validation::validate_password(&request.new_password).map_err(ApiError::bad_request)?;

    let updated = users::update_user(
        &state.db_pool,
        user_id,
        Some(&request.new_password),
        None,
        None,
        None,
        None,
    )
    .await?;

    state
        .invalidate_all_for_user(user_id, Some(&updated.username))
        .await;

    let _ = crate::db::audit_log::log_action(
        &state.db_pool,
        current_user_id,
        "password_admin_reset",
        Some("user"),
        Some(&user_id.to_string()),
        None,
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
```

- [ ] **Step 3: Add the route**

In `src/admin/server.rs`, add:

```rust
        .route(
            "/api/users/:id/password",
            post(handlers::users::admin_reset_password),
        )
```

- [ ] **Step 4: Build + full backend suite + clippy**

Run: `cargo build --bin crabby_proxy && cargo clippy --bin crabby_proxy --all-targets && cargo test --bin crabby_proxy`
Expected: builds, clippy clean, all tests pass (incl. `authz_tests::admin_reset_matrix`).

- [ ] **Step 5: Commit**

```bash
git add src/admin/handlers/users.rs src/admin/handlers/models.rs src/admin/server.rs
git commit -m "feat(users): admin/root_admin reset another user's password

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Frontend pure helpers (password, CSV, IPv4)

**Files:**
- Create: `webv2/src/lib/password.ts`, `webv2/src/lib/download.ts`, `webv2/src/lib/ip.ts`
- Test: `webv2/src/lib/password.test.ts`, `webv2/src/lib/ip.test.ts`

**Interfaces:**
- Produces (used by Tasks 5-9):
  - `generatePassword(len?: number): string`
  - `downloadCsv(filename: string, rows: string[][]): void`
  - `isIpv4(s: string): boolean`

- [ ] **Step 1: Write the failing tests**

Create `webv2/src/lib/password.test.ts`:

```ts
import { expect, test } from "bun:test";
import { generatePassword } from "./password";

test("generatePassword satisfies the backend rule across many iterations", () => {
  for (let i = 0; i < 500; i++) {
    const p = generatePassword();
    expect(p.length).toBe(20);
    expect(/[A-Za-z]/.test(p)).toBe(true); // at least one letter
    expect(/[0-9]/.test(p)).toBe(true); // at least one digit
  }
});

test("generatePassword honors a custom length", () => {
  expect(generatePassword(32).length).toBe(32);
});
```

Create `webv2/src/lib/ip.test.ts`:

```ts
import { expect, test } from "bun:test";
import { isIpv4 } from "./ip";

test("isIpv4 accepts dotted-quad IPv4", () => {
  expect(isIpv4("1.2.3.4")).toBe(true);
  expect(isIpv4("140.11.11.5")).toBe(true);
  expect(isIpv4("255.255.255.255")).toBe(true);
});

test("isIpv4 rejects non-IPv4", () => {
  expect(isIpv4("not-an-ip")).toBe(false);
  expect(isIpv4("256.1.1.1")).toBe(false);
  expect(isIpv4("1.2.3")).toBe(false);
  expect(isIpv4("2401:4900::1")).toBe(false);
  expect(isIpv4("140.11.11.*")).toBe(false);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd webv2 && bun test src/lib/password.test.ts src/lib/ip.test.ts`
Expected: FAIL — modules not found.

- [ ] **Step 3: Implement the helpers**

Create `webv2/src/lib/password.ts`:

```ts
// Strong password generator for admin-set credentials. Guarantees at least one
// letter and one digit so it always satisfies the backend's validate_password
// rule, and draws from a safe symbol set (no quotes/backslash/space).
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I/O to avoid confusion
const LOWER = "abcdefghijkmnpqrstuvwxyz"; // no l/o
const DIGIT = "23456789"; // no 0/1
const SYMBOL = "!@#$%^&*-_=+?";
const ALL = UPPER + LOWER + DIGIT + SYMBOL;

function pick(set: string): string {
  const idx = crypto.getRandomValues(new Uint32Array(1))[0] % set.length;
  return set[idx];
}

export function generatePassword(len = 20): string {
  const chars: string[] = [
    pick(UPPER),
    pick(LOWER),
    pick(DIGIT),
    pick(SYMBOL),
  ];
  while (chars.length < len) chars.push(pick(ALL));
  // Fisher-Yates shuffle so the guaranteed classes aren't always in front.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}
```

Create `webv2/src/lib/download.ts`:

```ts
// Trigger a client-side file download. Used for the one-time credential CSV.
export function downloadCsv(filename: string, rows: string[][]): void {
  const escape = (v: string) =>
    /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
  const csv = rows.map((r) => r.map(escape).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
```

Create `webv2/src/lib/ip.ts`:

```ts
// Strict dotted-quad IPv4 check (each octet 0-255, no wildcards).
export function isIpv4(s: string): boolean {
  const m = s.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  return m.slice(1).every((o) => {
    const n = Number(o);
    return n >= 0 && n <= 255 && String(n) === o;
  });
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cd webv2 && bun test src/lib/password.test.ts src/lib/ip.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add webv2/src/lib/password.ts webv2/src/lib/download.ts webv2/src/lib/ip.ts webv2/src/lib/password.test.ts webv2/src/lib/ip.test.ts
git commit -m "feat(webv2): password generator, CSV download, IPv4 helpers

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Frontend API — new endpoints + warning types

**Files:**
- Modify: `webv2/src/api/endpoints.ts`
- Modify: `webv2/src/api/types.ts`
- Modify: `webv2/src/hooks/queries.ts` (optional invalidation helper — only if the file exposes a mutations pattern; otherwise skip)

**Interfaces:**
- Produces (used by Tasks 6-9):
  - `changeOwnPassword(body: { current_password: string; new_password: string }): Promise<void>`
  - `adminResetPassword(userId: number, body: { new_password: string }): Promise<void>`
  - `CreateApprovalRequestResult` / `ApprovalResponse` carry `warning?: string | null`.

- [ ] **Step 1: Add the endpoint functions**

In `webv2/src/api/endpoints.ts`, in the Users group, add:

```ts
export const changeOwnPassword = (body: {
  current_password: string;
  new_password: string;
}) => post<void>("/api/users/me/password", body);

export const adminResetPassword = (
  userId: number,
  body: { new_password: string },
) => post<void>(`/api/users/${userId}/password`, body);
```

- [ ] **Step 2: Add the `warning` field to approval response types**

In `webv2/src/api/types.ts`, add `warning?: string | null;` to the interface returned by creating an approval request and the one returned by `createApproval` (the `ApprovalResponse` used as the POST result). If `createApprovalRequest` currently returns an inline/loose type, define/extend it to include:

```ts
  warning?: string | null;
```

Locate the exact interfaces by reading the file; the fields must be optional so existing consumers are unaffected. If `createApprovalRequest` in `endpoints.ts` is typed as `post<{ id: number; status: string }>(...)`, change it to `post<{ id: number; status: string; warning?: string | null }>(...)`.

- [ ] **Step 3: Typecheck**

Run: `cd webv2 && bun run typecheck`
Expected: no type errors.

- [ ] **Step 4: Commit**

```bash
git add webv2/src/api/endpoints.ts webv2/src/api/types.ts
git commit -m "feat(webv2): password-reset endpoints + broad-pattern warning types

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: CreateUserDialog — admin access, role limit, generated password, credential handout (C, D, E)

**Files:**
- Modify: `webv2/src/pages/users/index.tsx`

**Interfaces:**
- Consumes: `generatePassword`, `downloadCsv` (Task 4); `useSession`, `isAdminRole` (auth); existing `CreateUserDialog`, `Modal`, `Button`, `Field`, `Input`, `Select`, `CopyButton`, `toast`, `createUser`, `keys`, `useInvalidate`.

Read `webv2/src/pages/users/index.tsx` fully before editing. Apply these changes:

- [ ] **Step 1: Show the "New user" button to admin + root_admin**

The button visibility currently checks `session?.role === "root_admin"`. Change every such gate for the create-user button/empty-state action to `isAdminRole(session?.role)` (import `isAdminRole` from `@/lib/auth` if not already imported). `isAdminRole` returns true for `admin` and `root_admin`.

- [ ] **Step 2: Limit the Role select by caller role**

In `CreateUserDialog`, the Role `Select` currently offers `user` and `admin`. Render the `admin` option only when the current session role is `root_admin`; when the caller is `admin`, offer only `user` and default `role` state to `"user"`. Read `session` via `useSession()` inside the dialog (or pass it as a prop from the page which already has it).

- [ ] **Step 3: Auto-generate the password on open + Regenerate**

- Import `generatePassword` from `@/lib/password`.
- Initialize the `password` state with `generatePassword()` and re-generate it whenever the dialog transitions to open (e.g. a `useEffect` on the `open` prop that sets `setPassword(generatePassword())`).
- Render the password `Field` as a normal (revealed) text `Input` (not `type="password"`) with, alongside it, a `Button variant="secondary" size="sm"` labeled "Regenerate" calling `setPassword(generatePassword())`, and a `CopyButton value={password}`.
- Keep the field editable so an admin can type a custom password.

- [ ] **Step 4: Credential handout popup after success**

- Add local state: `const [created, setCreated] = useState<{ username: string; password: string } | null>(null);`.
- In the `create` mutation `onSuccess`, instead of immediately navigating, capture the submitted credentials: `setCreated({ username: username.trim(), password });` then `invalidate(keys.usersAll);` and close the create dialog. Keep the success toast.
- Render a second `Modal` (the handout) open when `created !== null`, titled "User created", containing:
  - The username with a `CopyButton`.
  - The password with a `CopyButton` (revealed mono text; you may reuse `CopyableMono`).
  - A line: "This password is shown once. Copy or download it now."
  - A `Button` "Download CSV" calling `downloadCsv(\`user-${created.username}.csv\`, [["username","password"],[created.username, created.password]])`.
  - A footer `Button` "Done" that navigates to the created user (`navigate(\`/users/${createdUserId}\`)` — capture the created user's `id` alongside the credentials: store `{ id, username, password }`) and clears `created`.

- [ ] **Step 5: Typecheck + build**

Run: `cd webv2 && bun run typecheck && bun run build`
Expected: no type errors; build succeeds.

- [ ] **Step 6: Commit**

```bash
git add webv2/src/pages/users/index.tsx
git commit -m "feat(webv2): admin create-user, generated password, credential handout

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Approvals — pattern help, broad-pattern warning, IPv4 auto-fill (A, B)

**Files:**
- Modify: `webv2/src/pages/approvals.tsx`

**Interfaces:**
- Consumes: `isIpv4` (Task 4); `createApprovalRequest` / `createApproval` result `warning` (Task 5); existing `RequestAccessDialog`, `CreateGrantDialog`, `Field`, `Input`, `toast`.

Read `webv2/src/pages/approvals.tsx` before editing.

- [ ] **Step 1: Document the pattern syntax in the Client-IP field**

In both `RequestAccessDialog` and `CreateGrantDialog`, change the Client-IP `Field` `hint` to explain accepted forms:

```
Exact IP, or a pattern: * (any), 140.11.11.* , 140.*.*.* , CIDR 140.11.0.0/16, or IPv6.
```

Do not add blocking client-side validation — the backend validates and returns 400 (already surfaced by the existing `toast.error(e.message)`).

- [ ] **Step 2: Surface the broad-pattern warning on success**

In the `create` mutation `onSuccess` of `RequestAccessDialog` (and the grant create in `CreateGrantDialog`), the success payload now may include `warning`. After the existing success toast, add:

```ts
if (data?.warning) toast.warning(data.warning);
```

(`onSuccess: (data) => { ... }` — ensure the mutation's `onSuccess` receives the response `data`; `sonner` exposes `toast.warning`.)

- [ ] **Step 3: Auto-fill current IPv4 via ipify on open**

In `RequestAccessDialog`, add an effect that runs when the dialog opens and the IP field is empty:

```ts
import { isIpv4 } from "@/lib/ip";
// ...
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
```

Match the actual state setter name for the IP field (the dialog uses an `ip`/`setIp` pair — confirm when reading the file). Do not overwrite a value the user already typed.

- [ ] **Step 4: Typecheck + build**

Run: `cd webv2 && bun run typecheck && bun run build`
Expected: no type errors; build succeeds.

- [ ] **Step 5: Commit**

```bash
git add webv2/src/pages/approvals.tsx
git commit -m "feat(webv2): approval IP patterns help, broad warning, IPv4 auto-fill

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Account page — self change-password card (F)

**Files:**
- Modify: `webv2/src/pages/account.tsx`

**Interfaces:**
- Consumes: `changeOwnPassword` (Task 5); `useSession`; `Panel`/`PanelHeader`, `Field`, `Input`, `Button`, `toast`.

- [ ] **Step 1: Add a "Change password" card**

In `webv2/src/pages/account.tsx`, render a new `Panel` (hidden entirely when `session.role === "root_admin"`) with a `useMutation` wrapping `changeOwnPassword`. Fields: `current_password`, `new_password`, `confirm_password` (all `Input type="password"` inside `Field`s). Add this card near the other sections:

```tsx
{session.role !== "root_admin" && <ChangePasswordCard />}
```

- [ ] **Step 2: Implement `ChangePasswordCard`**

Add this component in `account.tsx` (imports: `useState` from react, `useMutation` from `@tanstack/react-query`, `toast` from `sonner`, `changeOwnPassword` from `@/api/endpoints`, plus `Panel`, `PanelHeader`, `Button`, and `Field`/`Input`):

```tsx
function ChangePasswordCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");

  const mismatch = confirm.length > 0 && next !== confirm;
  const tooShort = next.length > 0 && next.length < 8;
  const canSubmit =
    current.length > 0 && next.length >= 8 && next === confirm;

  const change = useMutation({
    mutationFn: () =>
      changeOwnPassword({ current_password: current, new_password: next }),
    onSuccess: () => {
      toast.success("Password changed");
      setCurrent("");
      setNext("");
      setConfirm("");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Panel className="px-5 py-4">
      <PanelHeader title="Change password" />
      <div className="mt-3 grid max-w-sm gap-3">
        <Field label="Current password">
          {(id) => (
            <Input
              id={id}
              type="password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              autoComplete="current-password"
            />
          )}
        </Field>
        <Field
          label="New password"
          hint="At least 8 characters, with a letter and a digit."
          error={tooShort ? "Too short (min 8)" : undefined}
        >
          {(id) => (
            <Input
              id={id}
              type="password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              autoComplete="new-password"
            />
          )}
        </Field>
        <Field
          label="Confirm new password"
          error={mismatch ? "Passwords do not match" : undefined}
        >
          {(id) => (
            <Input
              id={id}
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
            />
          )}
        </Field>
        <div>
          <Button
            variant="primary"
            size="sm"
            loading={change.isPending}
            disabled={!canSubmit}
            onClick={() => change.mutate()}
          >
            Change password
          </Button>
        </div>
      </div>
    </Panel>
  );
}
```

Confirm the exact prop API of `Field`/`Input`/`Button`/`Panel`/`PanelHeader` by reading their files (they are already imported/used elsewhere in `account.tsx` and `users/index.tsx`); adjust the `Field` children shape if it takes a plain node rather than a render-prop.

- [ ] **Step 3: Typecheck + build**

Run: `cd webv2 && bun run typecheck && bun run build`
Expected: no type errors; build succeeds.

- [ ] **Step 4: Commit**

```bash
git add webv2/src/pages/account.tsx
git commit -m "feat(webv2): self-service change-password card on account page

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: User detail — admin reset-password dialog (G)

**Files:**
- Modify: `webv2/src/pages/users/detail.tsx` (and/or `webv2/src/pages/users/sections.tsx` — place the button where the per-user admin actions live)

**Interfaces:**
- Consumes: `generatePassword`, `downloadCsv` (Task 4); `adminResetPassword` (Task 5); `useSession`; `Modal`, `Button`, `Field`, `Input`, `CopyButton`, `toast`.

Read `webv2/src/pages/users/detail.tsx` and `sections.tsx` before editing to find the current user object (with `role`) and where admin actions render.

- [ ] **Step 1: Add a "Reset password" button gated by the authz matrix**

Where per-user admin actions render, show a "Reset password" `Button` when:

```ts
const session = useSession();
const canReset =
  session?.role === "root_admin" ||
  (session?.role === "admin" && targetUser.role === "user");
```

(`targetUser` = the user being viewed.) The button opens the reset dialog below.

- [ ] **Step 2: Implement the reset dialog (reuses generated password + handout)**

Add a component that mirrors Task 6's generated-password + handout pattern, but calls `adminResetPassword`:

```tsx
function ResetPasswordDialog({
  userId,
  username,
  open,
  onOpenChange,
}: {
  userId: number;
  username: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const [password, setPassword] = useState(() => generatePassword());
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (open) {
      setPassword(generatePassword());
      setDone(false);
    }
  }, [open]);

  const reset = useMutation({
    mutationFn: () => adminResetPassword(userId, { new_password: password }),
    onSuccess: () => {
      toast.success(`Password reset for ${username}`);
      setDone(true);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={done ? "New password" : `Reset password — ${username}`}
    >
      {!done ? (
        <div className="grid gap-3">
          <Field label="New password">
            {(id) => (
              <div className="flex gap-2">
                <Input
                  id={id}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => setPassword(generatePassword())}
                >
                  Regenerate
                </Button>
              </div>
            )}
          </Field>
          <div>
            <Button
              variant="primary"
              size="sm"
              loading={reset.isPending}
              disabled={password.length < 8}
              onClick={() => reset.mutate()}
            >
              Reset password
            </Button>
          </div>
        </div>
      ) : (
        <div className="grid gap-3">
          <p className="text-[13px] text-fg-muted">
            Password reset. Shown once — copy or download it now.
          </p>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[13px]">{password}</span>
            <CopyButton value={password} />
          </div>
          <div className="flex gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() =>
                downloadCsv(`user-${username}.csv`, [
                  ["username", "password"],
                  [username, password],
                ])
              }
            >
              Download CSV
            </Button>
            <Button variant="primary" size="sm" onClick={() => onOpenChange(false)}>
              Done
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
}
```

Wire local `const [resetOpen, setResetOpen] = useState(false);`, render `<ResetPasswordDialog userId={targetUser.id} username={targetUser.username} open={resetOpen} onOpenChange={setResetOpen} />`, and open it from the Step 1 button. Adjust imports and the `Modal`/`Field`/`Button` prop shapes to match the codebase after reading the files.

- [ ] **Step 3: Typecheck + build**

Run: `cd webv2 && bun run typecheck && bun run build`
Expected: no type errors; build succeeds.

- [ ] **Step 4: Commit**

```bash
git add webv2/src/pages/users/detail.tsx webv2/src/pages/users/sections.tsx
git commit -m "feat(webv2): admin reset-password dialog on user detail

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- A wildcard IP in approval UI (help text + `warning` surfacing) → Tasks 5 (types) + 7 ✓
- B IPv4 auto-fill (ipify, silent-fail, IPv4-only, non-overwrite) → Task 7 Step 3 + `isIpv4` Task 4 ✓
- C admin user-create (backend relax + UI gate + role limit) → Task 1 (backend) + Task 6 Steps 1-2 ✓
- D generated password (on-open + regenerate) → Task 4 `generatePassword` + Task 6 Step 3 ✓
- E credential handout (copy + Download CSV, once) → Task 4 `downloadCsv` + Task 6 Step 4 ✓
- F self-service reset (current-password, not root_admin; close update_user gap) → Task 2 (backend) + Task 8 (UI) ✓
- G admin-reset (admin→user, root_admin→anyone; audit) → Task 3 (backend) + Task 9 (UI) ✓
- Backend authz as pure tested fns → Task 1 (`authz_tests`) ✓

**Placeholder scan:** UI tasks (6-9) intentionally say "read the file, match prop shapes" because they integrate into large existing components not reproduced here — but every NEW unit (helpers, handlers, handout/reset/change-password components) has complete code, and every integration step names the exact existing symbol to change. No "add validation"/"TBD" placeholders.

**Type consistency:** `generatePassword(len?)`, `downloadCsv(filename, rows: string[][])`, `isIpv4(s)`, `changeOwnPassword({current_password,new_password})`, `adminResetPassword(userId,{new_password})` used identically across tasks. Backend authz fns `authorize_create_user`/`authorize_admin_reset`/`self_reset_allowed` defined in Task 1, consumed in Tasks 1-3. `warning?: string | null` optional throughout.
