# Admin / approval UX + password reset — design

Date: 2026-07-12
Status: approved, ready for implementation plan

Seven cohesive enhancements to the `webv2` frontend and the admin API, grouped:
approval-request UX (wildcard IPs, IPv4 auto-fill), user-creation UX (admin
access, generated passwords, credential handout), and password reset
(self-service + admin-reset).

Frontend target is **`webv2`** only (React 19 + React Router 7 + TanStack Query
v5 + Radix/Tailwind + `sonner` toasts). The older `web/` app is out of scope.

## Backend context (already true)

- `POST /api/users` (`create_user`) — currently **root_admin only** (`users.rs:32`).
- `PUT /api/users/:id` (`update_user`) — root_admin (any field) or self. **Self can
  currently change their own password with no current-password check** — a gap this
  spec closes.
- `POST /api/approval-requests` / `POST /api/approvals` — now return a `warning`
  field for broad IP patterns (from the wildcard-IP-approvals feature).
- `verify_password(pool, username, password)` and `validate_password(pwd)` exist
  (`db/users.rs`, `validation.rs`).
- `Role` enum has `RootAdmin`, `Admin`, `User`.
- Admin API extracts the caller IP via `extract_client_ip(peer, headers)` (XFF-aware).
- `webv2/nginx.conf` sets **no CSP** → cross-origin `fetch` needs no config change.

Frontend primitives to reuse (all under `webv2/src/components/ui/`): `Modal`,
`ConfirmDialog`, `Button`, `Input`/`Textarea`/`Select`/`Field`, `CopyButton`,
`CopyableMono`; `toast` from `sonner`; API via `src/api/http.ts` + typed
functions in `src/api/endpoints.ts`; query hooks in `src/hooks/queries.ts`;
session/role via `src/lib/auth.ts` (`useSession`, `isAdminRole`, `Role`).

---

## A. Wildcard IP support in the approval UI

Backend already accepts patterns; this surfaces them.

- `RequestAccessDialog` and `CreateGrantDialog` (`pages/approvals.tsx`): the
  Client-IP `Field` help text documents the accepted forms — exact IP, `*`,
  octet wildcard (`140.11.11.*`, `140.*.*.*`), CIDR (`140.11.0.0/16`), IPv6.
  A light, **non-blocking** client hint may flag obviously-malformed input, but
  the backend remains the validator (it returns `400` on bad patterns, already
  surfaced via the existing `toast.error(e.message)` path).
- **Broad-pattern warning:** add `warning?: string | null` to the response types
  for create-approval-request and create-approval in `api/types.ts`. On mutation
  success, if `warning` is present, show `toast.warning(warning)` in addition to
  the existing success toast. (`sonner` supports `toast.warning`.)

## B. Auto-fill current IPv4 in the request form

- On `RequestAccessDialog` open, `fetch("https://api.ipify.org?format=json")`,
  parse `{ ip }`, and prefill the Client-IP input **only if it is empty and the
  value is a valid IPv4**. Wrap in try/catch with a short timeout
  (`AbortController`, ~3s); on any failure leave the field empty and do not
  surface an error (best-effort convenience).
- The user can always overwrite the prefilled value.

## C. Add-user available to admin (backend + UI)

Backend (`create_user`, `users.rs`):

- Allow the caller when role is `RootAdmin` **or** `Admin` (was root_admin only).
- Privilege guard: an `Admin` caller may create only `role = "user"`. If an
  `Admin` submits any other role, return `403` ("Admins can only create regular
  users"). `RootAdmin` behavior unchanged (may create `user` or `admin`).

UI (`CreateUserDialog` in `pages/users/index.tsx`):

- Show the "New user" button to `admin` and `root_admin` (was root_admin only).
- Role `Select`: `root_admin` sees `user` / `admin`; `admin` sees `user` only.

## D. Auto-generate strong password in the new-user modal

- A `generatePassword()` helper (new `webv2/src/lib/password.ts`) produces a
  20-character password drawing from upper, lower, digit, and a safe symbol set,
  **guaranteed** to contain at least one letter and one digit (backend
  `validate_password` requires letters + digits) and to satisfy the app's
  existing client-side rules.
- `CreateUserDialog` fills the password field with a generated value **on open**,
  shows it in a readable (non-masked, or toggle-to-reveal) input with a
  **Regenerate** button and a `CopyButton`.
- The admin can still type a custom password (clears/So the generated value is
  just a default).

## E. Credential handout popup after user creation

- After `createUser` succeeds, capture the **plaintext password** from the form
  (the API response never returns it) and open a "User created" `Modal`:
  - Username and password each shown with a `CopyButton` (password via
    `CopyableMono` or a reveal+copy control).
  - A **"Download CSV"** button that triggers a client-side download of
    `username,password\n<user>,<pass>` as `text/csv` (new small helper
    `downloadCsv(filename, rows)` in `webv2/src/lib/download.ts`, using a Blob +
    object URL).
  - A note that the password is shown only once.
- Navigate to `/users/:id` when the admin closes the handout dialog (replacing
  the current immediate navigate).

## F. Self-service password reset (current password required)

Backend — new `POST /api/users/me/password`:

- Body: `{ current_password: string, new_password: string }`.
- Auth: the session user (`current_user_id`).
- **Deny `root_admin`** with `403` ("root_admin changes password via admin
  reset") — self-service is for `user` and `admin` only.
- Verify `current_password` against the caller's stored hash via
  `verify_password(pool, &current_user.username, &current_password)`; on mismatch
  return `401` ("Current password is incorrect").
- `validate_password(&new_password)` → `400` on failure.
- Update the caller's password, then `invalidate_all_for_user(id, username)`.
- Audit-log `password_self_reset`.

Backend — close the existing gap in `update_user`:

- If `request.password.is_some()` **and** the caller is `is_self` and **not**
  `root_admin`, return `403` ("Use the change-password endpoint"). This removes
  the no-current-password self reset path. (root_admin editing via update_user is
  unaffected; admin-reset uses endpoint G below.)

UI (`pages/account.tsx`):

- A "Change password" card with `current_password`, `new_password`,
  `confirm_password` fields; client-side check that new == confirm and passes the
  app password rule; submit calls the new endpoint; success → `toast.success` and
  clear the form.
- Hidden entirely when `session.role === "root_admin"`.

## G. Admin-reset another user's password

Backend — new `POST /api/users/:id/password`:

- Body: `{ new_password: string }` (no current password).
- Auth matrix:
  - `root_admin` → may target any user (including self, admins, other root_admins).
  - `admin` → may target only a user whose role is `user`. Fetch the target;
    if its role is `admin` or `root_admin`, return `403`.
  - anyone else → `403`.
- `validate_password(&new_password)` → `400` on failure.
- Update target password, `invalidate_all_for_user(target_id, target_username)`.
- Audit-log `password_admin_reset` with the target id.

UI (`pages/users/detail.tsx` / `sections.tsx`):

- A "Reset password" button on the user-detail view, visible when:
  - `session.role === "root_admin"` (any target), or
  - `session.role === "admin"` **and** the target user's role is `user`.
- Opens a dialog that **reuses features D + E**: an auto-generated password
  (Regenerate + copy), submit calls the endpoint, and on success shows the same
  copy / Download-CSV handout popup (the admin set the password and must hand it
  over). No current-password field.

---

## API additions (`webv2/src/api/endpoints.ts`, `types.ts`)

- `changeOwnPassword(body: { current_password: string; new_password: string }) → post<void>("/api/users/me/password", body)`
- `adminResetPassword(userId: number, body: { new_password: string }) → post<void>(\`/api/users/${userId}/password\`, body)`
- Response types for `createApprovalRequest` / `createApproval` gain
  `warning?: string | null`.

## Testing

Backend (Rust, sqlite in-memory, mirror existing `users.rs` handler-test style if
present, else db-level tests):

- `create_user`: admin may create `user`; admin creating `admin`/`root_admin` →
  403; root_admin still creates `user`/`admin`.
- self password endpoint: correct current password updates; wrong current → 401;
  root_admin → 403; invalid new password → 400.
- admin-reset endpoint: root_admin resets any target; admin resets a `user`;
  admin resetting an `admin`/`root_admin` → 403; non-admin → 403.
- `update_user` gap: self non-root with `password` set → 403.

Frontend (webv2 — match whatever test tooling exists; if none, rely on typecheck
+ manual verification and keep logic in testable pure helpers):

- `generatePassword()` always returns a value satisfying the password rule
  (letter + digit, length 20) across many iterations.
- `downloadCsv()` builds the expected CSV text.
- IPv4 validity predicate used for the ipify prefill accepts `1.2.3.4`, rejects
  `not-an-ip` and IPv6.

## Files touched

Backend:
- `src/admin/handlers/users.rs` — relax `create_user`; add `change_own_password`,
  `admin_reset_password`; guard `update_user` self password.
- `src/admin/handlers/models.rs` — request payload structs for the two endpoints
  (if payloads live there).
- `src/admin/server.rs` — routes `POST /api/users/me/password`,
  `POST /api/users/:id/password`.

Frontend (`webv2/src/`):
- `lib/password.ts` (new) — `generatePassword()`.
- `lib/download.ts` (new) — `downloadCsv()`.
- `lib/ip.ts` (new, or colocated) — `isIpv4()` predicate.
- `api/endpoints.ts`, `api/types.ts` — new calls + `warning` fields.
- `pages/users/index.tsx` — CreateUserDialog: gate, role limit, password gen,
  credential handout.
- `pages/users/detail.tsx` / `sections.tsx` — admin-reset button + dialog.
- `pages/account.tsx` — self change-password card.
- `pages/approvals.tsx` — pattern help text, `warning` surfacing, ipify prefill.

## Non-goals / risks

- ipify is a third-party call that leaks the request; it is best-effort and
  silent-fail, and the field is user-editable. Acceptable for a convenience
  prefill; documented.
- Showing/downloading a plaintext password is inherent to admin-set credentials;
  surfaced once, never returned by the API afterward.
- `web/` (old UI) is not updated; it may still PUT password via `update_user`,
  which now `403`s for self non-root — acceptable since `web/` is out of scope,
  but noted.
- Admin-reset deliberately cannot target admins/root_admins (prevents lateral
  takeover); root_admin remains the only role that can reset elevated accounts.
