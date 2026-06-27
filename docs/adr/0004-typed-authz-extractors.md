# ADR-0004: Authorization via typed extractors

**Status:** Accepted (2026-06-27)

## Context
The admin auth middleware proved only that a valid token existed; authorization
(role checks) was left to each handler. Several handlers — connections, tunnels,
config, groups, audit, dashboard — omitted it, so any authenticated principal
could call them.

## Decision
Introduce axum `FromRequestParts` extractors: `CurrentUser` (resolves identity,
re-checks `is_active`) and `AdminUser` (additionally enforces `require_admin`).
Handlers take these as parameters; the authz check happens in the extractor, so
it cannot be forgotten inside a handler body.

## Consequences
Object-level checks (self-or-admin) use `CurrentUser::can_access_user`. Adding a
new protected route means adding the extractor param — a visible, reviewable
step. (A fully compile-enforced router is a possible future improvement.)
