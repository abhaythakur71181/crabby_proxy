# ADR-0003: No sentinel user ids in the auth path

**Status:** Accepted (2026-06-27)

## Context
Config-credential auth returned `user_id = -1`. Downstream per-user validators
treat `Some(-1)` as a real user, but the DB lookup misses, and several
validators fail open on a missing user — silently disabling per-user controls
for anyone holding the shared config credential.

## Decision
Config auth resolves to the real `root_admin` DB id (mirroring the already-
hardened admin HTTP path) and rejects if `root_admin` is absent. No synthetic
negative ids enter the pipeline.

## Consequences
`is_admin` now derives correctly from the resolved role; per-user accounting and
filters apply uniformly. Code that branched on `user_id == -1` is removed.
