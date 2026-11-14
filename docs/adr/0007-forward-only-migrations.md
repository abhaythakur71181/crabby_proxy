# ADR-0007: Forward-only migrations with automatic pre-migration snapshots

**Status:** Accepted (2026-11-14)

## Context
Migrations (`migrations/NNN_*.sql`) are applied at boot by
`sqlx::migrate!` and are up-only. Some are destructive table rebuilds
(013, 015, 021) or column drops (020), so a bad upgrade had no rollback path
other than whatever backup the operator happened to take (#37).

Reversible migrations were considered. With SQLite they buy little: most
non-trivial changes are table rebuilds or `DROP COLUMN`, whose down
migration cannot restore the dropped data, and sqlx's reversible mode would
need a down file for every existing up file. A hand-written down migration
that silently loses data is worse than none.

Timestamps also came from two sources: application code
(`chrono::Utc::now().timestamp()`) and SQL `DEFAULT (strftime('%s','now'))`
on a few columns. Both are UTC Unix seconds, so there was no correctness bug,
but the split made the source of truth unclear.

## Decision
- **Migrations are forward-only.** Never edit a shipped migration (sqlx
  checksums it); fix forward with a new numbered file. Rebuild migrations
  copy rows with explicit column lists and recreate indexes with
  `IF NOT EXISTS`.
- **The rollback path is a snapshot.** `db::run_migrations` checks for
  pending migrations on an existing file-backed database and, before applying
  them, writes a consistent copy with `VACUUM INTO` to
  `<db>.pre-migrate-<from>-to-<to>-<unix>.bak` next to the database. If the
  snapshot cannot be written the migration is not run. Fresh and in-memory
  databases, and boots with nothing pending, take no snapshot.
- **Timestamps come from the application clock.** Every write binds
  `chrono::Utc::now().timestamp()` (UTC Unix seconds). The remaining SQL
  `DEFAULT (strftime('%s','now'))` clauses (audit_log, user_groups,
  user_group_members) are legacy fallbacks producing the same unit; new
  columns should not add DB-side defaults for timestamps.

## Consequences
To roll back an upgrade: stop the proxy, deploy the previous version, and
replace the database file with the snapshot (remove any `-wal`/`-shm`
files first). Writes made after the upgrade are lost. Snapshots are not
pruned automatically; delete old ones once an upgrade is known good. Regular
backups (see RUNBOOK) are still needed; the snapshot only covers the
migration step.
