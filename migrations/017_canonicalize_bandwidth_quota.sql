-- Single source of truth for the monthly bandwidth quota (#35).
--
-- Until now a user's quota lived in two columns that were reconciled at read
-- time: `monthly_bandwidth_quota` (bytes, nullable, migration 006) and the
-- legacy `bandwidth_limit_mb` (MiB, 0 = unlimited, migration 001). The
-- effective quota was "monthly_bandwidth_quota if > 0, else
-- bandwidth_limit_mb * 1 MiB if > 0, else unlimited".
--
-- This migration folds that rule into `monthly_bandwidth_quota` once, so the
-- byte column alone gives the same effective quota for every existing user,
-- then drops the legacy column. The admin API keeps accepting and returning
-- `bandwidth_limit_mb`; it is now derived from / written to the byte column.
--
-- It also drops `max_concurrent_connections` (migration 006), which was never
-- read or written by any code path: the per-user connection limit is, and
-- remains, `users.max_connections`.
--
-- Requires SQLite >= 3.35 for DROP COLUMN (the bundled libsqlite3 is newer).

UPDATE users
SET monthly_bandwidth_quota = bandwidth_limit_mb * 1048576
WHERE (monthly_bandwidth_quota IS NULL OR monthly_bandwidth_quota <= 0)
  AND bandwidth_limit_mb > 0;

-- 0 / negative previously meant "unlimited"; NULL is the canonical spelling.
UPDATE users
SET monthly_bandwidth_quota = NULL
WHERE monthly_bandwidth_quota <= 0;

ALTER TABLE users DROP COLUMN bandwidth_limit_mb;
ALTER TABLE users DROP COLUMN max_concurrent_connections;
