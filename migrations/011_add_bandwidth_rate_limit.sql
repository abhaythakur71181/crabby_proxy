-- Per-user bandwidth rate limit in bytes per second.
-- 0 or NULL means unlimited (no throttling).
ALTER TABLE users ADD COLUMN bandwidth_rate_bps INTEGER NOT NULL DEFAULT 0;
