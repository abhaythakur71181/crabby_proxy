-- Index to speed up quota SUM queries (user_id + started_at filter)
-- and cover bytes_sent/bytes_received so the SUM can be served from the index alone.
CREATE INDEX IF NOT EXISTS idx_usage_quota_lookup
    ON usage (user_id, started_at, bytes_sent, bytes_received);
