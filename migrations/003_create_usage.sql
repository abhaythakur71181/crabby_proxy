-- Create usage tracking table
CREATE TABLE IF NOT EXISTS usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    connection_id TEXT NOT NULL,

    -- Connection details
    client_ip TEXT NOT NULL,
    target_host TEXT NOT NULL,
    protocol TEXT NOT NULL,

    -- Timing
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    duration_seconds INTEGER,

    -- Bandwidth
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,

    -- Status
    status TEXT CHECK(status IN ('active', 'closed', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_usage_user ON usage(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_started ON usage(started_at);
CREATE INDEX IF NOT EXISTS idx_usage_connection ON usage(connection_id);
