-- The original CHECK constraint only allowed 'active', 'closed', 'failed'
-- but the code writes 'success', 'handshake', 'connection', 'timeout', etc.
-- SQLite doesn't support ALTER TABLE DROP CONSTRAINT, so we recreate the table.

CREATE TABLE IF NOT EXISTS usage_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    connection_id TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    target_host TEXT NOT NULL,
    protocol TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    duration_seconds INTEGER,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active'
);

INSERT INTO usage_new SELECT * FROM usage;

DROP TABLE usage;

ALTER TABLE usage_new RENAME TO usage;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_usage_user ON usage(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_started ON usage(started_at);
CREATE INDEX IF NOT EXISTS idx_usage_connection ON usage(connection_id);
CREATE INDEX IF NOT EXISTS idx_usage_quota_lookup ON usage(user_id, started_at, bytes_sent, bytes_received);
