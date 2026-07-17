-- Re-add a corrected CHECK constraint on usage.status.
--
-- Migration 013 dropped the CHECK entirely (the original set — active/closed/
-- failed — never matched the values the code emits, so every INSERT had failed).
-- The status value is now produced exclusively by the ConnectionStatus enum
-- (src/db/usage.rs); this constraint mirrors that enum's as_str() values exactly
-- and is a backstop against any non-enum writer. A schema-conformance test
-- (db::usage::tests) inserts every enum variant to guarantee they stay in sync.
--
-- SQLite cannot ADD a CHECK via ALTER, so the table is rebuilt. The INSERT uses
-- an explicit column list (not SELECT *) and every existing row already carries
-- an enum-produced status, so no data is lost.
--
-- NOTE: this rebuilds the whole `usage` table under a write lock; run it before
-- the table grows large (see retention issue #29, which will rebuild/rollup it).

CREATE TABLE usage_checked (
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
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN (
        'active', 'success', 'failed', 'handshake',
        'connection', 'response', 'timeout', 'tunnel', 'quota_exceeded'
    ))
);

INSERT INTO usage_checked (
    id, user_id, connection_id, client_ip, target_host, protocol,
    started_at, ended_at, duration_seconds, bytes_sent, bytes_received, status
)
SELECT
    id, user_id, connection_id, client_ip, target_host, protocol,
    started_at, ended_at, duration_seconds, bytes_sent, bytes_received, status
FROM usage;

DROP TABLE usage;

ALTER TABLE usage_checked RENAME TO usage;

-- Recreate indexes (match migration 013).
CREATE INDEX IF NOT EXISTS idx_usage_user ON usage(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_started ON usage(started_at);
CREATE INDEX IF NOT EXISTS idx_usage_connection ON usage(connection_id);
CREATE INDEX IF NOT EXISTS idx_usage_quota_lookup ON usage(user_id, started_at, bytes_sent, bytes_received);
