-- Explicit ON DELETE behaviour for foreign keys to users (#36).
--
-- The original tables declared `REFERENCES users(id)` with no ON DELETE
-- clause (and user_group_members cascaded on group_id but not user_id), so a
-- hard delete of a user was blocked by whichever child row it hit first, with
-- no stated intent. The app soft-deletes users (is_active = 0), but the schema
-- should say what a hard delete means. Policy:
--
--   * Data that only exists *for* a user -- sessions, API keys, group
--     memberships, IP approvals granted to them, approval requests they
--     filed -- is removed with the user: ON DELETE CASCADE on the subject
--     `user_id`.
--   * Actor columns (approvals.approved_by / terminated_by,
--     approval_requests.decided_by) are accountability records: they keep
--     the default NO ACTION, so an admin who made decisions cannot be hard
--     deleted out from under them.
--   * `usage` and `audit_log` are history and are deliberately left as-is
--     (NO ACTION): deleting a user must not silently erase billing or audit
--     history, and rebuilding the large `usage` table is expensive.
--
-- SQLite cannot alter a constraint, so each table is rebuilt: create the new
-- table, copy rows with an explicit column list, drop the old table, rename,
-- and recreate its indexes (IF NOT EXISTS). Rows whose subject/actor user no
-- longer exists can only come from manual edits made while FK enforcement was
-- off; they are unusable and would violate the constraint on copy, so they are
-- skipped. Each table's AUTOINCREMENT high-water mark is carried over so ids
-- of deleted rows are never reused. None of these tables is the parent of
-- another FK, so dropping them with foreign_keys=ON triggers no cascades.

-- sessions -------------------------------------------------------------------
CREATE TABLE sessions_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT
);
INSERT INTO sessions_new (id, user_id, token_hash, created_at, expires_at, ip_address, user_agent)
SELECT id, user_id, token_hash, created_at, expires_at, ip_address, user_agent
FROM sessions
WHERE user_id IN (SELECT id FROM users);
-- Carry the AUTOINCREMENT high-water mark over so ids are never reused.
INSERT INTO sqlite_sequence (name, seq)
SELECT 'sessions_new', 0 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'sessions_new');
UPDATE sqlite_sequence
SET seq = MAX(seq, COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'sessions'), 0))
WHERE name = 'sessions_new';
DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- api_keys -------------------------------------------------------------------
CREATE TABLE api_keys_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash TEXT UNIQUE NOT NULL,
    key_prefix TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    last_used_at INTEGER,
    is_active BOOLEAN DEFAULT 1
);
INSERT INTO api_keys_new (id, user_id, key_hash, key_prefix, name, created_at, expires_at, last_used_at, is_active)
SELECT id, user_id, key_hash, key_prefix, name, created_at, expires_at, last_used_at, is_active
FROM api_keys
WHERE user_id IN (SELECT id FROM users);
-- Carry the AUTOINCREMENT high-water mark over so ids are never reused.
INSERT INTO sqlite_sequence (name, seq)
SELECT 'api_keys_new', 0 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'api_keys_new');
UPDATE sqlite_sequence
SET seq = MAX(seq, COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'api_keys'), 0))
WHERE name = 'api_keys_new';
DROP TABLE api_keys;
ALTER TABLE api_keys_new RENAME TO api_keys;
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);

-- user_group_members ---------------------------------------------------------
CREATE TABLE user_group_members_new (
    user_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    added_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES user_groups(id) ON DELETE CASCADE
);
INSERT INTO user_group_members_new (user_id, group_id, added_at)
SELECT user_id, group_id, added_at
FROM user_group_members
WHERE user_id IN (SELECT id FROM users)
  AND group_id IN (SELECT id FROM user_groups);
DROP TABLE user_group_members;
ALTER TABLE user_group_members_new RENAME TO user_group_members;
CREATE INDEX IF NOT EXISTS idx_user_group_members_user ON user_group_members(user_id);
CREATE INDEX IF NOT EXISTS idx_user_group_members_group ON user_group_members(group_id);

-- approvals ------------------------------------------------------------------
CREATE TABLE approvals_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_ip TEXT NOT NULL,
    approved_by INTEGER NOT NULL REFERENCES users(id),
    approved_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    is_expired BOOLEAN DEFAULT 0,
    is_terminated BOOLEAN DEFAULT 0,
    terminated_by INTEGER REFERENCES users(id),
    terminated_at INTEGER,
    termination_reason TEXT,
    reason TEXT,
    approval_duration_hours INTEGER NOT NULL
);
INSERT INTO approvals_new (
    id, user_id, client_ip, approved_by, approved_at, expires_at, is_expired,
    is_terminated, terminated_by, terminated_at, termination_reason, reason,
    approval_duration_hours
)
SELECT
    id, user_id, client_ip, approved_by, approved_at, expires_at, is_expired,
    is_terminated, terminated_by, terminated_at, termination_reason, reason,
    approval_duration_hours
FROM approvals
WHERE user_id IN (SELECT id FROM users)
  AND approved_by IN (SELECT id FROM users)
  AND (terminated_by IS NULL OR terminated_by IN (SELECT id FROM users));
-- Carry the AUTOINCREMENT high-water mark over so ids are never reused.
INSERT INTO sqlite_sequence (name, seq)
SELECT 'approvals_new', 0 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'approvals_new');
UPDATE sqlite_sequence
SET seq = MAX(seq, COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'approvals'), 0))
WHERE name = 'approvals_new';
DROP TABLE approvals;
ALTER TABLE approvals_new RENAME TO approvals;
CREATE INDEX IF NOT EXISTS idx_approvals_user ON approvals(user_id);
CREATE INDEX IF NOT EXISTS idx_approvals_ip ON approvals(client_ip);
CREATE INDEX IF NOT EXISTS idx_approvals_expires ON approvals(expires_at);

-- approval_requests ----------------------------------------------------------
CREATE TABLE approval_requests_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_ip TEXT NOT NULL,
    duration_hours INTEGER NOT NULL,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    requested_at INTEGER NOT NULL,
    decided_by INTEGER REFERENCES users(id),
    decided_at INTEGER,
    decision_reason TEXT
);
INSERT INTO approval_requests_new (
    id, user_id, client_ip, duration_hours, reason, status, requested_at,
    decided_by, decided_at, decision_reason
)
SELECT
    id, user_id, client_ip, duration_hours, reason, status, requested_at,
    decided_by, decided_at, decision_reason
FROM approval_requests
WHERE user_id IN (SELECT id FROM users)
  AND (decided_by IS NULL OR decided_by IN (SELECT id FROM users));
-- Carry the AUTOINCREMENT high-water mark over so ids are never reused.
INSERT INTO sqlite_sequence (name, seq)
SELECT 'approval_requests_new', 0 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'approval_requests_new');
UPDATE sqlite_sequence
SET seq = MAX(seq, COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'approval_requests'), 0))
WHERE name = 'approval_requests_new';
DROP TABLE approval_requests;
ALTER TABLE approval_requests_new RENAME TO approval_requests;
CREATE INDEX IF NOT EXISTS idx_approval_requests_user ON approval_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests(status);
