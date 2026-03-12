-- User groups for shared configuration
CREATE TABLE IF NOT EXISTS user_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    -- Shared limits (override user defaults when set)
    max_connections INTEGER,
    bandwidth_limit_mb INTEGER,
    rate_limit_rps INTEGER,
    rate_limit_burst INTEGER,
    -- Shared access control
    allowed_protocols TEXT,       -- JSON array
    allowed_targets TEXT,         -- JSON array
    blocked_targets TEXT,         -- JSON array
    access_schedule TEXT,         -- JSON schedule
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Junction table: users belong to groups
CREATE TABLE IF NOT EXISTS user_group_members (
    user_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    added_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (group_id) REFERENCES user_groups(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_group_members_user ON user_group_members(user_id);
CREATE INDEX idx_user_group_members_group ON user_group_members(group_id);
