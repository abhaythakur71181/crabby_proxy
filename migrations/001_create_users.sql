-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('root_admin', 'admin', 'user')),
    created_by INTEGER REFERENCES users(id),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    is_active BOOLEAN DEFAULT 1,

    -- User-specific limits
    max_connections INTEGER DEFAULT 5,
    bandwidth_limit_mb INTEGER DEFAULT 1000,

    -- Rate limiting (configurable by admin)
    rate_limit_enabled BOOLEAN DEFAULT 1,
    rate_limit_rps INTEGER DEFAULT 10,
    rate_limit_burst INTEGER DEFAULT 20,

    -- Proxy config overrides
    allowed_protocols TEXT, -- JSON array: ["http", "socks5"]
    ip_whitelist TEXT,      -- JSON array

    -- Metadata
    notes TEXT,
    last_login_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_created_by ON users(created_by);
