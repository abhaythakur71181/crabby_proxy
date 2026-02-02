-- Create approvals table
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    client_ip TEXT NOT NULL,
    approved_by INTEGER NOT NULL REFERENCES users(id),
    approved_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    is_expired BOOLEAN DEFAULT 0,

    -- Termination (admin can manually terminate)
    is_terminated BOOLEAN DEFAULT 0,
    terminated_by INTEGER REFERENCES users(id),
    terminated_at INTEGER,
    termination_reason TEXT,

    -- Approval metadata
    reason TEXT,
    approval_duration_hours INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approvals_user ON approvals(user_id);
CREATE INDEX IF NOT EXISTS idx_approvals_ip ON approvals(client_ip);
CREATE INDEX IF NOT EXISTS idx_approvals_expires ON approvals(expires_at);
