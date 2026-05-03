-- Approval requests: users request access, admins approve/reject
CREATE TABLE IF NOT EXISTS approval_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    client_ip TEXT NOT NULL,
    duration_hours INTEGER NOT NULL,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'approved', 'rejected'
    requested_at INTEGER NOT NULL,

    -- Decision metadata (filled when admin acts)
    decided_by INTEGER REFERENCES users(id),
    decided_at INTEGER,
    decision_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_approval_requests_user ON approval_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests(status);
