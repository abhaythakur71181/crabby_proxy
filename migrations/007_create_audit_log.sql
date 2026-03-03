-- Audit log for tracking admin actions
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,           -- e.g. "user.create", "user.delete", "config.reload", "approval.create"
    target_type TEXT,               -- e.g. "user", "config", "approval", "api_key"
    target_id TEXT,                 -- ID of the affected entity
    details TEXT,                   -- JSON blob with action-specific data
    ip_address TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
