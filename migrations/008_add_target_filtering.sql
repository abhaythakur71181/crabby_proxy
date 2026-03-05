-- Add per-user target filtering and access schedule columns
ALTER TABLE users ADD COLUMN allowed_targets TEXT;     -- JSON: ["*.example.com", "api.github.com"]
ALTER TABLE users ADD COLUMN blocked_targets TEXT;     -- JSON: ["*.malware.org"]
ALTER TABLE users ADD COLUMN access_schedule TEXT;     -- JSON: {"days":["mon","tue","wed","thu","fri"],"start_hour":9,"end_hour":18,"timezone":"UTC"}
