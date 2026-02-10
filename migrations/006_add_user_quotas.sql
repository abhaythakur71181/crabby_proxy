-- Add quota columns to users table

ALTER TABLE users ADD COLUMN daily_bandwidth_quota INTEGER DEFAULT NULL;
ALTER TABLE users ADD COLUMN monthly_bandwidth_quota INTEGER DEFAULT NULL;
ALTER TABLE users ADD COLUMN max_concurrent_connections INTEGER DEFAULT 10;

-- Create index for quota checks
CREATE INDEX IF NOT EXISTS idx_users_quotas ON users(daily_bandwidth_quota, monthly_bandwidth_quota);
