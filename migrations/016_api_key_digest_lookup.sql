-- API keys are now stored as `sha256:<hex>` digests and looked up directly by
-- key_hash (the UNIQUE constraint already provides that index). Legacy Argon2
-- rows are found by (user_id, key_prefix) and rewritten to the digest form on
-- first successful use.
--
-- idx_api_keys_hash duplicated the automatic UNIQUE index on key_hash.
DROP INDEX IF EXISTS idx_api_keys_hash;
CREATE INDEX IF NOT EXISTS idx_api_keys_user_prefix ON api_keys(user_id, key_prefix);
