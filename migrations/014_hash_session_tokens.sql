-- Store only a SHA-256 hash of session bearer tokens, never the raw token.
-- Tokens are high-entropy, so SHA-256 (not a slow password hash) is sufficient;
-- a DB read must not disclose live, usable session tokens.
--
-- SQLite (>= 3.25) RENAME COLUMN automatically updates the UNIQUE constraint and
-- the idx_sessions_token index to reference the renamed column. The sessions
-- table is not yet wired into the JWT auth flow, so no in-place token->hash
-- backfill is required; any pre-existing rows are stale and cleared to avoid
-- leaving unhashed values behind.
DELETE FROM sessions;

ALTER TABLE sessions RENAME COLUMN token TO token_hash;
