-- Migration: add refresh_token column to users table
-- Date: 2026-03-28
-- Reason: Support JWT refresh token invalidation on logout (OWASP A07)

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS refresh_token VARCHAR(512);

-- Index for fast lookup on refresh token validation
CREATE INDEX IF NOT EXISTS idx_users_refresh_token
    ON users(refresh_token)
    WHERE refresh_token IS NOT NULL;

COMMENT ON COLUMN users.refresh_token IS
    'Active refresh token. NULL = logged out. Invalidated on logout.';