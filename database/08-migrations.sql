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

-- Migration: add WALLET_RESTORE to audit_action enum
-- Date: 2026-05-02
-- Reason: restoreWallet() is an ADMIN action and must be auditable (OWASP A09).
--         All other wallet admin ops (suspend, close) already have their own action.
--         Using ALTER TYPE ... ADD VALUE because PostgreSQL enums are append-only.

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'WALLET_RESTORE';