-- Migration: remove raw refresh_token from users
-- Date: 2026-10-25
-- Reason: user_sessions.token_hash is the single source of truth. A raw JWT
--          must never be stored because a database disclosure could reuse it.
-- OWASP A02/A07: revoke sessions by SHA-256 hash, not by a reusable token.

DROP INDEX IF EXISTS idx_users_refresh_token;

ALTER TABLE users
    DROP COLUMN IF EXISTS refresh_token;

-- Migration: add WALLET_RESTORE to audit_action enum
-- Date: 2026-05-02
-- Reason: restoreWallet() is an ADMIN action and must be auditable (OWASP A09).
--         All other wallet admin ops (suspend, close) already have their own action.
--         Using ALTER TYPE ... ADD VALUE because PostgreSQL enums are append-only.

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'WALLET_RESTORE';

-- Migration: audit refresh-token rotation and replay attempts
-- Date: 2026-10-27
-- OWASP A07/A09: a consumed refresh token presented again is a security signal.
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'TOKEN_REFRESH';
