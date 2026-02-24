-- ENUMS - Database-level controlled values
-- user roles
CREATE TYPE user_role AS ENUM ('USER', 'ADMIN', 'MANAGER');
COMMENT ON TYPE user_role IS 'System roles: USER (client), ADMIN (superadmin), MANAGER (support)';

-- Supported currencies (ISO 4217)
CREATE TYPE currency_code AS ENUM ('USD', 'EUR', 'COP', 'MXN', 'ARS');
COMMENT ON TYPE currency_code IS 'ISO 4217 currency codes';

-- Wallet status
CREATE TYPE wallet_status AS ENUM ('ACTIVE', 'SUSPENDED', 'CLOSED');
COMMENT ON TYPE wallet_status IS 'ACTIVE=operating normally, SUSPENDED=temporarily blocked, CLOSED=permanently closed';

-- Types of transactions
CREATE TYPE transaction_type AS ENUM ('TRANSFER', 'DEPOSIT', 'WITHDRAWAL');
COMMENT ON TYPE transaction_type IS 'TRANSFER=between wallets, DEPOSIT=external income, WITHDRAWAL=external retirement';

-- Transaction states
CREATE TYPE transaction_status AS ENUM ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'REVERSED');
COMMENT ON TYPE transaction_status IS 'Cycle: PENDING -> PROCESSING -> COMPLETED/FAILED (REVERSED if it is cancelled)';

-- Severity levels for logs
CREATE TYPE log_severity AS ENUM ('INFO', 'WARNING', 'ERROR', 'CRITICAL');
COMMENT ON TYPE log_severity IS 'INFO=normal, WARNING=alert, ERROR=failed, CRITICAL=requires immediate action';

-- Auditable actions
CREATE TYPE audit_action AS ENUM (
    'USER_LOGIN',
    'USER_LOGOUT',
    'USER_REGISTER',
    'USER_UPDATE',
    'USER_DELETE',
    'WALLET_CREATE',
    'WALLET_SUSPEND',
    'WALLET_CLOSE',
    'TRANSACTION_CREATE',
    'TRANSACTION_COMPLETE',
    'TRANSACTION_FAIL',
    'PASSWORD_CHANGE',
    'PASSWORD_RESET',
    '2FA_ENABLE',
    '2FA_DISABLE'
);
COMMENT ON TYPE audit_action IS 'Actions that are recorded in the audit_logs';