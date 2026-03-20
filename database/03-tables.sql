-- Table: users
-- User management with advanced security
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role user_role NOT NULL DEFAULT 'USER',
    is_active BOOLEAN DEFAULT TRUE,
    failed_login_attempts INT DEFAULT 0 CHECK (failed_login_attempts >= 0 AND failed_login_attempts <= 3),
    locked_until TIMESTAMP,
    email_verified BOOLEAN DEFAULT FALSE,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret TEXT, -- Encrypted by pgcrypto
    last_login_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT password_not_empty CHECK (LENGTH(password_hash) > 12)
);

COMMENT ON TABLE users IS 'System users with 2FA authentication and lock control';
COMMENT ON COLUMN users.password_hash IS 'BCrypt hash - NEVER store passwords in plain text';
COMMENT ON COLUMN users.locked_until IS 'NULL = unlocked, TIMESTAMP = unlocked until that date';
COMMENT ON COLUMN users.two_factor_secret IS 'Base32 secret for TOTP (Google authenticator)';

-- Table: wallets
-- Multi-currency digital wallets
CREATE TABLE wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    balance DECIMAL(19,4) DEFAULT 0 CHECK (balance >= 0),
    currency currency_code NOT NULL DEFAULT 'USD',
    status wallet_status NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_user_currency UNIQUE(user_id, currency),
    CONSTRAINT balance_limit CHECK (balance <= 999999999999999.9999)
);

COMMENT ON TABLE wallets IS 'A user can have multiple wallets (one per currency)';
COMMENT ON COLUMN wallets.balance IS 'DECIMAL(19,4) it supports up to 15 whole digits + 4 decimal places';

-- Table: transactions
-- History of all transactions
CREATE TABLE transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_wallet_id UUID REFERENCES wallets(id) ON DELETE RESTRICT, -- Prevents accidental deletion
    target_wallet_id UUID REFERENCES wallets(id) ON DELETE RESTRICT,
    amount DECIMAL(19,4) NOT NULL CHECK (amount > 0),
    transaction_type transaction_type NOT NULL,
    status transaction_status NOT NULL DEFAULT 'PENDING',
    description TEXT,
    reference_code VARCHAR(100) UNIQUE, -- For external tracking (PSE, PayPal, etc.)
    fee DECIMAL(19,4) DEFAULT 0 CHECK (fee >= 0),
    currency currency_code NOT NULL,
    metadata JSONB, -- Additional data (IP, device, etc.)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    CHECK (source_wallet_id IS NOT NULL OR target_wallet_id IS NOT NULL),
    CHECK (source_wallet_id IS DISTINCT FROM target_wallet_id),
    CHECK (
        (transaction_type = 'DEPOSIT' AND source_wallet_id IS NULL AND target_wallet_id IS NOT NULL) OR
        (transaction_type = 'WITHDRAWAL' AND source_wallet_id IS NOT NULL AND target_wallet_id IS NULL) OR
        (transaction_type = 'TRANSFER' AND source_wallet_id IS NOT NULL AND target_wallet_id IS NOT NULL)
    )
);

COMMENT ON TABLE transactions IS 'All system transactions(are never deleted)';
COMMENT ON COLUMN transactions.reference_code IS 'External ID for reconciliation with payment gateways';
COMMENT ON COLUMN transactions.metadata IS 'JSONB for flexible data:{ip, device, geolocation}';
COMMENT ON CONSTRAINT transactions_check ON transactions IS 'Validate consistency: DEPOSIT target only, WITHDRAWAL source only, TRANSFER both';

-- Table: audit_logs
-- Audit log (COMPLIANCE)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL, -- It retains the log even if you delete the user
    action audit_action NOT NULL,
    details JSONB,
    ip_address INET, -- Specific type for IPs
    user_agent TEXT,
    severity_level log_severity NOT NULL DEFAULT 'INFO',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE audit_logs IS 'NEVER delete - required for compliance and legal audits';
COMMENT ON COLUMN audit_logs.details IS 'JSONB allows searches: details @>{"email":"test@test.com"}';

-- Table: user_sessions
-- JWT session management (allows revocation)
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    CHECK (expires_at > created_at),
    CHECK (revoked = FALSE OR revoked_at IS NOT NULL)
);

COMMENT ON TABLE user_sessions IS 'It allows invalidating JWT tokens before their natural expiration';
COMMENT ON COLUMN user_sessions.token_hash IS 'SHA-256 of the JWT - never store tokens in plain text';

-- Table: transaction_history (STATE TRACKING)
-- Auditing status changes in transactions
CREATE TABLE transaction_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    old_status transaction_status,
    new_status transaction_status NOT NULL,
    changed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reason TEXT, -- Why did it change (ej: "Reversed by admin due to fraud")
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CHECK (old_status IS DISTINCT FROM new_status)
);

COMMENT ON TABLE transaction_history IS 'Complete history of transaction status changes';

CREATE INDEX idx_transaction_history_transaction ON transaction_history(transaction_id);