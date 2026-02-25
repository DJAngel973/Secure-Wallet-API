-- Performance indices

-- Users
CREATE INDEX idx_users_email ON users(email); -- UNIQUE is already there, but it helps with searches.
CREATE INDEX idx_users_role ON users(role) WHERE is_active = TRUE; -- Partial index
CREATE INDEX idx_users_created_at ON users(created_at DESC); -- For reports

-- Wallets
CREATE INDEX idx_wallets_user_id ON wallets(user_id);
CREATE INDEX idx_wallets_status ON wallets(status);
CREATE INDEX idx_wallets_currency ON wallets(currency);
CREATE INDEX idx_wallets_balance ON wallets(balance) WHERE status = 'ACTIVE'; -- Partial index

-- Transactions
CREATE INDEX idx_transactions_source_wallet ON transactions(source_wallet_id) WHERE source_wallet_id IS NOT NULL;
CREATE INDEX idx_transactions_target_wallet ON transactions(target_wallet_id) WHERE target_wallet_id IS NOT NULL;
CREATE INDEX idx_transactions_status ON transactions(status);
CREATE INDEX idx_transactions_type ON transactions(transaction_type);
CREATE INDEX idx_transactions_created_at ON transactions(created_at DESC); -- For historical records
CREATE INDEX idx_transactions_reference ON transactions(reference_code) WHERE reference_code IS NOT NULL;
CREATE INDEX idx_transactions_user_wallet ON transactions(source_wallet_id, target_wallet_id, created_at); -- Composite index

-- Audit logs
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_severity ON audit_logs(severity_level) WHERE severity_level IN ('ERROR', 'CRITICAL');
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_details ON audit_logs USING GIN(details); -- JSONB index

-- Sessions
CREATE INDEX idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON user_sessions(expires_at) WHERE revoked = FALSE;
CREATE INDEX idx_sessions_token_hash ON user_sessions(token_hash) WHERE revoked = FALSE;