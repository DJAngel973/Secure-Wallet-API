-- FUNCTION: Auto-update updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to all tables with updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_wallets_updated_at BEFORE UPDATE ON wallets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- TRIGGER: Auto-create audit log on transaction changes
CREATE OR REPLACE FUNCTION log_transaction_status_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO transaction_history (transaction_id, old_status, new_status)
        VALUES (NEW.id, OLD.status, NEW.status);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER transaction_status_audit AFTER UPDATE ON transactions
    FOR EACH ROW EXECUTE FUNCTION log_transaction_status_change();

-- TRIGGER: Validate sufficient balance before transaction
CREATE OR REPLACE FUNCTION validate_transaction_balance()
RETURNS TRIGGER AS $$
DECLARE
    wallet_balance DECIMAL(19,4);
BEGIN
    IF NEW.transaction_type IN ('TRANSFER', 'WITHDRAWAL') AND NEW.source_wallet_id IS NOT NULL THEN
        SELECT balance INTO wallet_balance
        FROM wallets
        WHERE id = NEW.source_wallet_id AND status = 'ACTIVE'
        FOR UPDATE; -- Look to prevent race conditions

        IF wallet_balance IS NULL THEN
            RAISE EXCEPTION 'Wallet % not found or inactive', NEW.source_wallet_id;
        END IF;

        IF wallet_balance < (NEW.amount + NEW.fee) THEN
            RAISE EXCEPTION 'Insufficient balance: has %, needs %', wallet_balance, (NEW.amount + NEW.fee);
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER check_balance_before_transaction
    BEFORE INSERT ON transactions
    FOR EACH ROW EXECUTE FUNCTION validate_transaction_balance();