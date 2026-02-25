-- FUNCTION: Process transaction (ACID guaranteed)
CREATE OR REPLACE FUNCTION process_transaction(
    p_transaction_id UUID
) RETURNS BOOLEAN AS $$
DECLARE
    v_transaction RECORD;
    v_source_balance DECIMAL(19,4);
    v_target_balance DECIMAL(19,4);
BEGIN
    -- Get transaction with lock
    SELECT * INTO v_transaction
    FROM transactions
    WHERE id = p_transaction_id AND status = 'PENDING'
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction % not found or not pending', p_transaction_id;
    END IF;

    -- Update status to PROCESSING
    UPDATE transactions SET status = 'PROCESSING' WHERE id = p_transaction_id;

    BEGIN
        -- WITHDRAWAL or TRANSFER: discount from source
        IF v_transaction.source_wallet_id IS NOT NULL THEN
            UPDATE wallets
            SET balance = balance - (v_transaction.amount + v_transaction.fee)
            WHERE id = v_transaction.source_wallet_id AND status = 'ACTIVE';

            IF NOT FOUND THEN
                RAISE EXCEPTION 'Source wallet not found or inactive';
            END IF;
        END IF;

        -- DEPOSIT or TRANSFER: add to target
        IF v_transaction.target_wallet_id IS NOT NULL THEN
            UPDATE wallets
            SET balance = balance + v_transaction.amount
            WHERE id = v_transaction.target_wallet_id AND status = 'ACTIVE';

            IF NOT FOUND THEN
                RAISE EXCEPTION 'Target wallet not found or inactive';
            END IF;
        END IF;

        -- Mark as completed
        UPDATE transactions
        SET status = 'COMPLETED', completed_at = CURRENT_TIMESTAMP
        WHERE id = p_transaction_id;

        RETURN TRUE;

    EXCEPTION WHEN OTHERS THEN
        -- Automatic rollback + mark as failed
        UPDATE transactions
        SET status = 'FAILED', completed_at = CURRENT_TIMESTAMP
        WHERE id = p_transaction_id;

        RAISE NOTICE 'Transaction failed: %', SQLERRM;
        RETURN FALSE;
    END;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION process_transaction IS 'Process ACID-guaranteed transactions - call from Spring @Transactional';

-- FUNCTION: Clean expired sessions (CRON JOB)
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    v_deleted_count INTEGER;
BEGIN
    DELETE FROM user_sessions
    WHERE expires_at < CURRENT_TIMESTAMP AND revoked = FALSE;

    GET DIAGNOSTICS v_deleted_count = ROW_COUNT;
    RETURN v_deleted_count;
END;
$$ LANGUAGE plpgsql;