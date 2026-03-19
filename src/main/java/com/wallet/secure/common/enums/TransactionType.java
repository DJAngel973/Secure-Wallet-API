package com.wallet.secure.common.enums;

/**
 * Maps to PostgreSQL type: transaction_type
 * DB definition: ENUM ('TRANSFER', 'DEPOSIT', 'WITHDRAWAL')
 *
 * Business rules (enforced also by DB CHECK constraints):
 *   DEPOSIT    → source_wallet_id IS NULL,  target_wallet_id NOT NULL
 *   WITHDRAWAL → source_wallet_id NOT NULL, target_wallet_id IS NULL
 *   TRANSFER   → source_wallet_id NOT NULL, target_wallet_id NOT NULL
 *
 * WHY this matters in code:
 * TransactionService must validate these rules BEFORE calling the DB.
 * Defense in depth: validated at app level AND enforced at DB level.
 */
public enum TransactionType {
    TRANSFER,
    DEPOSIT,
    WITHDRAWAL
}