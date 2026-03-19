package com.wallet.secure.common.enums;

/**
 * Maps to PostgreSQL type: transaction_status
 * DB definition: ENUM ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'REVERSED')
 *
 * Lifecycle:
 *   PENDING    → created, not yet processed
 *   PROCESSING → being processed (prevents double execution — optimistic lock)
 *   COMPLETED  → funds successfully moved
 *   FAILED     → error during processing, funds NOT moved or already returned
 *   REVERSED   → completed but reversed (fraud, admin correction, chargeback)
 *
 * WHY PROCESSING state exists:
 * Prevents race conditions. While a transaction is PROCESSING,
 * no other transaction can modify the same wallets concurrently.
 *
 * WHY no CANCELLED:
 * Your DB uses REVERSED for rollbacks. CANCELLED is not in the DB enum.
 * Adding it here without adding it to PostgreSQL would cause Hibernate
 * validation to FAIL on startup (ddl-auto: validate).
 */
public enum TransactionStatus {
    PENDING,
    PROCESSING,
    COMPLETED,
    FAILED,
    REVERSED
}