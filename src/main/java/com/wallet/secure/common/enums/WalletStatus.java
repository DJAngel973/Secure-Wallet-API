package com.wallet.secure.common.enums;

/**
 * Maps to PostgreSQL type: wallet_status
 * DB definition: ENUM ('ACTIVE', 'SUSPENDED', 'CLOSED')
 *
 * Lifecycle:
 *   ACTIVE    → wallet operates normally
 *   SUSPENDED → temporarily blocked (fraud investigation, admin action)
 *   CLOSED    → permanently closed — no new transactions allowed
 *
 * WHY no DELETE: wallets are never deleted (financial audit trail).
 * CLOSED is the terminal state.
 */
public enum WalletStatus {
    ACTIVE,
    SUSPENDED,
    CLOSED
}