package com.wallet.secure.common.enums;

/**
 * Maps to PostgreSQL type: audit_action
 * DB definition: all values listed below.
 *
 * OWASP A09 - Security Logging and Monitoring Failures:
 * Every security-relevant event MUST be logged with one of these actions.
 * This enum is the contract between the application and the audit_logs table.
 *
 * Naming convention: [DOMAIN]_[ACTION]
 * This makes it easy to filter logs by domain in queries:
 *   SELECT * FROM audit_logs WHERE action::text LIKE 'USER_%';
 */
public enum AuditAction {

    // User lifecycle
    USER_LOGIN,
    USER_LOGOUT,
    USER_REGISTER,
    USER_UPDATE,
    USER_DELETE,

    // Wallet lifecycle
    WALLET_CREATE,
    WALLET_SUSPEND,
    WALLET_CLOSE,
    WALLET_RESTORE,

    // Transaction lifecycle
    TRANSACTION_CREATE,
    TRANSACTION_COMPLETE,
    TRANSACTION_FAIL,

    // Security — credential management
    PASSWORD_CHANGE,
    PASSWORD_RESET,

    // Security — 2FA management
    TWO_FA_ENABLE,    // Maps to DB: '2FA_ENABLE'
    TWO_FA_DISABLE    // Maps to DB: '2FA_DISABLE'
}