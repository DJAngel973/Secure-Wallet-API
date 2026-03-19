package com.wallet.secure.common.enums;

/**
 * Maps to PostgreSQL type: log_severity
 * DB definition: ENUM ('INFO', 'WARNING', 'ERROR', 'CRITICAL')
 *
 * Used in audit_logs.severity_level to classify security events.
 *
 * INFO     → normal operation event (login, transaction created)
 * WARNING  → suspicious but not confirmed (multiple failed logins)
 * ERROR    → something failed (transaction failed, auth error)
 * CRITICAL → requires immediate action (brute force detected, fraud)
 *
 * WHY separate from Log4j2 levels:
 * This is a BUSINESS severity for compliance/audit purposes.
 * Log4j2 levels (DEBUG/INFO/WARN/ERROR) are for technical logging.
 * A business CRITICAL event might only be Log4j2 WARN technically.
 */
public enum LogSeverity {
    INFO,
    WARNING,
    ERROR,
    CRITICAL
}
