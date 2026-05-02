package com.wallet.secure.audit.service;

import com.wallet.secure.audit.entity.AuditLog;
import com.wallet.secure.audit.repository.AuditLogRepository;
import com.wallet.secure.common.enums.AuditAction;
import com.wallet.secure.common.enums.LogSeverity;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * Centralized service for writing security audit logs.
 * DESIGN DECISIONS:
 * 1. WHY @Async on log methods:
 *    Writing an audit log must NEVER slow down a financial transaction.
 *    If the audit DB write takes 50ms, the user's transfer should not wait.
 *    @Async runs the log write in a separate thread from Spring's task executor.
 *    The transaction completes immediately — the audit write happens in background.
 * 2. WHY Propagation.REQUIRES_NEW on log methods:
 *    If a transaction fails and rolls back (e.g. insufficient balance),
 *    the FAILURE audit log must still be saved — it cannot roll back with the
 *    parent transaction or we lose the forensic record.
 *    REQUIRES_NEW opens a completely independent transaction for the audit write.
 *    Parent transaction rolls back → audit log transaction commits independently. ✅
 * 3. WHY details is a manually built JSON String and not a Map/Object:
 *    Avoids Jackson dependency in this service layer.
 *    JSONB in PostgreSQL accepts any valid JSON string.
 *    AuditLogResponse.fromEntity() can parse it back when needed.
 *    Simple, no serialization overhead.
 * 4. WHY this service does NOT read audit logs:
 *    Reading is separated into AuditController → AuditLogRepository directly.
 *    AuditService has a single responsibility: WRITE audit events.
 *    This prevents the service from growing into a god class.
 * OWASP A09 — Security Logging and Monitoring Failures:
 * Every call to this service creates a tamper-evident forensic record.
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    // ─── Authentication Events

    /**
     * Logs a successful login.
     * Called by AuthService.login() after tokens are generated.
     *
     * @param userId    authenticated user's UUID
     * @param email     user's email (snapshot — stored in JSONB)
     * @param ipAddress client IP from HttpServletRequest
     * @param userAgent browser/device string from User-Agent header
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logLoginSuccess(UUID userId, String email, String ipAddress, String userAgent) {
        String details = buildDetails(
                "\"email\":\"" + email + "\"",
                "\"outcome\":\"SUCCESS\""
        );
        save(AuditLog.success(userId, AuditAction.USER_LOGIN, LogSeverity.INFO,
                details, ipAddress, userAgent));
    }

    /**
     * Logs a failed login attempt.
     * Called by AuthService when BadCredentialsException or LockedException is caught.
     * OWASP A09: failed logins are the primary signal for brute force detection.
     *
     * @param userId    null if user doesn't exist (prevents leaking existence)
     * @param email     attempted email
     * @param reason    "Bad credentials" or "Account locked"
     * @param ipAddress client IP
     * @param userAgent browser/device string
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logLoginFailure(UUID userId, String email, String reason,
                                String ipAddress, String userAgent) {
        String details = buildDetails(
                "\"email\":\"" + email + "\"",
                "\"outcome\":\"FAILURE\"",
                "\"reason\":\"" + reason + "\""
        );
        save(AuditLog.failure(userId, AuditAction.USER_LOGIN, LogSeverity.WARNING,
                details, ipAddress, userAgent));
    }

    /**
     * Logs a successful logout.
     * Called by AuthService.logout() after refresh token is revoked.
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logLogout(UUID userId, String email, String ipAddress, String userAgent) {
        String details = buildDetails(
                "\"email\":\"" + email + "\"",
                "\"outcome\":\"SUCCESS\""
        );
        save(AuditLog.success(userId, AuditAction.USER_LOGOUT, LogSeverity.INFO,
                details, ipAddress, userAgent));
    }

    /**
     * Logs a new user registration.
     * Called by AuthService.register() after user is created.
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logRegister(UUID userId, String email, String ipAddress, String userAgent) {
        String details = buildDetails(
                "\"email\":\"" + email + "\"",
                "\"outcome\":\"SUCCESS\""
        );
        save(AuditLog.success(userId, AuditAction.USER_REGISTER, LogSeverity.INFO,
                details, ipAddress, userAgent));
    }

    // ─── Transaction Events

    /**
     * Logs a completed financial transaction.
     * Called by TransactionService after COMPLETED status is set.
     * OWASP A09: every money movement must have a forensic record.
     *
     * @param userId          actor (sender for TRANSFER/WITHDRAWAL, receiver for DEPOSIT)
     * @param transactionId   UUID of the Transaction record
     * @param type            DEPOSIT, WITHDRAWAL, or TRANSFER
     * @param amount          amount moved
     * @param currency        currency code
     * @param ipAddress       client IP
     * @param userAgent       browser/device string
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logTransactionSuccess(UUID userId, UUID transactionId, String type,
                                      String amount, String currency,
                                      String ipAddress, String userAgent) {
        String details = buildDetails(
                "\"transactionId\":\"" + transactionId + "\"",
                "\"type\":\"" + type + "\"",
                "\"amount\":\"" + amount + "\"",
                "\"currency\":\"" + currency + "\"",
                "\"outcome\":\"SUCCESS\""
        );
        save(AuditLog.success(userId, AuditAction.TRANSACTION_COMPLETE, LogSeverity.INFO,
                details, ipAddress, userAgent));
    }

    /**
     * Logs a failed financial transaction.
     * Called by TransactionService in the catch block before rethrowing.
     * OWASP A09: failures are as important as successes — fraud often shows
     * as repeated failures before a successful attack.
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logTransactionFailure(UUID userId, String type, String reason,
                                      String ipAddress, String userAgent) {
        String details = buildDetails(
                "\"type\":\"" + type + "\"",
                "\"outcome\":\"FAILURE\"",
                "\"reason\":\"" + reason + "\""
        );
        save(AuditLog.failure(userId, AuditAction.TRANSACTION_FAIL, LogSeverity.ERROR,
                details, ipAddress, userAgent));
    }

    // ─── Wallet Events

    /**
     * Logs a wallet creation.
     * Called by WalletService.createWallet() after successful save.
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logWalletCreated(UUID userId, UUID walletId, String currency,
                                 String ipAddress, String userAgent) {
        String details = buildDetails(
                "\"walletId\":\"" + walletId + "\"",
                "\"currency\":\"" + currency + "\"",
                "\"outcome\":\"SUCCESS\""
        );
        save(AuditLog.success(userId, AuditAction.WALLET_CREATE, LogSeverity.INFO,
                details, ipAddress, userAgent));
    }

    /**
     * Logs a wallet suspension — ADMIN action.
     * Called by WalletService.suspendWallet().
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logWalletSuspended(UUID adminId, UUID walletId,
                                   String ipAddress, String userAgent) {
        String details = buildDetails(
                "\"walletId\":\"" + walletId + "\"",
                "\"adminId\":\"" + adminId + "\"",
                "\"outcome\":\"SUCCESS\""
        );
        save(AuditLog.success(adminId, AuditAction.WALLET_SUSPEND, LogSeverity.WARNING,
                details, ipAddress, userAgent));
    }

    /**
     * Logs a permanent wallet closure — ADMIN action.
     * Called by WalletService.closeWallet().
     * WARNING severity — permanent and irreversible.
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logWalletClosed(UUID adminId, UUID walletId,
                                String ipAddress, String userAgent) {
        String details = buildDetails(
                "\"walletId\":\"" + walletId + "\"",
                "\"adminId\":\"" + adminId + "\"",
                "\"outcome\":\"SUCCESS\""
        );
        save(AuditLog.success(adminId, AuditAction.WALLET_CLOSE, LogSeverity.WARNING,
                details, ipAddress, userAgent));
    }

    /**
     * Logs a wallet restoration from SUSPENDED to ACTIVE — ADMIN action.
     * Called by WalletService.restoreWallet().
     * WHY this needs its own audit entry: restoring a wallet re-enables all
     * financial operations on it. That is a security-relevant state change
     * that must be traceable to the admin who performed it.
     * OWASP A09: all wallet state changes by admins must be logged.
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logWalletRestored(UUID adminId, UUID walletId,
                                  String ipAddress, String userAgent) {
        String details = buildDetails(
                "\"walletId\":\"" + walletId + "\"",
                "\"adminId\":\"" + adminId + "\"",
                "\"outcome\":\"SUCCESS\""
        );
        save(AuditLog.success(adminId, AuditAction.WALLET_RESTORE, LogSeverity.WARNING,
                details, ipAddress, userAgent));
    }

    // ─── Security Events

    /**
     * Logs a password change.
     * Called by UserService.updateProfile() when password is updated.
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logPasswordChange(UUID userId, String email,
                                  String ipAddress, String userAgent) {
        String details = buildDetails(
                "\"email\":\"" + email + "\"",
                "\"outcome\":\"SUCCESS\""
        );
        save(AuditLog.success(userId, AuditAction.PASSWORD_CHANGE, LogSeverity.WARNING,
                details, ipAddress, userAgent));
    }

    /**
     * Logs a CRITICAL security event — brute force, fraud pattern, etc.
     * Called when suspicious activity threshold is exceeded.
     * OWASP A09: CRITICAL events must trigger immediate alerts.
     * In production: this would also fire a PagerDuty/Slack notification.
     *
     * @param userId    suspect user UUID
     * @param reason    description of why it is critical
     * @param ipAddress attacker's IP
     * @param userAgent attacker's device
     */
    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logCriticalSecurityEvent(UUID userId, String reason,
                                         String ipAddress, String userAgent) {
        String details = buildDetails(
                "\"reason\":\"" + reason + "\"",
                "\"outcome\":\"FAILURE\""
        );
        AuditLog auditLog = AuditLog.failure(userId, AuditAction.USER_LOGIN,
                LogSeverity.CRITICAL, details, ipAddress, userAgent);
        save(auditLog);

        // Technical log at ERROR level — also captured by Log4j2 appenders
        // In production: Log4j2 appenders forward CRITICAL logs to SIEM
        log.error("CRITICAL SECURITY EVENT: userId={} reason={} ip={}",
                userId, reason, ipAddress);
    }

    // ─── Brute Force Detection

    /**
     * Returns the count of failed logins for a user in the last N minutes.
     * Called by AuthService after each failed login attempt.
     * If count >= threshold → logCriticalSecurityEvent() is triggered.
     * WHY in AuditService and not AuthService:
     * AuditService owns the audit data — it knows how to query it.
     * AuthService owns the lockout logic — it decides what to do with the count.
     * Clear separation of responsibilities.
     *
     * @param userId        user to check
     * @param withinMinutes time window in minutes
     * @return count of failed login audit entries
     */
    @Transactional(readOnly = true)
    public long countRecentFailedLogins(UUID userId, int withinMinutes) {
        Instant since = Instant.now().minusSeconds((long) withinMinutes * 60);
        return auditLogRepository.countFailedLoginsSince(userId, since);
    }

    // ─── Private Helpers

    /**
     * Persists the audit log entry.
     * Catches all exceptions — a logging failure must NEVER crash the application.
     * If the audit DB is down, the business operation still succeeds.
     * The failure is logged to Log4j2 file appender as fallback.
     * OWASP A09: best-effort logging — degraded logging is better than no service.
     */
    private void save(AuditLog auditLog) {
        try {
            auditLogRepository.save(auditLog);
        } catch (Exception e) {
            // Fallback: write to Log4j2 file — at least we have a record
            log.error("AUDIT LOG WRITE FAILED — falling back to file log: action={} userId={} details={} error={}",
                    auditLog.getAction(),
                    auditLog.getUserId(),
                    auditLog.getDetails(),
                    e.getMessage());
        }
    }

    /**
     * Builds a JSON object string from key-value pairs.
     * Each entry must already be formatted as: "key":"value"
     * Example:
     * buildDetails("\"email\":\"a@b.com\"", "\"outcome\":\"SUCCESS\"")
     * → {"email":"a@b.com","outcome":"SUCCESS"}
     * WHY not use ObjectMapper:
     * Avoids Jackson dependency in the service layer.
     * These are simple flat JSON objects — no nesting, no arrays.
     * String concatenation is sufficient and faster for this use case.
     */
    private String buildDetails(String... keyValuePairs) {
        return "{" + String.join(",", keyValuePairs) + "}";
    }
}