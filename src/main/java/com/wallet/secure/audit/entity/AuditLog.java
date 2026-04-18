package com.wallet.secure.audit.entity;

import com.wallet.secure.common.enums.AuditAction;
import com.wallet.secure.common.enums.LogSeverity;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

/**
 * Immutable record of every security-relevant event in the system.
 *
 * Maps to: audit_logs table (03-tables.sql)
 *
 * OWASP A09 — Security Logging and Monitoring Failures:
 * Every action that affects security, money, or user data MUST
 * generate an audit log entry. This table is the forensic trail
 * used to investigate incidents, fraud, and compliance audits.
 *
 * IMMUTABILITY CONTRACT:
 * Audit logs are NEVER updated or deleted — not even by ADMIN.
 * This is enforced at three levels:
 *   1. No @Setter on this entity — Lombok only generates @Getter
 *   2. No update/delete methods in AuditLogRepository
 *   3. DB-level: no UPDATE/DELETE grants on audit_logs table
 *      (configured in 04-permissions.sql)
 *
 * WHY store userId and userEmail separately:
 * If the user is deleted, the audit record still needs to
 * identify who performed the action.
 * userId → UUID reference (may become orphaned if user deleted)
 * userEmail → snapshot at time of action (permanent forensic record)
 *
 * NOTE: ddl-auto=validate — must match 03-tables.sql exactly.
 */
@Entity
@Table(name = "audit_logs")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {

    // ─── Identity ─────────────────────────────────────────────────────────────

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    // ─── Actor — who performed the action ────────────────────────────────────

    /**
     * UUID of the user who triggered this event.
     * Nullable — system-generated events have no user (e.g. scheduled jobs).
     * NOT a @ManyToOne — intentionally denormalized for audit integrity.
     * If the user is deleted, this UUID still identifies them forensically.
     */
    @Column(name = "user_id")
    private UUID userId;

    /**
     * Email snapshot at the time of the action.
     * Stored even if the user later changes their email or is deleted.
     * OWASP A09: audit records must be self-contained — no join required
     * to understand what happened.
     */
    @Column(name = "user_email", length = 255)
    private String userEmail;

    // ─── Event Classification ─────────────────────────────────────────────────

    /**
     * The specific action that occurred.
     * Maps to PostgreSQL ENUM audit_action (02-types.sql).
     * Used for filtering: "show me all USER_LOGIN events in the last 7 days"
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false, length = 50)
    private AuditAction action;

    /**
     * Business severity of this event.
     * INFO     → normal operation
     * WARNING  → suspicious activity (multiple failed logins)
     * ERROR    → operation failed (transaction failed, auth rejected)
     * CRITICAL → security incident requiring immediate investigation
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "severity_level", nullable = false, length = 20)
    private LogSeverity severityLevel;

    // ─── Context ──────────────────────────────────────────────────────────────

    /**
     * IP address of the client that triggered this event.
     * Extracted from X-Forwarded-For header (behind reverse proxy)
     * or HttpServletRequest.getRemoteAddr() directly.
     * OWASP A09: IP is essential for geographic anomaly detection.
     */
    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    /**
     * Human-readable description of what happened.
     * Example: "User logged in successfully from 192.168.1.1"
     * Example: "Transfer of 500.00 USD from wallet-A to wallet-B"
     * Free-text — provides context beyond what the action enum conveys.
     */
    @Column(name = "description", length = 500)
    private String description;

    /**
     * UUID of the resource affected by this action.
     * For USER_LOGIN → userId
     * For TRANSACTION_CREATE → transactionId
     * For WALLET_SUSPEND → walletId
     * Enables filtering: "show all events related to this transaction"
     */
    @Column(name = "resource_id")
    private UUID resourceId;

    /**
     * Type of resource affected.
     * Example: "USER", "WALLET", "TRANSACTION"
     * Paired with resourceId for cross-domain audit queries.
     */
    @Column(name = "resource_type", length = 50)
    private String resourceType;

    /**
     * Outcome of the action.
     * "SUCCESS" or "FAILURE" — simple string for easy filtering.
     * WHY not a boolean: "SUCCESS"/"FAILURE" is more readable in
     * raw SQL queries and audit reports than true/false.
     */
    @Column(name = "outcome", length = 20)
    private String outcome;

    // ─── Timestamp ────────────────────────────────────────────────────────────

    /**
     * Exact moment the event occurred — set automatically by Spring Auditing.
     * Immutable — updatable = false ensures this never changes after insert.
     * OWASP A09: tamper-evident timestamp for forensic analysis.
     */
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    // ─── Factory Methods ──────────────────────────────────────────────────────

    /**
     * Creates a SUCCESS audit log entry.
     * Used for: successful login, completed transaction, wallet created, etc.
     */
    public static AuditLog success(UUID userId, String userEmail, AuditAction action,
                                   LogSeverity severity, String description,
                                   UUID resourceId, String resourceType, String ipAddress) {
        return AuditLog.builder()
                .userId(userId)
                .userEmail(userEmail)
                .action(action)
                .severityLevel(severity)
                .description(description)
                .resourceId(resourceId)
                .resourceType(resourceType)
                .ipAddress(ipAddress)
                .outcome("SUCCESS")
                .build();
    }

    /**
     * Creates a FAILURE audit log entry.
     * Used for: failed login, rejected transaction, unauthorized access attempt.
     * OWASP A09: failures are as important as successes for security monitoring.
     */
    public static AuditLog failure(UUID userId, String userEmail, AuditAction action,
                                   LogSeverity severity, String description,
                                   UUID resourceId, String resourceType, String ipAddress) {
        return AuditLog.builder()
                .userId(userId)
                .userEmail(userEmail)
                .action(action)
                .severityLevel(severity)
                .description(description)
                .resourceId(resourceId)
                .resourceType(resourceType)
                .ipAddress(ipAddress)
                .outcome("FAILURE")
                .build();
    }
}