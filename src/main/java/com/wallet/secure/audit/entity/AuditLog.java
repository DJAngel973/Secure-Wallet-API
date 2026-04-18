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
 * Maps to: audit_logs table

 * Why details is JSONB and not separate columns:
 * Audit events have different context depending on the action.
 * USER_LOGIN needs: email, ip, outcome
 * TRANSACTION_CREATE needs: walletId, amount, currency, outcome
 * WALLET_SUSPEND needs: walletId, adminId, reason
 * A rigid column structure would require many NULLs.
 * JSONB is flexible — each event stores exactly what it needs.
 * DB has a GIN index on details for fast JSON queries (04-index.sql).
 *
 * IMMUTABILITY CONTRACT:
 * → No @Setter — Lombok only generates @Getter
 * → No update/delete in AuditLogRepository
 * → DB: audit_logs is append-only by design (CONTEXT.md)
 *
 * OWASP A09 — Security Logging and Monitoring Failures.
 */
@Entity
@Table(name = "audit_logs")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {

    // ─── Identity

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    // ─── Actor

    /**
     * UUID of the user who triggered this event.
     * Nullable — system events have no user.
     * ON DELETE SET NULL — log is preserved even if user is deleted.
     * NOT a @ManyToOne — denormalized intentionally for audit integrity.
     */
    @Column(name = "user_id")
    private UUID userId;

    // ─── Event Classification

    /**
     * The specific action that occurred.
     * Maps to PostgreSQL ENUM audit_action (02-types.sql).
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false, length = 50)
    private AuditAction action;

    /**
     * Business severity of this event.
     * Maps to PostgreSQL ENUM log_severity (02-types.sql).
     * INFO / WARNING / ERROR / CRITICAL
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "severity_level", nullable = false, length = 20)
    @Builder.Default
    private LogSeverity severityLevel = LogSeverity.INFO;

    // ─── Context

    /**
     * Flexible JSONB payload — stores event-specific context.
     * Stored as serialized JSON string, parsed by AuditService.
     *
     * Common fields by action:
     *   USER_LOGIN:          { "email", "outcome", "reason" }
     *   TRANSACTION_CREATE:  { "walletId", "amount", "currency", "outcome" }
     *   WALLET_SUSPEND:      { "walletId", "adminId", "outcome" }
     *   PASSWORD_CHANGE:     { "email", "outcome" }
     *
     * DB has GIN index on this column → fast JSON search:
     *   SELECT * FROM audit_logs WHERE details @> '{"outcome":"FAILURE"}'
     *
     * OWASP A09: details MUST NOT contain passwords, tokens, or raw PII.
     * Safe to store: email (for identification), UUIDs, amounts, outcomes.
     */
    @Column(name = "details", columnDefinition = "jsonb")
    private String details;

    /**
     * IP address of the client — PostgreSQL INET type.
     * Mapped as String in Java — Hibernate handles INET → String conversion.
     * Supports both IPv4 and IPv6.
     * OWASP A09: essential for geographic anomaly detection and forensics.
     */
    @Column(name = "ip_address")
    private String ipAddress;

    /**
     * Browser / device identifier from the HTTP User-Agent header.
     * Example: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
     * Used for: device fingerprinting, suspicious device detection.
     * OWASP A09: device context is critical for fraud investigation.
     */
    @Column(name = "user_agent")
    private String userAgent;

    // ─── Timestamp

    /**
     * Exact moment the event occurred.
     * Set automatically by AuditingEntityListener — never set manually.
     * updatable = false — cannot be changed after insert.
     */
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    // ─── Factory Methods

    /**
     * Creates a SUCCESS audit log with JSONB details.
     *
     * @param userId     actor UUID (null for system events)
     * @param action     what happened
     * @param severity   business severity
     * @param details    JSON string with event-specific context
     * @param ipAddress  client IP
     * @param userAgent  client browser/device
     */
    public static AuditLog success(UUID userId, AuditAction action, LogSeverity severity,
                                   String details, String ipAddress, String userAgent) {
        return AuditLog.builder()
                .userId(userId)
                .action(action)
                .severityLevel(severity)
                .details(details)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();
    }

    /**
     * Creates a FAILURE audit log with JSONB details.
     * OWASP A09: failures are as important as successes for security monitoring.
     */
    public static AuditLog failure(UUID userId, AuditAction action, LogSeverity severity,
                                   String details, String ipAddress, String userAgent) {
        return AuditLog.builder()
                .userId(userId)
                .action(action)
                .severityLevel(severity)
                .details(details)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();
    }
}