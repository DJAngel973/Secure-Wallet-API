package com.wallet.secure.audit.repository;

import com.wallet.secure.audit.entity.AuditLog;
import com.wallet.secure.common.enums.AuditAction;
import com.wallet.secure.common.enums.LogSeverity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Data access layer for audit logs.
 *
 * REAL DB COLUMNS available for filtering:
 *   user_id, action, severity_level, ip_address, user_agent, created_at
 *
 * WHAT IS NOT A COLUMN (lives inside details JSONB):
 *   outcome, email, resourceId, resourceType, description
 *   → These require native SQL with PostgreSQL JSONB operators
 *   → JPQL cannot query inside JSONB — native queries required
 *
 * IMMUTABILITY ENFORCEMENT:
 * This repository is append-only by contract.
 * save() is called exclusively by AuditService for INSERT operations.
 * No business code ever updates or deletes an audit log.
 *
 * OWASP A09: audit logs must be tamper-evident.
 * Deleting or modifying logs would constitute evidence tampering.
 */
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    // ─── Standard Column Queries — JPQL

    /**
     * Returns all audit events for a specific user — paginated.
     * Used by: GET /audit/users/{userId} (ADMIN only)
     * Full activity reconstruction for forensic investigation.
     * OWASP A09: supports incident response for compromised accounts.
     */
    Page<AuditLog> findByUserIdOrderByCreatedAtDesc(UUID userId, Pageable pageable);

    /**
     * Returns all events for a specific action type — paginated.
     * Used by: GET /audit?action=USER_LOGIN
     * Example: "show all USER_LOGIN events in the last 24 hours"
     */
    Page<AuditLog> findByActionOrderByCreatedAtDesc(AuditAction action, Pageable pageable);

    /**
     * Returns all events at a specific severity level — paginated.
     * Used by: GET /audit?severity=CRITICAL (security monitoring dashboard)
     */
    Page<AuditLog> findBySeverityLevelOrderByCreatedAtDesc(LogSeverity severityLevel, Pageable pageable);

    /**
     * Returns all events within a time window — paginated.
     * Used by: GET /audit?from=2026-01-01&to=2026-01-31 (monthly audit report)
     * Essential for compliance reporting (SOC2, PCI-DSS).
     */
    Page<AuditLog> findByCreatedAtBetweenOrderByCreatedAtDesc(
            Instant from, Instant to, Pageable pageable);

    /**
     * Returns all events from a specific IP address — paginated.
     * Used by: GET /audit?ip=192.168.1.1 (suspicious IP investigation)
     * OWASP A09: IP-based filtering is critical for attack source identification.
     *
     * WHY CAST(a.ipAddress AS string):
     * Hibernate maps INET as String in Java but PostgreSQL stores it as INET.
     * The cast ensures the comparison works correctly across both layers.
     */
    @Query("SELECT a FROM AuditLog a WHERE CAST(a.ipAddress AS string) = :ipAddress ORDER BY a.createdAt DESC")
    Page<AuditLog> findByIpAddressOrderByCreatedAtDesc(
            @Param("ipAddress") String ipAddress, Pageable pageable);

    // ─── JSONB Queries — Native SQL ��──────────────────────────────────────────

    /**
     * Returns FAILURE events for a user within a time window.
     * Uses PostgreSQL JSONB operator @> to query inside details column.
     *
     * WHY native SQL and not JPQL:
     * JPQL has no support for JSONB operators (@>, ->>, etc.).
     * Native SQL is required to query inside the details JSONB column.
     *
     * Used by: brute force detection in AuditService.
     * If a user has >= 3 failures in 15 minutes → CRITICAL severity alert.
     * OWASP A09: failure patterns must be detectable in real time.
     */
    @Query(value = "SELECT * FROM audit_logs WHERE user_id = :userId AND details @> '{\"outcome\":\"FAILURE\"}' AND created_at >= :since ORDER BY created_at DESC", nativeQuery = true)
    List<AuditLog> findRecentFailuresByUserId(
            @Param("userId") UUID userId,
            @Param("since") Instant since);

    /**
     * Counts failed login attempts for a user since a given time.
     * Lightweight version of findRecentFailuresByUserId — returns count only.
     *
     * Used by: AuditService.countRecentFailedLogins()
     * Called after every failed login to decide if lockout threshold is reached.
     * More efficient than loading the full list just to count.
     */
    @Query(value = "SELECT COUNT(*) FROM audit_logs WHERE user_id = :userId AND action = 'USER_LOGIN' AND details @> '{\"outcome\":\"FAILURE\"}' AND created_at >= :since", nativeQuery = true)
    long countFailedLoginsSince(
            @Param("userId") UUID userId,
            @Param("since") Instant since);

    /**
     * Returns all CRITICAL severity events since a given time.
     * Used by: security monitoring — alerts on CRITICAL events.
     * A CRITICAL event (brute force detected, fraud pattern) must trigger
     * an immediate notification to the security team.
     * OWASP A09: detection without alerting is useless.
     */
    @Query("SELECT a FROM AuditLog a WHERE a.severityLevel = com.wallet.secure.common.enums.LogSeverity.CRITICAL AND a.createdAt >= :since ORDER BY a.createdAt DESC")
    List<AuditLog> findCriticalEventsSince(@Param("since") Instant since);

    /**
     * Returns all events for a user filtered by action — paginated.
     * Used by: GET /audit/users/{userId}?action=TRANSACTION_CREATE
     * Enables focused investigation: "show only transactions for this user"
     */
    Page<AuditLog> findByUserIdAndActionOrderByCreatedAtDesc(
            UUID userId, AuditAction action, Pageable pageable);

    /**
     * Returns all events for a user within a time window — paginated.
     * Used by: GET /audit/users/{userId}?from=...&to=...
     * Enables: "show all activity of user X during this incident window"
     */
    Page<AuditLog> findByUserIdAndCreatedAtBetweenOrderByCreatedAtDesc(
            UUID userId, Instant from, Instant to, Pageable pageable);
}