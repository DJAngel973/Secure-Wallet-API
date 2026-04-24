package com.wallet.secure.audit.controller;

import com.wallet.secure.audit.dto.AuditLogResponse;
import com.wallet.secure.audit.repository.AuditLogRepository;
import com.wallet.secure.common.enums.AuditAction;
import com.wallet.secure.common.enums.LogSeverity;
import com.wallet.secure.common.response.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

/**
 * REST Controller for audit log read operations — ADMIN only.
 *
 * Base path: /audit
 * ALL endpoints require ADMIN role — @PreAuthorize("hasRole('ADMIN')")
 * Regular users NEVER access audit logs — not even their own.
 *
 * WHY controller calls repository directly (no AuditService read methods):
 * AuditService is write-only by design — single responsibility.
 * These are simple paginated reads with no business logic.
 * Adding a read layer in AuditService would be boilerplate with no value.
 *
 * Endpoint summary:
 * GET /audit                          → all logs paginated
 * GET /audit/users/{userId}           → logs for a specific user
 * GET /audit/action/{action}          → logs filtered by action type
 * GET /audit/severity/{severity}      → logs filtered by severity
 * GET /audit/ip/{ipAddress}           → logs from a specific IP
 * GET /audit/range                    → logs within a date range
 * GET /audit/critical                 → recent CRITICAL events (last 24h)
 * GET /audit/users/{userId}/failures  → recent failures for a user
 *
 * OWASP A01: @PreAuthorize evaluated BEFORE method execution.
 * Non-ADMIN → 403 immediately, no data is ever loaded.
 * OWASP A09: reading audit logs is itself audited (logged by Spring Security).
 */
@RestController
@RequestMapping("/audit")
@RequiredArgsConstructor
@Log4j2
@Tag(name = "7. Audit Logs", description = "Security audit trail — ADMIN only")
@PreAuthorize("hasRole('ADMIN')")
public class AuditController {

    private final AuditLogRepository auditLogRepository;

    // -- General Queries

    /**
     * GET /audit
     * Returns all audit logs - paginated, most recent first.
     * Default page size: 50 (audit dashboards show more rows than user UIs)
     * OWASP A09: provides full system activity visibility to admins
     */
    @GetMapping
    public ResponseEntity<ApiResponse<Page<AuditLogResponse>>> getAllLogs(@PageableDefault(size = 50) Pageable pageable) {

        Page<AuditLogResponse> page = auditLogRepository
                .findAll(pageable)
                .map(AuditLogResponse::fromEntity);

        return ResponseEntity.ok(ApiResponse.ok("Audit logs retrieved", page));
    }

    /**
     * GET /audit/users/{userId}
     * Returns all audit events for a specific user - paginated
     * Use case: "Show me everything user X has done in the system"
     * Forensic investigation of a compromised or suspicious account.
     */
    @GetMapping("/users/{userId}")
    public ResponseEntity<ApiResponse<Page<AuditLogResponse>>> getLogsByUser(@PathVariable UUID userId, @PageableDefault(size = 50) Pageable pageable) {

        Page<AuditLogResponse> page = auditLogRepository
                .findByUserIdOrderByCreatedAtDesc(userId, pageable)
                .map(AuditLogResponse::fromEntity);

        return ResponseEntity.ok(ApiResponse.ok("User audit logs retrieved", page));
    }

    /**
     * GET /audit/action/{action}
     * Returns all events for a specific action type - paginated
     * Use case: "Show me all USER_LOGIN events" or "all TRANSACTION_FAIL events"
     * Example: GET /audit/action/USER_LOGIN
     */
    @GetMapping("/action/{action}")
    public ResponseEntity<ApiResponse<Page<AuditLogResponse>>> getLogsByAction(@PathVariable AuditAction action, @PageableDefault(size = 50) Pageable pageable) {

        Page<AuditLogResponse> page = auditLogRepository
                .findByActionOrderByCreatedAtDesc(action, pageable)
                .map(AuditLogResponse::fromEntity);

        return ResponseEntity.ok(ApiResponse.ok("Audit logs by action retrieved", page));
    }

    /**
     * GET /audit/severity/{severity}
     * Returns all events at a specific severity level - paginated
     * Use case: "Show me all WARNING and CRITICAL events"
     * Example: GET /audit/severity/CRITICAL
     */
    @GetMapping("/severity/{severity}")
    public ResponseEntity<ApiResponse<Page<AuditLogResponse>>> getLogsBySeverity(@PathVariable LogSeverity severity, @PageableDefault(size = 50) Pageable pageable) {

        Page<AuditLogResponse> page = auditLogRepository
                .findBySeverityLevelOrderByCreatedAtDesc(severity, pageable)
                .map(AuditLogResponse::fromEntity);

        return ResponseEntity.ok(ApiResponse.ok("Audit logs by severity retrieved", page));
    }

    /**
     * GET /audit/ip/{ipAddress}
     * Returns all events originating from a specific IP address — paginated.
     *
     * Use case: "Show me everything that came from this suspicious IP"
     * Critical for identifying the scope of an attack from one source.
     * Example: GET /audit/ip/192.168.1.100
     *
     * WHY @PathVariable and not @RequestParam:
     * IP addresses in query params can be confused with dots in routing.
     * Path variable is safer: /audit/ip/192.168.1.100
     */
    @GetMapping("/ip/{ipAddress}")
    public ResponseEntity<ApiResponse<Page<AuditLogResponse>>> getLogsByIp(
            @PathVariable String ipAddress,
            @PageableDefault(size = 50) Pageable pageable) {

        Page<AuditLogResponse> page = auditLogRepository
                .findByIpAddressOrderByCreatedAtDesc(ipAddress, pageable)
                .map(AuditLogResponse::fromEntity);

        return ResponseEntity.ok(ApiResponse.ok("Audit logs by IP retrieved", page));
    }

    /**
     * GET /audit/range?from=2026-01-01&to=2026-01-31
     * Returns all events within a date range — paginated.
     *
     * Use case: monthly compliance reports, incident time window analysis.
     * Dates are accepted as LocalDate (yyyy-MM-dd) and converted to UTC Instant.
     *
     * Why LocalDate and not Instant in the param:
     * Admin users think in calendar dates, not Unix timestamps.
     * "Give me logs from January" is more natural than microsecond timestamps.
     */
    @GetMapping("/range")
    public ResponseEntity<ApiResponse<Page<AuditLogResponse>>> getLogsByDateRange(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to,
            @PageableDefault(size = 50) Pageable pageable) {

        Instant fromInstant = from.atStartOfDay(ZoneOffset.UTC).toInstant();
        Instant toInstant   = to.plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant();

        Page<AuditLogResponse> page = auditLogRepository
                .findByCreatedAtBetweenOrderByCreatedAtDesc(fromInstant, toInstant, pageable)
                .map(AuditLogResponse::fromEntity);

        return ResponseEntity.ok(ApiResponse.ok("Audit logs by date range retrieved", page));
    }

    // --- Security Monitoring

    /**
     * GET /audit/critical
     * Returns all CRITICAL severity events in the last 24 hours.
     *
     * Use case: admin security dashboard — "what critical events happened today?"
     * OWASP A09: CRITICAL events require immediate human review.
     * In production this would also feed into a SIEM (Splunk, Datadog).
     */
    @GetMapping("/critical")
    public ResponseEntity<ApiResponse<List<AuditLogResponse>>> getRecentCriticalEvents() {

        Instant since = Instant.now().minusSeconds(86400); // last 24 hours
        List<AuditLogResponse> events = auditLogRepository
                .findCriticalEventsSince(since)
                .stream()
                .map(AuditLogResponse::fromEntity)
                .toList();

        return ResponseEntity.ok(ApiResponse.ok("Critical events retrieved", events));
    }

    /**
     * GET /audit/users/{userId}/failures
     * Returns recent FAILURE audit events for a specific user.
     *
     * Use case: "How many times has this user failed to login recently?"
     * Used during incident response to assess if an account is under attack.
     * Covers the last 60 minutes by default.
     */
    @GetMapping("/users/{userId}/failures")
    public ResponseEntity<ApiResponse<List<AuditLogResponse>>> getRecentFailuresForUser(
            @PathVariable UUID userId) {

        Instant since = Instant.now().minusSeconds(3600); // last 60 minutes
        List<AuditLogResponse> failures = auditLogRepository
                .findRecentFailuresByUserId(userId, since)
                .stream()
                .map(AuditLogResponse::fromEntity)
                .toList();

        return ResponseEntity.ok(ApiResponse.ok("Recent failures retrieved", failures));
    }
}