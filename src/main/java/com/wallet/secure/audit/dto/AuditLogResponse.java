package com.wallet.secure.audit.dto;

import com.wallet.secure.audit.entity.AuditLog;
import com.wallet.secure.common.enums.AuditAction;
import com.wallet.secure.common.enums.LogSeverity;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.UUID;

/**
 * DTO returned for all audit log read operations.
 *
 * OWASP A09 — what IS exposed and why:
 * → id, userId, action, severityLevel → core identification fields
 * → details (JSONB as String) → event context, already sanitized at write time
 * → ipAddress, userAgent → forensic context for investigation
 * → createdAt → timestamp for timeline reconstruction
 *
 * OWASP A02 — what is NOT exposed:
 * → Raw DB internals or system metadata beyond what's needed
 *
 * WHO can read audit logs:
 * → ADMIN only — enforced at controller level with @PreAuthorize
 * → Regular users NEVER see audit logs — not even their own
 *   (prevents attackers from knowing what was detected)
 */
@Getter
@Builder
public class AuditLogResponse {

    private final UUID id;
    private final UUID userId;
    private final AuditAction action;
    private final LogSeverity severityLevel;

    /**
     * Raw JSONB details string
     * Example: {"email": "testsemail@test.com", "outcome":"SUCCESS"}
     * The frontend/admin UI is responsable for parsing and displaying this
     */
    private final String details;

    private final String ipAddress;
    private final String userAgent;
    private final Instant createdAt;

    /**
     * Static factory - converts AuditLog entity to AuditLogResponse DTO.
     * Flat mapping - no transformation needed beyond field extraction.
     */
    public static AuditLogResponse fromEntity(AuditLog auditLog) {
        return AuditLogResponse.builder()
                .id(auditLog.getId())
                .userId(auditLog.getUserId())
                .action(auditLog.getAction())
                .severityLevel(auditLog.getSeverityLevel())
                .details(auditLog.getDetails())
                .ipAddress(auditLog.getIpAddress())
                .userAgent(auditLog.getUserAgent())
                .createdAt(auditLog.getCreatedAt())
                .build();
    }
}