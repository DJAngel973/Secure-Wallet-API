package com.wallet.secure.auth.dto;

import com.wallet.secure.auth.entity.Session;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.UUID;

/**
 * DTO returned for session read operations.
 * <p>
 * OWASP A02 — what is NOT exposed:
 * → tokenHash  ← NEVER returned to the client
 *               Even the hash must not leave the server.
 *               The client already has the raw token — it doesn't need the hash.
 * </p>
 * OWASP A01 — what IS exposed and why:
 * → id         ← UUID used by DELETE /sessions/{id} to revoke a specific session
 * → ipAddress  ← user sees from which IP the session was opened
 * → userAgent  ← user sees which browser/device opened the session
 * → createdAt  ← user sees when the session was opened
 * → expiresAt  ← user sees when the session will expire naturally
 * → revoked    ← user sees if the session is still active
 * → current    ← UI highlights "this is your current session"
 * <p>
 * The combination of ipAddress + userAgent + createdAt lets the user
 * identify "this session is my phone in Colombia" vs
 * "this session is an unknown device in Russia" → revoke it.
 * </p>
 * OWASP A07: session transparency is a security feature —
 * users who can see their sessions can detect unauthorized access.
 */
@Getter
@Builder
public class SessionResponse {

    /** Session UUID — used to revoke this specific session via DELETE /sessions/{id} */
    private final UUID id;

    /**
     * IP address when session was created.
     * Shown as-is — the user understands their own IP.
     * Example: "192.168.1.100" or "2001:db8::1" (IPv6)
     */
    private final String ipAddress;

    /**
     * Browser/device identifier.
     * Raw User-Agent — frontend can parse it for display:
     * "Chrome on Windows" instead of the full UA string.
     * Example: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
     */
    private final String userAgent;

    /** When the session was created — "logged in 2 hours ago" */
    private final Instant createdAt;

    /** When the session expires naturally — "expires in 6 days" */
    private final Instant expiresAt;

    /** Whether the session has been explicitly revoked (logged out) */
    private final boolean revoked;

    /** When the session was revoked — null if still active */
    private final Instant revokedAt;

    /**
     * True if this session belongs to the current request.
     * Determined by SessionService comparing the request's token hash
     * with this session's stored hash.
     * Used by the frontend to mark "THIS DEVICE" in the session list.
     * NOT stored in DB — computed at query time.
     */
    private final boolean current;

    // ─── Factory Methods ──────────────────────────────────────────────────────

    /**
     * Converts a Session entity to SessionResponse.
     *
     * @param session  the session entity
     * @param isCurrent true if this session matches the current request's token
     */
    public static SessionResponse fromEntity(Session session, boolean isCurrent) {
        return SessionResponse.builder()
                .id(session.getId())
                .ipAddress(session.getIpAddress())
                .userAgent(session.getUserAgent())
                .createdAt(session.getCreatedAt())
                .expiresAt(session.getExpiresAt())
                .revoked(session.isRevoked())
                .revokedAt(session.getRevokedAt())
                .current(isCurrent)
                .build();
    }

    /**
     * Convenience overload — when the current session context is not available.
     * Used for admin queries where "current" is not meaningful.
     */
    public static SessionResponse fromEntity(Session session) {
        return fromEntity(session, false);
    }
}