package com.wallet.secure.auth.entity;

import com.wallet.secure.user.entity.User;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

/**
 * Represents an active user session tracked in the DB.
 *
 * Maps to: user_sessions table (03-tables.sql)
 *
 * REAL DB SCHEMA:
 *   id          UUID PK
 *   user_id     UUID FK → users (ON DELETE CASCADE)
 *   token_hash  TEXT UNIQUE  ← SHA-256 of the refresh token
 *   ip_address  INET
 *   user_agent  TEXT
 *   expires_at  TIMESTAMP NOT NULL
 *   created_at  TIMESTAMP
 *   revoked     BOOLEAN DEFAULT FALSE
 *   revoked_at  TIMESTAMP
 *
 * WHY store token_hash and NOT the raw refresh token:
 * If the sessions table is compromised, the attacker gets hashes.
 * A SHA-256 hash of a JWT cannot be reversed to obtain the token.
 * OWASP A02: sensitive tokens never stored in plain text in DB.
 *
 * WHY this table exists alongside refreshToken in User entity:
 * User.refreshToken → simple single-device session (current behavior)
 * user_sessions     → multi-device session management
 *   → "Show me all devices where I'm logged in"
 *   → "Log out from my phone but keep my laptop session"
 *   → "Admin: revoke all sessions for suspicious user"
 *
 * OWASP A07: real session revocation capability.
 * Without this table, logout is only client-side (delete the token).
 * With this table, the server can reject a token even if it hasn't expired.
 */
@Entity
@Table(name = "user_sessions")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Session {

    // ─── Identity

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    // ─── Ownership

    /**
     * The user this session belongs to.
     * ON DELETE CASCADE — deleting a user revokes all their sessions.
     * @ManyToOne because one user can have sessions on multiple devices.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // ─── Token

    /**
     * SHA-256 hash of the refresh token.
     * Used to look up the session when a refresh request arrives.
     * UNIQUE — one hash per row, ensures no duplicate sessions.
     * OWASP A02: raw token never stored — only its hash.
     */
    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    // ─── Context

    /**
     * Client IP at the time the session was created.
     * Mapped as String — Hibernate handles INET ↔ String conversion.
     * OWASP A07: enables geographic anomaly detection.
     * Example: session created in Colombia, refresh from Russia → suspicious.
     */
    @Column(name = "ip_address")
    private String ipAddress;

    /**
     * Browser/device string at session creation.
     * Example: "Mozilla/5.0 (Android 13; Mobile)"
     * Used for device fingerprinting in the session list UI.
     */
    @Column(name = "user_agent")
    private String userAgent;

    // ─── Lifecycle

    /**
     * When this session naturally expires.
     * Mirrors the refresh token expiration from JwtService.
     * After this time, the session is invalid even if not revoked.
     */
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    /**
     * When the session was created — set by Spring Auditing.
     * updatable = false — never changes after insert.
     */
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * Whether this session has been explicitly revoked.
     * true = user logged out from this device, or admin revoked it.
     * false = session is still active (subject to expiration check).
     * DB CHECK: revoked = FALSE OR revoked_at IS NOT NULL
     * → If revoked=true, revoked_at must be set (enforced by revokeNow())
     */
    @Column(name = "revoked", nullable = false)
    @Builder.Default
    private boolean revoked = false;

    /**
     * Exact moment the session was revoked.
     * Null until revoke() is called.
     * DB CHECK guarantees this is set when revoked=true.
     */
    @Column(name = "revoked_at")
    private Instant revokedAt;

    // ─── Business Methods

    /**
     * Marks this session as revoked — called on logout.
     * Sets both revoked=true and revokedAt=now() to satisfy DB CHECK constraint.
     * OWASP A07: server-side session termination.
     */
    public void revokeNow() {
        this.revoked = true;
        this.revokedAt = Instant.now();
    }

    /**
     * Returns true if this session is currently valid:
     * → not revoked
     * → not expired
     * Called by SessionService before trusting a refresh token.
     */
    public boolean isActive() {
        return !revoked && Instant.now().isBefore(expiresAt);
    }
}