package com.wallet.secure.auth.repository;

import com.wallet.secure.auth.entity.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Data access layer for user sessions.
 * <p>
 * OWASP A07: this repository is the enforcement point for
 * server-side session revocation. Every token validation
 * must go through findByTokenHash() before being trusted.
 * </p>
 */
@Repository
public interface SessionRepository extends JpaRepository<Session, UUID> {

    /**
     * Finds a session by the SHA-256 hash of its refresh token.
     * Called on every POST /auth/refresh to validate the session.
     * If not found → token was never registered or was deleted → reject.
     */
    Optional<Session> findByTokenHash(String tokenHash);

    /**
     * Returns all active (non-revoked, non-expired) sessions for a user.
     * Used by: GET /sessions → "show me all devices where I'm logged in"
     * OWASP A07: users can monitor and control their own sessions.
     */
    @Query("SELECT s FROM Session s WHERE s.user.id = :userId AND s.revoked = false AND s.expiresAt > :now ORDER BY s.createdAt DESC")
    List<Session> findActiveSessionsByUserId(
            @Param("userId") UUID userId,
            @Param("now") Instant now);

    /**
     * Returns ALL sessions for a user (active + revoked + expired).
     * Used by: ADMIN GET /sessions/users/{userId} → full session history.
     * OWASP A09: complete forensic session timeline.
     */
    List<Session> findByUserIdOrderByCreatedAtDesc(UUID userId);

    /**
     * Revokes ALL active sessions for a user in a single DB update.
     * Called on:
     * → Password change — all sessions invalidated for security
     * → Admin account suspension — immediate access termination
     * → User self-service "logout from all devices"
     * <p>
     * WHY bulk update instead of loading + updating each:
     * A user could have 10+ active sessions across devices.
     * Loading all and saving individually = N+1 queries.
     * One UPDATE WHERE = 1 query regardless of session count.
     * </p>
     * OWASP A07: critical for incident response — one call terminates
     * all access immediately when a compromise is detected.
     */
    @Modifying
    @Query("UPDATE Session s SET s.revoked = true, s.revokedAt = :now WHERE s.user.id = :userId AND s.revoked = false")
    void revokeAllActiveSessionsForUser(
            @Param("userId") UUID userId,
            @Param("now") Instant now);

    /**
     * Deletes expired AND revoked sessions older than a given date.
     * Called by a scheduled cleanup job (future) to keep the table lean.
     * Without cleanup, user_sessions grows indefinitely.
     * <p>
     * WHY delete only revoked+expired (not just expired):
     * Active sessions must never be deleted — they represent live access.
     * Only sessions that are BOTH expired AND revoked are safe to remove.
     * </p>
     */
    @Modifying
    @Query("DELETE FROM Session s WHERE s.expiresAt < :before AND s.revoked = true")
    void deleteExpiredAndRevokedBefore(@Param("before") Instant before);

    /**
     * Counts active sessions for a user.
     * Used to enforce a maximum concurrent sessions limit.
     * Example: if a user has 5 active sessions and tries to login again
     * from a new device → revoke the oldest one first.
     */
    @Query("SELECT COUNT(s) FROM Session s WHERE s.user.id = :userId AND s.revoked = false AND s.expiresAt > :now")
    long countActiveSessionsByUserId(
            @Param("userId") UUID userId,
            @Param("now") Instant now);
}