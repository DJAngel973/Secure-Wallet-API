package com.wallet.secure.user.repository;

import com.wallet.secure.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for User entity — data access layer.
 *
 * WHY JpaRepository<User, UUID>:
 * - Provides save(), findById(), delete(), findAll() for free
 * - UUID = type of the primary key (matches users.id UUID in DB)
 * - Spring Data generates the SQL at runtime — no boilerplate
 *
 * Query methods follow Spring Data naming conventions:
 * findBy[Field] → SELECT * FROM users WHERE field = ?
 * Spring generates the SQL automatically from the method name.
 *
 * OWASP A03: All queries use prepared statements via JPA — no string concatenation.
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    // ─── Lookup Queries ───────────────────────────────────────────────────────

    /**
     * Find user by email — primary lookup for login.
     * Returns Optional to force null-check at call site.
     * OWASP A03: JPA generates: WHERE email = ? (prepared statement)
     *
     * Used by: AuthService.login(), UserDetailsServiceImpl.loadUserByUsername()
     */
    Optional<User> findByEmail(String email);

    /**
     * Check if an email is already registered.
     * More efficient than findByEmail() — only checks existence, no data transfer.
     *
     * Used by: AuthService.register() to prevent duplicate accounts.
     */
    boolean existsByEmail(String email);

    // ─── Security Queries ─────────────────────────────────────────────────────

    /**
     * Find active and unlocked users by email.
     * Combines 3 conditions in one query — avoids loading locked/inactive users.
     *
     * Used by: AuthService — fast pre-check before full authentication.
     */
    @Query("""
        SELECT u FROM User u
        WHERE u.email = :email
          AND u.isActive = true
          AND (u.lockedUntil IS NULL OR u.lockedUntil < :now)
        """)
    Optional<User> findActiveUserByEmail(
            @Param("email") String email,
            @Param("now") Instant now
    );

    /**
     * Find users whose account lock has expired — for scheduled unlock jobs.
     * Returns users that are still marked as locked but the time has passed.
     *
     * Used by: scheduled task (future) to auto-unlock accounts.
     */
    @Query("""
        SELECT u FROM User u
        WHERE u.lockedUntil IS NOT NULL
          AND u.lockedUntil < :now
          AND u.isActive = true
        """)
    java.util.List<User> findUsersWithExpiredLock(@Param("now") Instant now);

    // ─── Update Queries (avoid loading the full entity) ───────────────────────

    /**
     * Update last login timestamp directly in DB — no need to load the full entity.
     * @Modifying = this query changes data (not SELECT)
     * Used by: AuthService after successful login.
     */
    @Modifying
    @Query("UPDATE User u SET u.lastLoginAt = :loginAt WHERE u.id = :id")
    void updateLastLoginAt(@Param("id") UUID id, @Param("loginAt") Instant loginAt);

    /**
     * Increment failed login attempts directly in DB.
     * Atomic operation — avoids race conditions on concurrent login attempts.
     * OWASP A07: brute force protection counter.
     *
     * Used by: AuthService on each failed login attempt.
     */
    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = u.failedLoginAttempts + 1 WHERE u.id = :id")
    void incrementFailedLoginAttempts(@Param("id") UUID id);

    /**
     * Lock account until a specific timestamp.
     * Called when failedLoginAttempts reaches MAX_FAILED_ATTEMPTS (3).
     * OWASP A07: temporary lockout after repeated failures.
     *
     * Used by: AuthService after 3rd consecutive failed login.
     */
    @Modifying
    @Query("UPDATE User u SET u.lockedUntil = :until, u.failedLoginAttempts = :attempts WHERE u.id = :id")
    void lockAccount(
            @Param("id") UUID id,
            @Param("until") Instant until,
            @Param("attempts") int attempts
    );

    /**
     * Reset failed attempts and remove lock — after successful login.
     * OWASP A07: clean state after legitimate access.
     *
     * Used by: AuthService after successful authentication.
     */
    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = 0, u.lockedUntil = NULL WHERE u.id = :id")
    void resetFailedLoginAttempts(@Param("id") UUID id);

    /**
     * Verify email — marks account as fully active.
     * Called after user clicks verification link in email.
     *
     * Used by: AuthService.verifyEmail()
     */
    @Modifying
    @Query("UPDATE User u SET u.emailVerified = true WHERE u.id = :id")
    void verifyEmail(@Param("id") UUID id);
}