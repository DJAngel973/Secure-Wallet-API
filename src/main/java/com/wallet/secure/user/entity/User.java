package com.wallet.secure.user.entity;

import com.wallet.secure.common.enums.UserRole;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

/**
 * Represents a system user with advanced security controls.
 *
 * Maps to: users table (03-tables.sql)
 *
 * Security features mapped:
 * - BCrypt password hash (OWASP A02)
 * - Account lockout after failed attempts (OWASP A07)
 * - Email verification required before login
 * - TOTP 2FA for high-value operations > $100 (ADR-004, ADR-005)
 * - Role-based access control (OWASP A01)
 *
 * NOTE: ddl-auto=validate — Hibernate validates against existing schema.
 * This entity must match 03-tables.sql exactly.
 */
@Entity
@Table(name = "users")
@EntityListeners(AuditingEntityListener.class)   // AuditConfig enables this
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    // ─── Identity ─────────────────────────────────────────────────────────────

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    /**
     * Unique email — used as username for login.
     * DB constraint: email_format CHECK validates regex at DB level.
     * Bean Validation validates at API level (RegisterRequest DTO).
     * OWASP A03: email is used in queries only via prepared statements (JPA).
     */
    @Column(name = "email", unique = true, nullable = false, length = 255)
    private String email;

    // ─── Security ─────────────────────────────────────────────────────────────

    /**
     * BCrypt hash — NEVER the plain password.
     * Strength 12 configured in SecurityConfig.passwordEncoder().
     * DB constraint: password_not_empty CHECK (LENGTH > 12).
     * OWASP A02: adaptive hashing algorithm.
     */
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    /**
     * Role-based access control.
     * USER = standard client, ADMIN = superadmin, MANAGER = support.
     * Maps to PostgreSQL ENUM user_role (02-types.sql).
     * OWASP A01: principle of least privilege.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 20)
    @Builder.Default
    private UserRole role = UserRole.USER;

    // ─── Account Status ───────────────────────────────────────────────────────

    /**
     * Soft activation control.
     * FALSE = account disabled (admin action or pending email verification).
     * OWASP A07: prevents access without disabling the account permanently.
     */
    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private Boolean isActive = true;

    /**
     * Failed login counter — reset to 0 on successful login.
     * DB constraint: CHECK (>= 0 AND <= 3).
     * When reaches 3 → lockUntil is set.
     * OWASP A07: protection against brute force attacks.
     */
    @Column(name = "failed_login_attempts", nullable = false)
    @Builder.Default
    private Integer failedLoginAttempts = 0;

    /**
     * Account locked until this timestamp.
     * NULL = account is not locked.
     * NOT NULL = locked until that datetime.
     * OWASP A07: temporary lockout after repeated failures.
     */
    @Column(name = "locked_until")
    private Instant lockedUntil;

    // ─── Email Verification ───────────────────────────────────────────────────

    /**
     * Email verification status.
     * FALSE = pending verification — login NOT allowed.
     * TRUE = verified — full access.
     * OWASP A07: prevents fake accounts and account takeover.
     */
    @Column(name = "email_verified", nullable = false)
    @Builder.Default
    private Boolean emailVerified = false;

    // ─── Two-Factor Authentication (TOTP) ─────────────────────────────────────

    /**
     * Whether 2FA is enabled for this user.
     * When TRUE, operations > $100 require TOTP code (ADR-005).
     */
    @Column(name = "two_factor_enabled", nullable = false)
    @Builder.Default
    private Boolean twoFactorEnabled = false;

    /**
     * Base32 TOTP secret for Google Authenticator / Authy.
     * Stored encrypted via pgcrypto at DB level (03-tables.sql comment).
     * NULL when 2FA is not configured.
     * OWASP A02: sensitive credential — never exposed in API responses.
     */
    @Column(name = "two_factor_secret")
    private String twoFactorSecret;

    // ─── Activity Tracking ────────────────────────────────────────────────────

    /**
     * Last successful login timestamp.
     * Used for: suspicious activity detection, session reporting.
     * NULL = user has never logged in.
     */
    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    // ─── Audit Timestamps (automatic via AuditConfig) ─────────────────────────

    /**
     * Set automatically by Spring Data JPA on first persist.
     * Managed by AuditingEntityListener — never set manually.
     * Maps to: created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
     */
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * Updated automatically by Spring Data JPA on every update.
     * Managed by AuditingEntityListener — never set manually.
     * DB trigger update_users_updated_at also handles this (05-triggers.sql).
     * Maps to: updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
     */
    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    // ─── Business Methods ─────────────────────────────────────────────────────

    /**
     * Checks if the account is currently locked.
     * Returns true if lockedUntil is set and is in the future.
     */
    public boolean isAccountLocked() {
        return lockedUntil != null && Instant.now().isBefore(lockedUntil);
    }

    /**
     * Checks if the account is fully operational:
     * - active
     * - not locked
     * - email verified
     * Used by Spring Security UserDetailsService.
     */
    public boolean isFullyActive() {
        return Boolean.TRUE.equals(isActive)
                && !isAccountLocked()
                && Boolean.TRUE.equals(emailVerified);
    }

    /**
     * Increments failed login counter.
     * Called by AuthService on each failed login attempt.
     */
    public void incrementFailedLoginAttempts() {
        this.failedLoginAttempts = (this.failedLoginAttempts == null ? 0 : this.failedLoginAttempts) + 1;
    }

    /**
     * Resets failed login counter after successful login.
     */
    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
        this.lockedUntil = null;
    }
}