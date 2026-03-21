package com.wallet.secure.user.dto;

import com.wallet.secure.common.enums.UserRole;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.UUID;

/**
 * DTO for user data returned in API responses.
 *
 * WHY not return the User entity directly:
 * - Entity has passwordHash, twoFactorSecret, failedLoginAttempts — NEVER expose these
 * - This DTO exposes only what the client legitimately needs
 * - OWASP A02: prevents accidental exposure of sensitive credentials
 *
 * Mapped from User entity in UserService — entity never leaves the service layer.
 */
@Getter
@Builder
public class UserResponse {

    private UUID id;
    private String email;
    private UserRole role;
    private Boolean isActive;
    private Boolean emailVerified;
    private Boolean twoFactorEnabled;
    private Instant lastLoginAt;
    private Instant createdAt;

    /*
     * Fields intentionally EXCLUDED:
     * - passwordHash      → OWASP A02: never expose hashes
     * - twoFactorSecret   → OWASP A02: never expose TOTP secrets
     * - failedLoginAttempts → internal security state
     * - lockedUntil       → internal security state
     * - updatedAt         → not relevant for the client
     */
}
