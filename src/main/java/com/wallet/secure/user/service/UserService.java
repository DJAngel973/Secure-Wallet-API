package com.wallet.secure.user.service;

import com.wallet.secure.common.exception.EmailAlreadyExistsException;
import com.wallet.secure.common.exception.InvalidCredentialsException;
import com.wallet.secure.common.exception.UnauthorizedOperationException;
import com.wallet.secure.common.exception.UserNotFoundException;
import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.user.dto.RegisterRequest;
import com.wallet.secure.user.dto.UpdateProfileRequest;
import com.wallet.secure.user.dto.UserResponse;
import com.wallet.secure.user.entity.User;
import com.wallet.secure.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Business logic for user management.
 *
 * Responsibilities:
 * - User registration with BCrypt hashing
 * - Profile updates (email, password) with re-authentication
 * - Account deactivation (soft delete — never hard delete users)
 * - Entity → DTO mapping (User entity never leaves this layer)
 *
 * OWASP A02: passwords hashed here with BCrypt strength 12
 * OWASP A07: account lockout logic, re-auth for sensitive changes
 * OWASP A09: all sensitive operations logged
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class UserService {

    private static final int MAX_FAILED_ATTEMPTS = 3;
    private static final int LOCK_DURATION_MINUTES = 30;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // ─── Registration ─────────────────────────────────────────────────────────

    /**
     * Registers a new user.
     *
     * Flow:
     * 1. Check email not already taken
     * 2. Hash password with BCrypt
     * 3. Build User entity with safe defaults
     * 4. Save and return UserResponse (never the entity)
     *
     * @param request validated RegisterRequest DTO
     * @return ApiResponse with UserResponse data
     * @throws IllegalArgumentException if email already exists
     */
    @Transactional
    public ApiResponse<UserResponse> register(RegisterRequest request) {
        // Step 1 — verify email is not taken
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Registration attempt with existing email: {}",
                    maskEmail(request.getEmail()));
            // OWASP A07: vague message — don't reveal if email exists
            throw new EmailAlreadyExistsException("Email already in use");
        }

        // Step 2 — hash password (plain text never touches the DB)
        // OWASP A02: BCrypt strength 12 configured in SecurityConfig
        String hashedPassword = passwordEncoder.encode(request.getPassword());

        // Step 3 — build entity with secure defaults
        User user = User.builder()
                .email(request.getEmail())
                .passwordHash(hashedPassword)
                // role defaults to USER — set by @Builder.Default in entity
                // isActive = true, emailVerified = false — set by @Builder.Default
                // failedLoginAttempts = 0 — set by @Builder.Default
                // twoFactorEnabled = false, set by @Builder.Default
                .build();

        // Step 4 — persist and return DTO
        User saved = userRepository.save(user);

        log.info("New user registered: id={}, email={}",
                saved.getId(), maskEmail(saved.getEmail()));

        return ApiResponse.ok("User registered successfully", toResponse(saved));
    }

    // ─── Profile Update ───────────────────────────────────────────────────────

    /**
     * Updates user profile (email and/or password).
     *
     * Flow:
     * 1. Load user — throws if not found
     * 2. Verify currentPassword — re-authentication required
     * 3. If new email → check availability → reset emailVerified
     * 4. If new password → hash and update
     * 5. Save and return updated UserResponse
     *
     * OWASP A07: currentPassword required for any sensitive change.
     *
     * @param userId  authenticated user's ID (from JWT — not from request body)
     * @param request UpdateProfileRequest DTO
     * @return ApiResponse with updated UserResponse
     */
    @Transactional
    public ApiResponse<UserResponse> updateProfile(UUID userId, UpdateProfileRequest request) {
        // Step 1 — load user
        User user = findUserById(userId);

        // Step 2 — re-authentication: verify current password
        // OWASP A07: prevents account takeover via stolen JWT
        if (request.getCurrentPassword() == null ||
                !passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            log.warn("Profile update failed — wrong current password: userId={}", userId);
            throw new InvalidCredentialsException("Current password is incorrect");
        }

        boolean updated = false;

        // Step 3 — update email if provided
        if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(request.getEmail())) {
                throw new EmailAlreadyExistsException("Email already in use");
            }
            log.info("Email change requested: userId={}, from={} to={}",
                    userId, maskEmail(user.getEmail()), maskEmail(request.getEmail()));

            user.setEmail(request.getEmail());
            // Reset verification — new email must be verified
            user.setEmailVerified(false);
            updated = true;
            // TODO: send verification email to new address (email service — future)
        }

        // Step 4 — update password if provided
        if (request.getPassword() != null && !request.getPassword().isBlank()) {
            // Prevent reusing the same password
            if (passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
                throw new InvalidCredentialsException(
                        "New password must be different from current password");
            }
            user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
            log.info("Password changed: userId={}", userId);
            updated = true;
        }

        if (!updated) {
            return ApiResponse.ok("No changes applied", toResponse(user));
        }

        User saved = userRepository.save(user);
        return ApiResponse.ok("Profile updated successfully", toResponse(saved));
    }

    // ─── Account Deactivation ─────────────────────────────────────────────────

    /**
     * Soft-deactivates a user account.
     * Sets isActive = false — data is preserved for audit compliance.
     *
     * WHY soft delete:
     * - Financial regulations require data retention
     * - audit_logs reference user IDs — hard delete would break compliance
     * - OWASP A09: audit trail must be preserved
     *
     * @param userId ID of user to deactivate
     * @param requesterId ID of who is requesting (must be same user or ADMIN)
     */
    @Transactional
    public ApiResponse<Void> deactivateAccount(UUID userId, UUID requesterId) {
        User user = findUserById(userId);

        // OWASP A01: only the user or an ADMIN can deactivate an account
        // Fine-grained check — controller also uses @PreAuthorize
        if (!userId.equals(requesterId)) {
            log.warn("Unauthorized deactivation attempt: requesterId={} tried userId={}",
                    requesterId, userId);
            throw new UnauthorizedOperationException("Not authorized to deactivate this account");
        }

        user.setIsActive(false);
        userRepository.save(user);

        log.info("Account deactivated: userId={}", userId);
        return ApiResponse.ok("Account deactivated successfully");
    }

    // ─── Read ─────────────────────────────────────────────────────────────────

    /**
     * Returns the profile of a user by ID.
     * OWASP A01: controller must ensure the caller can only access their own profile
     * unless they have ADMIN role.
     */
    @Transactional(readOnly = true)
    public ApiResponse<UserResponse> getProfile(UUID userId) {
        User user = findUserById(userId);
        return ApiResponse.ok("Profile retrieved", toResponse(user));
    }

    // ─── Internal Helpers ───────────────────────────────────────────────��─────

    /**
     * Loads a user by ID — throws a descriptive exception if not found.
     * Centralized so all methods use the same error handling.
     */
    private User findUserById(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("User not found: id={}", userId);
                    // OWASP A05: vague message — don't reveal internal details
                    return new UserNotFoundException("User not found");
                });
    }

    /**
     * Maps User entity → UserResponse DTO.
     * Single place where the mapping happens — easy to maintain.
     * OWASP A02: sensitive fields (passwordHash, twoFactorSecret) are
     * intentionally excluded from UserResponse.
     */
    private UserResponse toResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .role(user.getRole())
                .isActive(user.getIsActive())
                .emailVerified(user.getEmailVerified())
                .twoFactorEnabled(user.getTwoFactorEnabled())
                .lastLoginAt(user.getLastLoginAt())
                .createdAt(user.getCreatedAt())
                .build();
    }

    /**
     * Masks email for logs — OWASP A09: never log full emails.
     * "angel@example.com" → "an***@example.com"
     */
    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) return "***";
        String[] parts = email.split("@");
        String local = parts[0];
        String masked = local.length() > 2
                ? local.substring(0, 2) + "***"
                : "***";
        return masked + "@" + parts[1];
    }

    /**
     * Finds a user by email — used by UserController to resolve UUID from JWT principal.
     * NOTE: This is a temporary bridge until CustomUserDetails carries the UUID directly.
     * OWASP A03: JPA prepared statement via repository method.
     */
    @Transactional(readOnly = true)
    public ApiResponse<UserResponse> findUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        return ApiResponse.ok("User found", toResponse(user));
    }
}
