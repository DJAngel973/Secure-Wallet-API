package com.wallet.secure.user.controller;

import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.user.dto.RegisterRequest;
import com.wallet.secure.user.dto.UpdateProfileRequest;
import com.wallet.secure.user.dto.UserResponse;
import com.wallet.secure.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * REST Controller for user management endpoints.
 *
 * Base path: /users
 * Public:    POST /auth/register (in AuthController — future)
 * Protected: all endpoints here require valid JWT
 *
 * WHY userId comes from @AuthenticationPrincipal and NOT from request body:
 * The JWT is validated by the security filter before reaching this controller.
 * The principal extracted from the JWT is the only trusted source of identity.
 * If the client sent their own userId in the body, an attacker could
 * manipulate any user's data. OWASP A01: Broken Access Control.
 *
 * OWASP A01: Broken Access Control prevention
 */
@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Log4j2
public class UserController {

    private final UserService userService;

    // ─── Profile Read ─────────────────────────────────────────────────────────

    /**
     * GET /users/me
     * Returns the authenticated user's own profile.
     *
     * @AuthenticationPrincipal injects the UserDetails from the validated JWT.
     * OWASP A01: users can only see their own profile via /me.
     * Admins can see any profile via GET /users/{id} (below).
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> getMyProfile(
            @AuthenticationPrincipal UserDetails userDetails) {

        UUID userId = resolveUserId(userDetails);
        return ResponseEntity.ok(userService.getProfile(userId));
    }

    /**
     * GET /users/{id}
     * Returns any user's profile — ADMIN only.
     *
     * @PreAuthorize evaluated BEFORE the method executes.
     * If the caller doesn't have ADMIN role → 403 immediately.
     * OWASP A01: fine-grained access control at method level.
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<UserResponse>> getUserById(
            @PathVariable UUID id) {

        return ResponseEntity.ok(userService.getProfile(id));
    }

    // ─── Profile Update ───────────────────────────────────────────────────────

    /**
     * PUT /users/me
     * Updates the authenticated user's email and/or password.
     * Requires currentPassword in the request body (re-authentication).
     *
     * OWASP A07: sensitive operation — currentPassword verified in UserService.
     */
    @PutMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> updateMyProfile(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody UpdateProfileRequest request) {

        UUID userId = resolveUserId(userDetails);
        return ResponseEntity.ok(userService.updateProfile(userId, request));
    }

    // ─── Account Deactivation ─────────────────────────────────────────────────

    /**
     * DELETE /users/me
     * Soft-deactivates the authenticated user's account.
     * isActive = false — data preserved for audit compliance.
     *
     * HTTP 200 with message — not 204, because ApiResponse carries confirmation.
     * OWASP A09: data retention for financial compliance.
     */
    @DeleteMapping("/me")
    public ResponseEntity<ApiResponse<Void>> deactivateMyAccount(
            @AuthenticationPrincipal UserDetails userDetails) {

        UUID userId = resolveUserId(userDetails);
        return ResponseEntity.ok(userService.deactivateAccount(userId, userId));
    }

    /**
     * DELETE /users/{id}
     * Admin deactivates any user's account.
     * OWASP A01: ADMIN role required.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> deactivateUser(
            @PathVariable UUID id,
            @AuthenticationPrincipal UserDetails userDetails) {

        UUID requesterId = resolveUserId(userDetails);
        return ResponseEntity.ok(userService.deactivateAccount(id, requesterId));
    }

    // ─── Private Helper ───────────────────────────────────────────────────────

    /**
     * Resolves the authenticated user's UUID from their email (JWT principal).
     *
     * WHY this is temporary:
     * UserDetails.getUsername() = email in this project.
     * We query the DB to get the UUID from that email.
     * This is an extra DB query on every request.
     *
     * When auth/ domain is implemented:
     * JwtAuthFilter will store a CustomUserDetails with UUID directly.
     * This method becomes: return ((CustomUserDetails) userDetails).getId();
     * → zero extra DB queries.
     */
    private UUID resolveUserId(UserDetails userDetails) {
        return userService.findUserByEmail(userDetails.getUsername())
                        .getData()
                        .getId();
    }
}
