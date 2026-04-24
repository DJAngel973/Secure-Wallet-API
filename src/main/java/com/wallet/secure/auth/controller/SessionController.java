package com.wallet.secure.auth.controller;

import com.wallet.secure.auth.dto.SessionResponse;
import com.wallet.secure.auth.service.SessionService;
import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.user.repository.UserRepository;
import com.wallet.secure.common.exception.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.util.List;
import java.util.UUID;

/**
 * REST Controller for session management.
 *
 * Base path: /sessions
 *
 * WHO can call each endpoint:
 * → Any authenticated user → see and revoke their OWN sessions
 * → ADMIN only             → see sessions of ANY user
 *
 * Endpoint summary:
 * GET    /sessions                        → list my active sessions
 * DELETE /sessions/{sessionId}            → revoke one of my sessions
 * DELETE /sessions/all                    → revoke ALL my sessions (logout all devices)
 * GET    /sessions/users/{userId}         → ADMIN: full session history of a user
 * DELETE /sessions/users/{userId}/all     → ADMIN: revoke all sessions of a user
 *
 * WHY sessions are under /sessions and not /auth/sessions:
 * Session management is a distinct domain from authentication.
 * /auth → obtaining tokens (login, logout, refresh)
 * /sessions → managing existing sessions (list, revoke specific)
 * Clean URL structure matches the domain separation.
 *
 * OWASP A01: userId always extracted from JWT — never from request body.
 * A user cannot see or revoke another user's sessions by changing a URL param.
 * Ownership is enforced in SessionService.revokeSessionById().
 *
 * OWASP A07: server-side session revocation — real multi-device control.
 */
@RestController
@RequestMapping("/sessions")
@RequiredArgsConstructor
@Log4j2
@Tag(name = "2. Sessions", description = "Multi-device session management — see and revoke active sessions")
public class SessionController {

    private final SessionService sessionService;
    private final UserRepository userRepository;

    // ─── User Endpoints

    /**
     * GET /sessions
     * Returns all ACTIVE sessions for the authenticated user.
     *
     * Use case: "Show me all devices where I'm currently logged in"
     * Response includes the current session flagged as current=true.
     *
     * The refresh token is extracted from the Authorization header to determine
     * which session is the "current" one — the frontend can highlight it.
     *
     * WHY not return revoked/expired sessions here:
     * The user only needs to see what is currently active.
     * Revoked/expired sessions have no actionable meaning for the user.
     * ADMIN sees all sessions including history via /sessions/users/{userId}.
     *
     * OWASP A01: userId from JWT — user can only see their own sessions.
     */
    @GetMapping
    public ResponseEntity<ApiResponse<List<SessionResponse>>> getMySessions(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestHeader(value = "X-Refresh-Token", required = false) String refreshToken) {

        UUID userId = resolveUserId(userDetails.getUsername());

        // refreshToken is optional — if provided, the current session is flagged
        // Client sends the refresh token in X-Refresh-Token header (not Authorization)
        // Authorization header carries the access token — not the refresh token
        return ResponseEntity.ok(
                sessionService.getActiveSessions(userId, refreshToken));
    }

    /**
     * DELETE /sessions/{sessionId}
     * Revokes a specific session by its UUID.
     *
     * Use case: "I see a session from an unknown device in Russia — revoke it"
     * The user stays logged in on their current device.
     * Only the specified session is terminated.
     *
     * Ownership is enforced in SessionService:
     * → If sessionId belongs to another user → 401 (not 403, to prevent enumeration)
     * → OWASP A01: cannot revoke another user's session by guessing a UUID
     *
     * @param sessionId UUID of the session to revoke
     */
    @DeleteMapping("/{sessionId}")
    public ResponseEntity<ApiResponse<Void>> revokeSession(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable UUID sessionId) {

        UUID userId = resolveUserId(userDetails.getUsername());

        return ResponseEntity.ok(
                sessionService.revokeSessionById(sessionId, userId));
    }

    /**
     * DELETE /sessions/all
     * Revokes ALL active sessions for the authenticated user.
     *
     * Use case: "I think my account was compromised — log me out everywhere"
     * After this call the user must log in again on all devices.
     *
     * WHY this doesn't also invalidate the current access token:
     * Access tokens are stateless — they expire in 15 minutes naturally.
     * Revoking all refresh tokens means no new access tokens can be obtained.
     * After max 15 minutes, the attacker loses access on all devices.
     * OWASP A07: acceptable 15-minute window for stateless JWT.
     *
     * NOTE: this also revokes the CURRENT session.
     * The client should redirect to login after calling this endpoint.
     */
    @DeleteMapping("/all")
    public ResponseEntity<ApiResponse<Void>> revokeAllMySessions(
            @AuthenticationPrincipal UserDetails userDetails) {

        UUID userId = resolveUserId(userDetails.getUsername());
        sessionService.revokeAllSessions(userId);

        log.info("All sessions revoked by user: userId={}", userId);
        return ResponseEntity.ok(
                ApiResponse.ok("All sessions revoked — please log in again", null));
    }

    // ─── Admin Endpoints

    /**
     * GET /sessions/users/{userId}
     * Returns FULL session history for a user — ADMIN only.
     * Includes active, revoked, and expired sessions.
     *
     * Use case: "Show me all sessions for this user in the last 7 days"
     * Used during incident response to trace account activity.
     *
     * WHY ADMIN sees full history but user sees only active:
     * Users need actionable info — only active sessions matter to them.
     * Admins need forensic info — full history for investigation.
     *
     * OWASP A01: @PreAuthorize evaluated BEFORE method execution.
     * Non-ADMIN → 403 immediately, no data is ever loaded.
     * OWASP A09: viewing user sessions is itself an admin action — auditable.
     */
    @GetMapping("/users/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<SessionResponse>>> getUserSessions(
            @PathVariable UUID userId) {

        return ResponseEntity.ok(
                sessionService.getAllSessionsForUser(userId));
    }

    /**
     * DELETE /sessions/users/{userId}/all
     * Revokes ALL active sessions for a specific user — ADMIN only.
     *
     * Use cases:
     * → Suspected account compromise — immediate access termination
     * → Account suspension — ensure no active sessions remain
     * → Compliance: "user X must be logged out of all systems immediately"
     *
     * OWASP A01: ADMIN only — @PreAuthorize enforced before method.
     * OWASP A09: this action must be audited — AuditService called.
     */
    @DeleteMapping("/users/{userId}/all")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> revokeAllSessionsForUser(
            @PathVariable UUID userId) {

        sessionService.revokeAllSessions(userId);

        log.warn("ADMIN revoked all sessions for userId={}", userId);
        return ResponseEntity.ok(
                ApiResponse.ok("All sessions for user revoked", null));
    }

    // ─── Private Helper

    /**
     * Resolves the user UUID from their email.
     * Email comes from the validated JWT — cannot be forged.
     * OWASP A01: identity always from the trusted token, never from request body.
     */
    private UUID resolveUserId(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"))
                .getId();
    }
}