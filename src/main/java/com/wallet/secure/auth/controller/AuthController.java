package com.wallet.secure.auth.controller;

import com.wallet.secure.auth.dto.AuthResponse;
import com.wallet.secure.auth.dto.LoginRequest;
import com.wallet.secure.auth.dto.LogoutRequest;
import com.wallet.secure.auth.dto.RefreshTokenRequest;
import com.wallet.secure.auth.service.AuthService;
import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.user.dto.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * REST Controller for authentication endpoints.
 *
 * Base path: /auth
 * All endpoints here are PUBLIC - defined in SecurityConfig.PUBLIC_ENDPOINTS
 * No JWT required to reach register, login, or refresh.
 *
 * Why AuthController is separate from UserController:
 * UserController manages user data (profile, password, deactivation)
 * AuthController manages sessions (tokens, login, logout).
 * Single Responsibility - matches the separation between AuthService/UserService
 *
 * OWASP A07: this is the entry point for all authentication flows.
 * OWASP A01: logout requires valid JWT - only authenticated users can logout.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Log4j2
@Tag(name = "1. Authentication", description = "Register, login, logout and token refresh — public endpoints")
public class AuthController {

    private final AuthService authService;

    // --- Register

    /**
     * POST /auth/register
     * Creates a new account and returns tokens immediately
     *
     * HTTP 201 Created - a new resource was created
     * Returns AuthResponse (tokens) - the user is logged in after registration
     *
     * Why 201 and not 200:
     * REST convention - POST that creates a resource returns 201.
     * The client knows a new user was created, not just a query executed.
     *
     * @Valid triggers Bean Validation on RegisterRequest before reaching AuthService:
     * -> @NotBlank on email and password
     * -> @Email on email format
     * -> @Pattern on password complexity
     * If validation fails -> GlobalExceptionHandler returns 400 with field errors.
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponse>> register(@Valid @RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request, httpRequest));
    }

    // --- login

    /**
     * POST /auth/login
     * Authentication credentials and returns access + refresh tokens
     * HTTP 200 - no new resource created, just a session established
     * On failure, AuthService throws:
     * -> BadCredentialsException  -> GlobalExceptionHandler -> 401
     * -> LockedException   -> GlobalExceptionHandler -> 423
     * The controller never sees the exception - handler intercepts it
     *
     * OWASP AA07: same error message for wrong password and unknown email
     * -> prevents user enumeration (handled in AuthService/UserDetailsServiceImpl)
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authService.login(request, httpRequest));
    }

    // --- Refresh

    /**
     * POST /auth/refresh
     * Issues a new access token using a valid refresh token.
     *
     * HTTP 200 — no new resource, just a new token issued.
     *
     * WHY POST and not GET:
     * GET requests are cached and logged by proxies/browsers.
     * Sending a refresh token in a GET request could expose it in logs.
     * POST body is not cached or logged by default.
     * OWASP A09: tokens must not appear in logs or cache.
     *
     * On failure → InvalidCredentialsException → GlobalExceptionHandler → 401.
     */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(@Valid @RequestBody RefreshTokenRequest request) {

        ApiResponse<AuthResponse> response = authService.refresh(request);

        return ResponseEntity.ok(response);
    }

    // --- Logout

    /**
     * POST /auth/logout
     * Revokes the refresh token — truly ends the session.
     *
     * WHY logout requires authentication (JWT in header):
     * Without auth, anyone could logout any user by guessing their email.
     * The JWT in the Authorization header proves identity.
     * OWASP A01: authenticated action — only the token owner can logout.
     *
     * WHY POST and not DELETE:
     * Logout is an action (revoke session), not a resource deletion.
     * POST is semantically correct for actions.
     *
     * @AuthenticationPrincipal injects the email from the validated JWT.
     * The email comes from JwtAuthFilter → SecurityContext → here.
     * The client never sends their email — it comes from the trusted token.
     * OWASP A01: identity always from the validated token, never from request body.
     *
     * HTTP 200 — action completed, message in body confirms logout.
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody LogoutRequest logoutRequest,   // ← nuevo
            HttpServletRequest httpRequest) {

        return ResponseEntity.ok(
                authService.logout(
                        userDetails.getUsername(),
                        logoutRequest,                         // ← nuevo
                        httpRequest));
    }
}