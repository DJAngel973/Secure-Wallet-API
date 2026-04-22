package com.wallet.secure.auth.service;

import com.wallet.secure.audit.service.AuditService;
import com.wallet.secure.auth.dto.AuthResponse;
import com.wallet.secure.auth.dto.LoginRequest;
import com.wallet.secure.auth.dto.RefreshTokenRequest;
import com.wallet.secure.auth.security.JwtService;
import com.wallet.secure.common.exception.InvalidCredentialsException;
import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.user.dto.RegisterRequest;
import com.wallet.secure.user.entity.User;
import com.wallet.secure.user.repository.UserRepository;
import com.wallet.secure.user.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.wallet.secure.auth.dto.LogoutRequest;

import java.time.Instant;

/**
 * Handles all authentication operations: register, login, refresh, logout.
 * Why AuthService is separate from UserService:
 * UserService manages user data (profile, password update, deactivation)
 * AuthService manages sessions (tokens, login attempts, logout)
 * Single Responsibility - each service has one reason to change.
 * AuditService integration:
 * Every authentication event (success AND failure) is logged.
 * OWASP A07 + A09: authentication failures are the primary signal
 * for brute force detection and account compromise investigation
 * HttpServiceRequest is injected to extract:
 * -> IP address (X-Forwarded-For or remoteAddr)
 * -> User-Agent(browser/device fingerprint)
 * Both are stored in audit_logs for forensic analysis
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final UserService userService;
    private final AuditService auditService;
    private final SessionService sessionService;

    // --- Register

    /**
     * Creates a new account and returns tokens immediately.
     * <p>
     * Why return tokens on register (not just 201 created):
     * The user is already authentication after registration.
     * Forcing an extra login step adds friction with no security benefit.
     * Standard practice: register -> auto-login -> redirect to dashboard.
     * </p>
     * Flow:
     * 1. Delegate account creation to UserService (validates email, hashes password)
     * 2. Generate access + refresh tokens
     * 3. Save refresh token in DB
     * 4. Return AuthResponse
     *
     * @param request DTO with email and password (validated by @Valid at controller)
     * @return ApiResponse wrapping AuthResponse with both tokens
     */
    @Transactional
    public ApiResponse<AuthResponse> register(RegisterRequest request, HttpServletRequest  httpRequest) {

        // Step 1 - Create user (UserService handles email duplicate check + BCrypt)
        userService.register(request);

        // Step 2 - load the just-created user to generate tokens
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalStateException(
                        "User not found immediately after creation"));

        // Step 3 - generate tokens and persist refresh token
        AuthResponse tokens = generateAndSaveTokens(user, extractIp(httpRequest), extractUserAgent(httpRequest));
        auditService.logRegister(
                user.getId(),
                user.getEmail(),
                extractIp(httpRequest),
                extractUserAgent(httpRequest));

        log.info("New user registered: {}", user.getId());
        return ApiResponse.ok("Registration successful", tokens);
    }

    // --- Private Helpers

    /**
     * Generates both tokens and persists the refresh token in DB.
     * Single method for register and login - avoids duplication.
     * <p>
     * Why persist the refresh token:
     * Enables real logout - setRefreshToken(null) = session revoked.
     * </p>
     * OWASP A07: without DB persistence, logout is just client-side
     */
    private AuthResponse generateAndSaveTokens(User user, String ipAddress, String userAgent) {
        String accessToken = jwtService.generateAccessToken(user.getEmail());
        String refreshToken = jwtService.generateRefreshToken(user.getEmail());

        // Persist refresh token - enable revocation on logout
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        sessionService.createSession(user, refreshToken, ipAddress, userAgent);

        return AuthResponse.of(
                accessToken,
                refreshToken,
                jwtService.getExpirationInSeconds()
        );
    }

    /**
     * Extracts client IP - checks X-Forwarded-For first (behind reverse proxy)
     * Falls back to remoteAddr for direct connections.
     * OWASP A09: accurate IP is critical for geographic anomaly detection
     */
    private String extractIp(HttpServletRequest request) {
        if (request == null) return "unknown";
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
            // The first one is the real client IP
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    /**
     * Extracts the User-Agent header for device fingerprinting.
     * Returns "unknown" if not present - never null.
     */
    private String extractUserAgent(HttpServletRequest request) {
        if (request == null) return "unknown";
        String ua = request.getHeader("User-Agent");
        return (ua != null && !ua.isBlank()) ? ua : "unknown";
    }

    // --- Login

    /**
     * Authenticates credentials and return tokens.
     * <p>
     * Why use AuthenticationManager instead of manual password check:
     * AuthenticationManager delegates to UserDetailsServiceImpl
     * With checks: password match + account locked + account active.
     * All these checks happen in one call - no risk of forgetting one.
     * </p>
     * OWASP A07:
     * - BadCredentialsException -> same message as "User not found" (prevents user enumeration)
     * - Failed attempts tracked -> account lockout after 3 failures
     * - LastLoginAt updated on success -> suspicious activity detection
     *
     * @param request DTO with email and password
     * @return ApiResponse wrapping AuthResponse with both tokens
     */
    @Transactional
    public ApiResponse<AuthResponse> login(LoginRequest request, HttpServletRequest httpRequest) {

        String ip = extractIp(httpRequest);
        String userAgent = extractUserAgent(httpRequest);

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()));
        } catch (LockedException e) {
            // Account is locked - log as WARNING, not CRITICAL (already handled)
            userRepository.findByEmail(request.getEmail()).ifPresent(user ->
                    auditService.logLoginFailure(user.getId(),
                            request.getEmail(),
                            "Account locked", extractIp(httpRequest), extractUserAgent(httpRequest)));
            throw e;
        } catch (BadCredentialsException e) {
            // Log failure - check if brute force threshold is reached
            userRepository.findByEmail(request.getEmail()).ifPresent(user -> {
                auditService.logLoginFailure(user.getId(),
                        request.getEmail(),
                        "Bad credentials", extractIp(httpRequest), extractUserAgent(httpRequest));
                // OWASP A07: brute force detection
                // If >= 5 failures in 15 minutes -> CRITICAL alert
                long recentFailures = auditService.countRecentFailedLogins(user.getId(), 15);
                if (recentFailures >= 5) {
                    auditService.logCriticalSecurityEvent(
                            user.getId(),
                            String.format("Brute force detected: %s failed logins in 15 minutes", recentFailures),

                            extractIp(httpRequest), extractUserAgent(httpRequest));
                }
            });
            throw e;
        }

        // Only reached if authentication succeeded
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid credentials"));

        // Reset failed attempts counter + update lastLoginAt
        // OWASP A07: counter reset prevents permanent lockout after legitime login
        user.resetFailedLoginAttempts();
        user.setLastLoginAt(Instant.now());

        // Generate tokens and persist refresh token
        AuthResponse tokens = generateAndSaveTokens(user, ip, userAgent);
        // OWASP A09: log successful login with IP and device
        auditService.logLoginSuccess(user.getId(),
                user.getEmail(), extractIp(httpRequest), extractUserAgent(httpRequest));

        log.info("Successful login: userId={}", user.getId());
        return ApiResponse.ok("Login successful", tokens);
    }

    // --- Refresh

    /**
     * Issues a new access token using a valid refresh token.
     * <p>
     * Why validate refresh token against DB (not just the JWT signature):
     * JWT signature alone tells us the token was legitimately issued.
     * DB validation tells us the token has NOT been revoked (logout happened).
     * Without DB check: logout is cosmetic - the refresh token still works.
     * OWASP A07: stateful refresh token = real revocation capability.
     * </p>
     * Flow:
     * 1. Validate JWT signature and expiration of refresh token
     * 2. Check refresh token exists in DB (not revoked by logout)
     * 3. Generate new access token
     * 4. Return new access token (refresh token stays the same)
     *
     * @param request DTO with refreshToken
     * @return ApiResponse with new access token (refresh token not rotated here)
     */
    @Transactional
    public ApiResponse<AuthResponse> refresh(RefreshTokenRequest request)  {

        String refreshToken = request.getRefreshToken();

        // Step 1 - validate JWT signature + expiration + type="refresh"
        if (!jwtService.isRefreshTokenValid(refreshToken)) {
            throw new InvalidCredentialsException("Invalid or expired refresh token");
        }

        // Step 2 - extract email and find user
        String email = jwtService.extractEmail(refreshToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidCredentialsException("Invalid refresh token"));

        // Step 3 - verify token matches DB (not revoked)
        // OWASP A07: token revocation - logout deletes the DB token
        if (!refreshToken.equals(user.getRefreshToken())) {
            log.warn("Refresh token mismatch for userId= {} - possible token reuse after logout", user.getId());
            throw new InvalidCredentialsException("Refresh token has been revoked");
        }
        sessionService.validateSession(refreshToken);

        // Step 4 - generate only a new access token
        // Refresh token stays the same - client already has it
        String newAccessToken = jwtService.generateAccessToken(email);
        AuthResponse response = AuthResponse.refreshed(
                newAccessToken,
                jwtService.getExpirationInSeconds()
        );
        log.info("Token refreshed for: userI={}", user.getId());

        return ApiResponse.ok("Token refreshed", response);
    }

    // --- Logout

    /**
     * Revokes the refresh token by removing it from DB
     * <p>
     * Why logout only removes the refresh token (not access token):
     * Access tokens are stateless - they cannot be "revoked" without a blacklist.
     * But they expire in 15 minutes - acceptable window.
     * Removing the refresh token ensures:
     * -> The user cannot silently obtain a new access token
     * -> After 15 min the access token expires and the session truly ends
     * </p>
     * OWASP A07: real session termination within 15 minutes maximum.
     *
     * @param email the authentication user's email (from SecurityContext)
     */
    @Transactional
    public ApiResponse<Void> logout(String email, LogoutRequest logoutRequest, HttpServletRequest httpRequest) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidCredentialsException("User not found"));

        // Remove refresh token from DB - future refresh calls will fail
        user.setRefreshToken(null);
        userRepository.save(user);

        sessionService.revokeByToken(logoutRequest.getRefreshToken());

        //OWASP A09: log every logout - session termination must be auditable
        auditService.logLogout(
                user.getId(),
                user.getEmail(),
                extractIp(httpRequest),
                extractUserAgent(httpRequest));

        log.info("User logged out: userId={}", user.getId());

        return ApiResponse.ok("Logout successful", null);
    }
}