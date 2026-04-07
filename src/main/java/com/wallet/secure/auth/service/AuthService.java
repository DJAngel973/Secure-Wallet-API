package com.wallet.secure.auth.service;

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
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import java.time.Instant;
import com.wallet.secure.common.util.LogSanitizer;

/**
 * Handles all authentication operations: register, login, refresh, logout.
 *
 * Why AuthService is separate from UserService:
 * UserService manages user data (profile, password update, deactivation)
 * AuthService manages sessions (tokens, login attempts, logout)
 * Single Responsibility - each service has one reason to change.
 *
 * OWASP A07: This clas is the main defense against authentication failures.
 * Every method here has a direct security implication.
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final UserService userService;

    // --- Register

    /**
     * Creates a new account and returns tokens immediately.
     *
     * Why return tokens on register (not just 201 created):
     * The user is already authentication after registration.
     * Forcing an extra login step adds friction with no security benefit.
     * Standard practice: register -> auto-login -> redirect to dashboard.
     *
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
    public ApiResponse<AuthResponse> register(RegisterRequest request) {

        // Step 1 - Create user (UserService handles email duplicate check + BCrypt)
        userService.register(request);

        // Step 2 - load the just-created user to generate tokens
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalStateException(
                        "User not found immediately after creation"));

        // Step 3 - generate tokens and persist refresh token
        AuthResponse tokens = generateAndSaveTokens(user);
        log.info("New user registered: {}", LogSanitizer.sanitize(request.getEmail()));

        return ApiResponse.ok("Registration successful", tokens);
    }

    // --- Private Helpers

    /**
     * Generates both tokens and persists the refresh token in DB.
     * Single method for register and login - avoids duplication.
     *
     * Why persist the refresh token:
     * Enables real logout - setRefreshToken(null) = session revoked.
     *
     * OWASP A07: without DB persistence, logout is just client-side
     */
    private AuthResponse generateAndSaveTokens(User user) {
        String accessToken = jwtService.generateAccessToken(user.getEmail());
        String refreshToken = jwtService.generateRefreshToken(user.getEmail());

        // Persist refresh token - enable revocation on logout
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        return AuthResponse.of(
                accessToken,
                refreshToken,
                jwtService.getExpirationInSeconds()
        );
    }

    // --- Login

    /**
     * Authenticates credentials and return tokens.
     *
     * Why use AuthenticationManager instead of manual password check:
     * AuthenticationManager delegates to UserDetailsServiceImpl
     * With checks: password match + account locked + account active.
     * All these checks happen in one call - no risk of forgetting one.
     *
     * OWASP A07:
     * - BadCredentialsException -> same message as "User not found" (prevents user enumeration)
     * - Failed attempts tracked -> account lockout after 3 failures
     * - LastLoginAt updated on success -> suspicious activity detection
     *
     * @param request DTO with email and password
     * @return ApiResponse wrapping AuthResponse with both tokens
     */
    @Transactional
    public ApiResponse<AuthResponse> login(LoginRequest request) {

        // This call triggers:
        // 1. UserDetailsServiceImpl.loadUserByUsername(email)
        // 2. BCrypt.matches(plainPassword, storedHash)
        // 3. AccountLocked / Disabled checks
        // Throws BadCredentialsException or LockedException on failure
        // Both are handled by GlobalExceptionHandler -> 401 / 423
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // Only reached if authentication succeeded
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid credentials"));

        // Reset failed attempts counter + update lastLoginAt
        // OWASP A07: counter reset prevents permanent lockout after legitime login
        user.resetFailedLoginAttempts();
        user.setLastLoginAt(Instant.now());

        // Generate tokens and persist refresh token
        AuthResponse tokens = generateAndSaveTokens(user);
        log.info("Successful login: {}", LogSanitizer.sanitize(request.getEmail()));

        return ApiResponse.ok("Login successful", tokens);
    }

    // --- Refresh

    /**
     * Issues a new access token using a valid refresh token.
     *
     * Why validate refresh token against DB (not just the JWT signature):
     * JWT signature alone tells us the token was legitimately issued.
     * DB validation tells us the token has NOT been revoked (logout happened).
     * Without DB check: logout is cosmetic - the refresh token still works.
     * OWASP A07: stateful refresh token = real revocation capability.
     *
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
            log.warn("Refresh token mismatch for user: {} - possible token reuse after logout", LogSanitizer.sanitize(email));
            throw new InvalidCredentialsException("Refresh token has been revoked");
        }

        // Step 4 - generate only a new access token
        // Refresh token stays the same - client already has it
        String newAccessToken = jwtService.generateAccessToken(email);
        AuthResponse response = AuthResponse.refreshed(
                newAccessToken,
                jwtService.getExpirationInSeconds()
        );
        log.info("Token refreshed for: {}", LogSanitizer.sanitize(email));

        return ApiResponse.ok("Token refreshed", response);
    }

    // --- Logout

    /**
     * Revokes the refresh token by removing it from DB
     *
     * Why logout only removes the refresh token (not access token):
     * Access tokens are stateless - they cannot be "revoked" without a blacklist.
     * But they expire in 15 minutes - acceptable window.
     * Removing the refresh token ensures:
     * -> The user cannot silently obtain a new access token
     * -> After 15 min the access token expires and the session truly ends
     *
     * OWASP A07: real session termination within 15 minutes maximum.
     *
     * @param email the authentication user's email (from SecurityContext)
     */
    @Transactional
    public ApiResponse<Void> logout(String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidCredentialsException("User not found"));

        // Remove refresh token from DB - future refresh calls will fail
        user.setRefreshToken(null);
        userRepository.save(user);
        log.info("User logged out: {}", LogSanitizer.sanitize(email));

        return ApiResponse.ok("Logout successful", null);
    }
}