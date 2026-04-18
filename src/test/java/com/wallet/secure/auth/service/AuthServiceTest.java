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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AuthService.
 *
 * What we test:
 * 1. register()  — delegation to UserService + token generation
 * 2. login()     — authentication, failed attempts reset, tokens
 * 3. refresh()   — JWT validation + DB token validation
 * 4. logout()    — refresh token revocation in DB
 *
 * OWASP A07: these tests verify that authentication fails correctly
 * — not only that it works when credentials are valid.
 *
 * Mocks:
 * → AuthenticationManager — no full Spring Security context
 * → UserRepository        — no real DB
 * → JwtService            — we control what tokens are "generated"
 * → UserService           — already covered by its own tests
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService")
class AuthServiceTest {

    @Mock private AuthenticationManager authenticationManager;
    @Mock private UserRepository userRepository;
    @Mock private JwtService jwtService;
    @Mock private UserService userService;

    @InjectMocks
    private AuthService authService;

    // ─── Shared test data

    private User testUser;
    private final String TEST_EMAIL    = "angel@test.com";
    private final String ACCESS_TOKEN  = "access.jwt.token";
    private final String REFRESH_TOKEN = "refresh.jwt.token";

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(UUID.randomUUID())
                .email(TEST_EMAIL)
                .passwordHash("$2a$12$hashedpassword")
                .failedLoginAttempts(0)
                .build();

        /*
         * lenient() — these stubs apply to ALL tests via @BeforeEach.
         * Some tests fail before token generation is reached
         * (e.g. wrong password throws before generateAccessToken is called).
         * Without lenient() → UnnecessaryStubbingException on those tests.
         */
        lenient().when(jwtService.generateAccessToken(TEST_EMAIL))
                .thenReturn(ACCESS_TOKEN);
        lenient().when(jwtService.generateRefreshToken(TEST_EMAIL))
                .thenReturn(REFRESH_TOKEN);
        lenient().when(jwtService.getExpirationInSeconds())
                .thenReturn(900L);
    }

    // ─── register

    @Nested
    @DisplayName("register()")
    class RegisterTests {

        @Test
        @DisplayName("registers user and returns access + refresh tokens")
        void register_validRequest_returnsTokens() {
            // GIVEN
            RegisterRequest request = mock(RegisterRequest.class);
            when(request.getEmail()).thenReturn(TEST_EMAIL);

            // UserService.register() does not throw → user created successfully
            doNothing().when(userService).register(request);

            // After registration, AuthService loads the user by email to generate tokens
            when(userRepository.findByEmail(TEST_EMAIL))
                    .thenReturn(Optional.of(testUser));
            when(userRepository.save(any(User.class))).thenReturn(testUser);

            // WHEN
            ApiResponse<AuthResponse> response = authService.register(request);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData().getAccessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response.getData().getRefreshToken()).isEqualTo(REFRESH_TOKEN);

            // Refresh token was persisted in DB — enables future revocation on logout
            verify(userRepository, times(1)).save(any(User.class));
        }

        @Test
        @DisplayName("throws exception when user is not found immediately after creation")
        void register_userNotFoundAfterCreation_throwsException() {
            // GIVEN — edge case: UserService creates the user but findByEmail() fails
            // (race condition or consistency bug)
            RegisterRequest request = mock(RegisterRequest.class);
            when(request.getEmail()).thenReturn(TEST_EMAIL);
            doNothing().when(userService).register(request);
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

            // WHEN / THEN
            assertThatThrownBy(() -> authService.register(request))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("User not found immediately after creation");
        }
    }

    // ─── login

    @Nested
    @DisplayName("login()")
    class LoginTests {

        @Test
        @DisplayName("returns tokens on successful login")
        void login_validCredentials_returnsTokens() {
            // GIVEN
            LoginRequest request = mock(LoginRequest.class);
            when(request.getEmail()).thenReturn(TEST_EMAIL);
            when(request.getPassword()).thenReturn("SecurePass12!");

            // AuthenticationManager does not throw → credentials are valid
            doNothing().when(authenticationManager)
                    .authenticate(any(UsernamePasswordAuthenticationToken.class));

            when(userRepository.findByEmail(TEST_EMAIL))
                    .thenReturn(Optional.of(testUser));
            when(userRepository.save(any(User.class))).thenReturn(testUser);

            // WHEN
            ApiResponse<AuthResponse> response = authService.login(request);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData().getAccessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response.getData().getRefreshToken()).isEqualTo(REFRESH_TOKEN);
        }

        @Test
        @DisplayName("resets failed login attempts on successful login — OWASP A07")
        void login_success_resetsFailedAttempts() {
            // GIVEN — user had 2 previous failed attempts
            testUser.setFailedLoginAttempts(2);

            LoginRequest request = mock(LoginRequest.class);
            when(request.getEmail()).thenReturn(TEST_EMAIL);
            when(request.getPassword()).thenReturn("SecurePass12!");

            doNothing().when(authenticationManager)
                    .authenticate(any(UsernamePasswordAuthenticationToken.class));
            when(userRepository.findByEmail(TEST_EMAIL))
                    .thenReturn(Optional.of(testUser));
            when(userRepository.save(any(User.class))).thenReturn(testUser);

            // WHEN
            authService.login(request);

            // THEN — failed attempts reset to 0 after legitimate login
            // OWASP A07: prevents permanent lockout after a legitimate login
            assertThat(testUser.getFailedLoginAttempts()).isZero();
        }

        @Test
        @DisplayName("updates lastLoginAt on successful login")
        void login_success_updatesLastLoginAt() {
            // GIVEN — lastLoginAt was null (user had never logged in)
            assertThat(testUser.getLastLoginAt()).isNull();

            LoginRequest request = mock(LoginRequest.class);
            when(request.getEmail()).thenReturn(TEST_EMAIL);
            when(request.getPassword()).thenReturn("SecurePass12!");

            doNothing().when(authenticationManager)
                    .authenticate(any(UsernamePasswordAuthenticationToken.class));
            when(userRepository.findByEmail(TEST_EMAIL))
                    .thenReturn(Optional.of(testUser));
            when(userRepository.save(any(User.class))).thenReturn(testUser);

            // WHEN
            authService.login(request);

            // THEN — lastLoginAt was set — used for suspicious activity detection
            assertThat(testUser.getLastLoginAt()).isNotNull();
        }

        @Test
        @DisplayName("propagates BadCredentialsException on wrong password — OWASP A07")
        void login_wrongPassword_throwsBadCredentials() {
            // GIVEN — AuthenticationManager throws on invalid credentials
            LoginRequest request = mock(LoginRequest.class);
            when(request.getEmail()).thenReturn(TEST_EMAIL);
            when(request.getPassword()).thenReturn("WrongPassword!");

            doThrow(new BadCredentialsException("Bad credentials"))
                    .when(authenticationManager)
                    .authenticate(any(UsernamePasswordAuthenticationToken.class));

            // WHEN / THEN
            // OWASP A07: BadCredentialsException propagated to GlobalExceptionHandler
            // which returns 401 with a generic message — client cannot tell
            // whether the email or the password was wrong (prevents user enumeration)
            assertThatThrownBy(() -> authService.login(request))
                    .isInstanceOf(BadCredentialsException.class);

            // No tokens were generated — login failed before reaching token generation
            verify(jwtService, never()).generateAccessToken(any());
            verify(jwtService, never()).generateRefreshToken(any());
        }
    }

    // ─── refresh

    @Nested
    @DisplayName("refresh()")
    class RefreshTests {

        @Test
        @DisplayName("returns new access token with valid refresh token")
        void refresh_validToken_returnsNewAccessToken() {
            // GIVEN
            testUser.setRefreshToken(REFRESH_TOKEN);

            RefreshTokenRequest request = mock(RefreshTokenRequest.class);
            when(request.getRefreshToken()).thenReturn(REFRESH_TOKEN);

            when(jwtService.isRefreshTokenValid(REFRESH_TOKEN)).thenReturn(true);
            when(jwtService.extractEmail(REFRESH_TOKEN)).thenReturn(TEST_EMAIL);
            when(userRepository.findByEmail(TEST_EMAIL))
                    .thenReturn(Optional.of(testUser));

            String newAccessToken = "new.access.jwt.token";
            when(jwtService.generateAccessToken(TEST_EMAIL)).thenReturn(newAccessToken);

            // WHEN
            ApiResponse<AuthResponse> response = authService.refresh(request);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData().getAccessToken()).isEqualTo(newAccessToken);
        }

        @Test
        @DisplayName("throws exception when refresh token signature is invalid — OWASP A07")
        void refresh_invalidSignature_throwsException() {
            // GIVEN — token with invalid signature (tampered by attacker)
            RefreshTokenRequest request = mock(RefreshTokenRequest.class);
            when(request.getRefreshToken()).thenReturn("tampered.token.here");
            when(jwtService.isRefreshTokenValid("tampered.token.here")).thenReturn(false);

            // WHEN / THEN
            // Validation fails at JWT signature level — DB is never queried
            assertThatThrownBy(() -> authService.refresh(request))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessageContaining("Invalid or expired refresh token");

            verify(userRepository, never()).findByEmail(any());
        }

        @Test
        @DisplayName("throws exception when refresh token was revoked after logout — OWASP A07")
        void refresh_revokedToken_throwsException() {
            // GIVEN — user logged out → refreshToken in DB is null
            testUser.setRefreshToken(null);

            RefreshTokenRequest request = mock(RefreshTokenRequest.class);
            when(request.getRefreshToken()).thenReturn(REFRESH_TOKEN);
            when(jwtService.isRefreshTokenValid(REFRESH_TOKEN)).thenReturn(true);
            when(jwtService.extractEmail(REFRESH_TOKEN)).thenReturn(TEST_EMAIL);
            when(userRepository.findByEmail(TEST_EMAIL))
                    .thenReturn(Optional.of(testUser));

            // WHEN / THEN
            // OWASP A07: token revoked after logout — cannot be reused
            assertThatThrownBy(() -> authService.refresh(request))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessageContaining("revoked");
        }

        @Test
        @DisplayName("throws exception when token does not match DB — token reuse attack")
        void refresh_tokenMismatch_throwsException() {
            // GIVEN — attacker uses an old refresh token
            // the user already has a new one in DB (token rotation scenario)
            testUser.setRefreshToken("different.token.in.db");

            RefreshTokenRequest request = mock(RefreshTokenRequest.class);
            when(request.getRefreshToken()).thenReturn(REFRESH_TOKEN);
            when(jwtService.isRefreshTokenValid(REFRESH_TOKEN)).thenReturn(true);
            when(jwtService.extractEmail(REFRESH_TOKEN)).thenReturn(TEST_EMAIL);
            when(userRepository.findByEmail(TEST_EMAIL))
                    .thenReturn(Optional.of(testUser));

            // WHEN / THEN
            // OWASP A07: detects stale token reuse attempt
            assertThatThrownBy(() -> authService.refresh(request))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessageContaining("revoked");
        }
    }

    // ─── logout

    @Nested
    @DisplayName("logout()")
    class LogoutTests {

        @Test
        @DisplayName("clears refresh token from DB on logout — OWASP A07")
        void logout_authenticatedUser_clearsRefreshToken() {
            // GIVEN — user has an active refresh token
            testUser.setRefreshToken(REFRESH_TOKEN);
            when(userRepository.findByEmail(TEST_EMAIL))
                    .thenReturn(Optional.of(testUser));
            when(userRepository.save(any(User.class))).thenReturn(testUser);

            // WHEN
            ApiResponse<Void> response = authService.logout(TEST_EMAIL);

            // THEN
            assertThat(response.isSuccess()).isTrue();

            // Refresh token removed from DB — future /refresh calls will fail
            // OWASP A07: real server-side logout, not just client-side token deletion
            assertThat(testUser.getRefreshToken()).isNull();
            verify(userRepository, times(1)).save(testUser);
        }

        @Test
        @DisplayName("throws exception when user is not found during logout")
        void logout_userNotFound_throwsException() {
            // GIVEN
            when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

            // WHEN / THEN
            assertThatThrownBy(() -> authService.logout(TEST_EMAIL))
                    .isInstanceOf(InvalidCredentialsException.class);

            // Nothing was saved — user didn't exist
            verify(userRepository, never()).save(any());
        }
    }
}