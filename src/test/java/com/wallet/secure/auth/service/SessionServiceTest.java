package com.wallet.secure.auth.service;

import com.wallet.secure.auth.dto.SessionResponse;
import com.wallet.secure.auth.entity.Session;
import com.wallet.secure.auth.repository.SessionRepository;
import com.wallet.secure.auth.security.JwtService;
import com.wallet.secure.common.exception.InvalidCredentialsException;
import com.wallet.secure.common.exception.ResourceNotFoundException;
import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.user.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for SessionService.
 *
 * WHAT we test:
 * 1. createSession()      — builds entity with correct fields and hashes the token
 * 2. validateSession()    — rejects unknown, revoked and expired sessions
 * 3. revokeByToken()      — marks session as revoked, no-op when not found
 * 4. revokeAllSessions()  — delegates bulk update to repository
 * 5. revokeSessionById()  — ownership check (OWASP A01), already-revoked guard
 * 6. getActiveSessions()  — flags current session, handles null token
 * 7. hashToken()          — deterministic, 64-char hex output (SHA-256)
 *
 * WHAT we do NOT test:
 * → @Transactional behavior — requires Spring context
 * → Real SHA-256 correctness — guaranteed by the JVM spec
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SessionService")
class SessionServiceTest {

    @Mock private SessionRepository sessionRepository;
    @Mock private JwtService jwtService;

    @InjectMocks
    private SessionService sessionService;

    // ─── Shared test data

    private User testUser;
    private UUID userId;
    private UUID sessionId;

    private static final String RAW_TOKEN    = "test.refresh.token.device.A";
    private static final String OTHER_TOKEN  = "test.refresh.token.device.B";
    private static final String TEST_IP      = "192.168.1.100";
    private static final String TEST_UA      = "Mozilla/5.0 Test";

    @BeforeEach
    void setUp() {
        userId    = UUID.randomUUID();
        sessionId = UUID.randomUUID();

        testUser = User.builder()
                .id(userId)
                .email("angel@test.com")
                .passwordHash("$2a$12$hashedpassword")
                .build();
    }

    // ─── Helper — builds a minimal valid Session

    private Session buildActiveSession(String rawToken) {
        String hash = sessionService.hashToken(rawToken);
        return Session.builder()
                .user(testUser)
                .tokenHash(hash)
                .ipAddress(TEST_IP)
                .userAgent(TEST_UA)
                .expiresAt(Instant.now().plusSeconds(3600)) // expires in 1 hour
                .build();
    }

    private Session buildRevokedSession(String rawToken) {
        Session session = buildActiveSession(rawToken);
        session.revokeNow();
        return session;
    }

    private Session buildExpiredSession(String rawToken) {
        String hash = sessionService.hashToken(rawToken);
        return Session.builder()
                .user(testUser)
                .tokenHash(hash)
                .ipAddress(TEST_IP)
                .userAgent(TEST_UA)
                .expiresAt(Instant.now().minusSeconds(60)) // expired 1 minute ago
                .build();
    }

    // ─── createSession()

    @Nested
    @DisplayName("createSession()")
    class CreateSessionTests {

        @Test
        @DisplayName("saves session with hashed token — raw token never stored in DB")
        void createSession_savesHashedToken() {
            // GIVEN
            lenient().when(jwtService.getRefreshExpirationMs()).thenReturn(86_400_000L); // 1 day
            when(sessionRepository.save(any(Session.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            // WHEN
            sessionService.createSession(testUser, RAW_TOKEN, TEST_IP, TEST_UA);

            // THEN — capture what was saved
            ArgumentCaptor<Session> captor = ArgumentCaptor.forClass(Session.class);
            verify(sessionRepository).save(captor.capture());

            Session saved = captor.getValue();
            // OWASP A02: raw token is NEVER stored — only the SHA-256 hash
            assertThat(saved.getTokenHash()).isNotEqualTo(RAW_TOKEN);
            assertThat(saved.getTokenHash()).isEqualTo(sessionService.hashToken(RAW_TOKEN));
            assertThat(saved.getTokenHash()).hasSize(64); // SHA-256 in hex = 64 chars
        }

        @Test
        @DisplayName("saves session with correct user, ip and userAgent")
        void createSession_savesCorrectContext() {
            // GIVEN
            lenient().when(jwtService.getRefreshExpirationMs()).thenReturn(86_400_000L);
            when(sessionRepository.save(any(Session.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            // WHEN
            sessionService.createSession(testUser, RAW_TOKEN, TEST_IP, TEST_UA);

            // THEN
            ArgumentCaptor<Session> captor = ArgumentCaptor.forClass(Session.class);
            verify(sessionRepository).save(captor.capture());

            Session saved = captor.getValue();
            assertThat(saved.getUser()).isEqualTo(testUser);
            assertThat(saved.getIpAddress()).isEqualTo(TEST_IP);
            assertThat(saved.getUserAgent()).isEqualTo(TEST_UA);
            assertThat(saved.getExpiresAt()).isAfter(Instant.now());
        }
    }

    // ─── validateSession()

    @Nested
    @DisplayName("validateSession()")
    class ValidateSessionTests {

        @Test
        @DisplayName("returns session when token is valid and not expired")
        void validateSession_validToken_returnsSession() {
            // GIVEN
            Session activeSession = buildActiveSession(RAW_TOKEN);
            when(sessionRepository.findByTokenHash(sessionService.hashToken(RAW_TOKEN)))
                    .thenReturn(Optional.of(activeSession));

            // WHEN
            Session result = sessionService.validateSession(RAW_TOKEN);

            // THEN
            assertThat(result).isEqualTo(activeSession);
        }

        @Test
        @DisplayName("throws when session is not found — possible token reuse after logout")
        void validateSession_sessionNotFound_throwsException() {
            // GIVEN — token was never issued or was deleted
            when(sessionRepository.findByTokenHash(any())).thenReturn(Optional.empty());

            // WHEN / THEN
            // OWASP A07: unknown token = definitive rejection
            assertThatThrownBy(() -> sessionService.validateSession(RAW_TOKEN))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessageContaining("revoked");
        }

        @Test
        @DisplayName("throws when session is revoked — user already logged out")
        void validateSession_revokedSession_throwsException() {
            // GIVEN — user called logout → session was marked revoked
            Session revokedSession = buildRevokedSession(RAW_TOKEN);
            when(sessionRepository.findByTokenHash(any()))
                    .thenReturn(Optional.of(revokedSession));

            // WHEN / THEN
            // OWASP A07: revoked token cannot refresh — even with valid JWT signature
            assertThatThrownBy(() -> sessionService.validateSession(RAW_TOKEN))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessageContaining("revoked or expired");
        }

        @Test
        @DisplayName("throws when session is expired — natural expiration")
        void validateSession_expiredSession_throwsException() {
            // GIVEN — session was issued long ago and expiresAt < now
            Session expiredSession = buildExpiredSession(RAW_TOKEN);
            when(sessionRepository.findByTokenHash(any()))
                    .thenReturn(Optional.of(expiredSession));

            // WHEN / THEN
            assertThatThrownBy(() -> sessionService.validateSession(RAW_TOKEN))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessageContaining("revoked or expired");
        }
    }

    // ─── revokeByToken()

    @Nested
    @DisplayName("revokeByToken()")
    class RevokeByTokenTests {

        @Test
        @DisplayName("marks session as revoked when found")
        void revokeByToken_sessionFound_revokesSession() {
            // GIVEN
            Session activeSession = buildActiveSession(RAW_TOKEN);
            when(sessionRepository.findByTokenHash(sessionService.hashToken(RAW_TOKEN)))
                    .thenReturn(Optional.of(activeSession));
            when(sessionRepository.save(any(Session.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            // WHEN
            sessionService.revokeByToken(RAW_TOKEN);

            // THEN
            assertThat(activeSession.isRevoked()).isTrue();
            assertThat(activeSession.getRevokedAt()).isNotNull();
            verify(sessionRepository).save(activeSession);
        }

        @Test
        @DisplayName("does nothing (no-op) when session is not found — safe to call twice")
        void revokeByToken_sessionNotFound_doesNotThrow() {
            // GIVEN — token may have already expired and been cleaned up
            when(sessionRepository.findByTokenHash(any())).thenReturn(Optional.empty());

            // WHEN / THEN — must not throw; idempotent revocation
            assertThatNoException().isThrownBy(() -> sessionService.revokeByToken(RAW_TOKEN));
            verify(sessionRepository, never()).save(any());
        }
    }

    // ─── revokeAllSessions()

    @Nested
    @DisplayName("revokeAllSessions()")
    class RevokeAllSessionsTests {

        @Test
        @DisplayName("delegates bulk revocation to repository with userId and current time")
        void revokeAllSessions_delegatesToRepository() {
            // GIVEN — no return value needed for @Modifying query
            doNothing().when(sessionRepository)
                    .revokeAllActiveSessionsForUser(any(UUID.class), any(Instant.class));

            // WHEN
            sessionService.revokeAllSessions(userId);

            // THEN — bulk update is issued once with the correct userId
            ArgumentCaptor<Instant> timeCaptor = ArgumentCaptor.forClass(Instant.class);
            verify(sessionRepository).revokeAllActiveSessionsForUser(eq(userId), timeCaptor.capture());

            // The Instant passed must be "now" — allow 5 seconds of tolerance
            Instant revokedAt = timeCaptor.getValue();
            assertThat(revokedAt).isBefore(Instant.now().plusSeconds(1));
            assertThat(revokedAt).isAfter(Instant.now().minusSeconds(5));
        }
    }

    // ─── revokeSessionById()

    @Nested
    @DisplayName("revokeSessionById()")
    class RevokeSessionByIdTests {

        @Test
        @DisplayName("revokes session when it belongs to the requesting user — OWASP A01")
        void revokeSessionById_owner_revokesSuccessfully() {
            // GIVEN
            Session activeSession = buildActiveSession(RAW_TOKEN);
            when(sessionRepository.findById(sessionId))
                    .thenReturn(Optional.of(activeSession));
            when(sessionRepository.save(any(Session.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            // Inject a UUID field into the session for the test
            // Session.id is set by the DB — we need to simulate it here
            // We test ownership via User.id comparison, not Session.id

            // WHEN
            ApiResponse<Void> response = sessionService.revokeSessionById(sessionId, userId);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(activeSession.isRevoked()).isTrue();
        }

        @Test
        @DisplayName("throws 404 when session does not exist")
        void revokeSessionById_sessionNotFound_throwsNotFoundException() {
            // GIVEN
            when(sessionRepository.findById(sessionId)).thenReturn(Optional.empty());

            // WHEN / THEN
            assertThatThrownBy(() -> sessionService.revokeSessionById(sessionId, userId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Session not found");
        }

        @Test
        @DisplayName("throws 401 when session belongs to a different user — OWASP A01")
        void revokeSessionById_differentUser_throwsUnauthorized() {
            // GIVEN — session belongs to testUser but attacker uses their own userId
            UUID attackerId = UUID.randomUUID();
            Session victimSession = buildActiveSession(RAW_TOKEN);

            when(sessionRepository.findById(sessionId))
                    .thenReturn(Optional.of(victimSession));

            // WHEN / THEN
            // OWASP A01: user cannot revoke another user's session
            assertThatThrownBy(() -> sessionService.revokeSessionById(sessionId, attackerId))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessageContaining("Not authorized");

            verify(sessionRepository, never()).save(any());
        }

        @Test
        @DisplayName("returns success without re-revoking when session is already revoked")
        void revokeSessionById_alreadyRevoked_returnsSuccessIdempotent() {
            // GIVEN — session already revoked (user called this endpoint twice)
            Session revokedSession = buildRevokedSession(RAW_TOKEN);
            when(sessionRepository.findById(sessionId))
                    .thenReturn(Optional.of(revokedSession));

            // WHEN
            ApiResponse<Void> response = sessionService.revokeSessionById(sessionId, userId);

            // THEN — idempotent: success, but no extra save()
            assertThat(response.isSuccess()).isTrue();
            verify(sessionRepository, never()).save(any());
        }
    }

    // ─── getActiveSessions()

    @Nested
    @DisplayName("getActiveSessions()")
    class GetActiveSessionsTests {

        @Test
        @DisplayName("flags the session matching currentRefreshToken as current=true")
        void getActiveSessions_withMatchingToken_flagsCurrentSession() {
            // GIVEN — two active sessions; first one belongs to the current request
            Session currentSession = buildActiveSession(RAW_TOKEN);
            Session otherSession   = buildActiveSession(OTHER_TOKEN);

            when(sessionRepository.findActiveSessionsByUserId(eq(userId), any(Instant.class)))
                    .thenReturn(List.of(currentSession, otherSession));

            // WHEN
            ApiResponse<List<SessionResponse>> response =
                    sessionService.getActiveSessions(userId, RAW_TOKEN);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData()).hasSize(2);

            // The session that matches the current token must be flagged
            SessionResponse current = response.getData().get(0);
            SessionResponse other   = response.getData().get(1);

            assertThat(current.isCurrent()).isTrue();
            assertThat(other.isCurrent()).isFalse();
        }

        @Test
        @DisplayName("returns current=false for all sessions when currentRefreshToken is null")
        void getActiveSessions_nullToken_noSessionFlagged() {
            // GIVEN — caller did not provide a current token (e.g. admin lookup)
            Session session = buildActiveSession(RAW_TOKEN);
            when(sessionRepository.findActiveSessionsByUserId(eq(userId), any(Instant.class)))
                    .thenReturn(List.of(session));

            // WHEN
            ApiResponse<List<SessionResponse>> response =
                    sessionService.getActiveSessions(userId, null);

            // THEN — null token → no session can be flagged as current
            assertThat(response.getData().get(0).isCurrent()).isFalse();
        }

        @Test
        @DisplayName("returns empty list when user has no active sessions")
        void getActiveSessions_noSessions_returnsEmptyList() {
            // GIVEN
            when(sessionRepository.findActiveSessionsByUserId(eq(userId), any(Instant.class)))
                    .thenReturn(List.of());

            // WHEN
            ApiResponse<List<SessionResponse>> response =
                    sessionService.getActiveSessions(userId, null);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData()).isEmpty();
        }
    }

    // ─── hashToken()

    @Nested
    @DisplayName("hashToken()")
    class HashTokenTests {

        @Test
        @DisplayName("returns 64-character lowercase hex string — SHA-256 output")
        void hashToken_returnsCorrectFormat() {
            // WHEN
            String hash = sessionService.hashToken(RAW_TOKEN);

            // THEN — SHA-256 produces 32 bytes = 64 hex chars
            assertThat(hash).hasSize(64);
            assertThat(hash).matches("[0-9a-f]{64}");
        }

        @Test
        @DisplayName("is deterministic — same input always produces the same hash")
        void hashToken_deterministic_sameInputSameOutput() {
            // WHEN
            String hash1 = sessionService.hashToken(RAW_TOKEN);
            String hash2 = sessionService.hashToken(RAW_TOKEN);

            // THEN — SHA-256 is deterministic by definition
            // OWASP A02: lookup by hash only works if hash is reproducible
            assertThat(hash1).isEqualTo(hash2);
        }

        @Test
        @DisplayName("different tokens produce different hashes — no collisions")
        void hashToken_differentInputs_differentHashes() {
            // WHEN
            String hash1 = sessionService.hashToken(RAW_TOKEN);
            String hash2 = sessionService.hashToken(OTHER_TOKEN);

            // THEN — collision resistance: distinct tokens must not share a hash
            assertThat(hash1).isNotEqualTo(hash2);
        }
    }
}
