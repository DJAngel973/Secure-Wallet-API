package com.wallet.secure.audit.service;

import com.wallet.secure.audit.entity.AuditLog;
import com.wallet.secure.audit.repository.AuditLogRepository;
import com.wallet.secure.common.enums.AuditAction;
import com.wallet.secure.common.enums.LogSeverity;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AuditService.
 *
 * WHAT we test:
 * 1. Each log method saves an AuditLog with the correct action and severity
 * 2. JSONB details contain the expected fields (outcome, email, type, etc.)
 * 3. save() failure NEVER throws — fallback to Log4j2 (OWASP A09)
 * 4. countRecentFailedLogins() delegates correctly to the repository
 * 5. logCriticalSecurityEvent() uses CRITICAL severity
 *
 * WHAT we do NOT test:
 * → @Async behavior — requires Spring context, covered by integration tests
 * → @Transactional(REQUIRES_NEW) — same reason
 * → These are infrastructure concerns, not business logic
 *
 * WHY ArgumentCaptor:
 * AuditService calls auditLogRepository.save(auditLog).
 * We capture the AuditLog passed to save() and assert its fields.
 * This verifies the service builds the entity correctly.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuditService")
class AuditServiceTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @InjectMocks
    private AuditService auditService;

    // ─── Shared test data

    private UUID userId;
    private final String TEST_EMAIL  = "angel@test.com";
    private final String TEST_IP     = "192.168.1.100";
    private final String TEST_UA     = "Mozilla/5.0 Test";

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        // save() returns the entity passed — standard stub for repository saves
        lenient().when(auditLogRepository.save(any(AuditLog.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    // ─── Authentication Events

    @Nested
    @DisplayName("logLoginSuccess()")
    class LogLoginSuccessTests {

        @Test
        @DisplayName("saves audit log with USER_LOGIN action and INFO severity")
        void logLoginSuccess_savesCorrectActionAndSeverity() {
            // WHEN
            auditService.logLoginSuccess(userId, TEST_EMAIL, TEST_IP, TEST_UA);

            // THEN — capture what was passed to save()
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog saved = captor.getValue();
            assertThat(saved.getAction()).isEqualTo(AuditAction.USER_LOGIN);
            assertThat(saved.getSeverityLevel()).isEqualTo(LogSeverity.INFO);
            assertThat(saved.getUserId()).isEqualTo(userId);
            assertThat(saved.getIpAddress()).isEqualTo(TEST_IP);
            assertThat(saved.getUserAgent()).isEqualTo(TEST_UA);
        }

        @Test
        @DisplayName("details JSONB contains email and SUCCESS outcome")
        void logLoginSuccess_detailsContainEmailAndOutcome() {
            // WHEN
            auditService.logLoginSuccess(userId, TEST_EMAIL, TEST_IP, TEST_UA);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            String details = captor.getValue().getDetails();
            assertThat(details).contains("\"email\":\"" + TEST_EMAIL + "\"");
            assertThat(details).contains("\"outcome\":\"SUCCESS\"");
        }
    }

    @Nested
    @DisplayName("logLoginFailure()")
    class LogLoginFailureTests {

        @Test
        @DisplayName("saves audit log with USER_LOGIN action and WARNING severity")
        void logLoginFailure_savesCorrectActionAndSeverity() {
            // WHEN
            auditService.logLoginFailure(userId, TEST_EMAIL, "Bad credentials", TEST_IP, TEST_UA);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog saved = captor.getValue();
            assertThat(saved.getAction()).isEqualTo(AuditAction.USER_LOGIN);
            assertThat(saved.getSeverityLevel()).isEqualTo(LogSeverity.WARNING);
        }

        @Test
        @DisplayName("details JSONB contains email, FAILURE outcome and reason")
        void logLoginFailure_detailsContainFailureAndReason() {
            // WHEN
            auditService.logLoginFailure(userId, TEST_EMAIL, "Bad credentials", TEST_IP, TEST_UA);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            String details = captor.getValue().getDetails();
            assertThat(details).contains("\"outcome\":\"FAILURE\"");
            assertThat(details).contains("\"reason\":\"Bad credentials\"");
            assertThat(details).contains("\"email\":\"" + TEST_EMAIL + "\"");
        }

        @Test
        @DisplayName("accepts null userId — user may not exist when login fails")
        void logLoginFailure_nullUserId_savesWithoutError() {
            // GIVEN — attacker trying a non-existent email
            // userId is null because the user was not found
            // WHEN / THEN — must not throw
            assertThatNoException().isThrownBy(() ->
                    auditService.logLoginFailure(null, "nonexistent@test.com",
                            "Bad credentials", TEST_IP, TEST_UA));

            verify(auditLogRepository).save(any(AuditLog.class));
        }
    }

    @Nested
    @DisplayName("logLogout()")
    class LogLogoutTests {

        @Test
        @DisplayName("saves audit log with USER_LOGOUT action and INFO severity")
        void logLogout_savesCorrectActionAndSeverity() {
            // WHEN
            auditService.logLogout(userId, TEST_EMAIL, TEST_IP, TEST_UA);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog saved = captor.getValue();
            assertThat(saved.getAction()).isEqualTo(AuditAction.USER_LOGOUT);
            assertThat(saved.getSeverityLevel()).isEqualTo(LogSeverity.INFO);
        }
    }

    @Nested
    @DisplayName("logRegister()")
    class LogRegisterTests {

        @Test
        @DisplayName("saves audit log with USER_REGISTER action and INFO severity")
        void logRegister_savesCorrectActionAndSeverity() {
            // WHEN
            auditService.logRegister(userId, TEST_EMAIL, TEST_IP, TEST_UA);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog saved = captor.getValue();
            assertThat(saved.getAction()).isEqualTo(AuditAction.USER_REGISTER);
            assertThat(saved.getSeverityLevel()).isEqualTo(LogSeverity.INFO);
        }
    }

    // ─── Transaction Events

    @Nested
    @DisplayName("logTransactionSuccess()")
    class LogTransactionSuccessTests {

        @Test
        @DisplayName("saves audit log with TRANSACTION_COMPLETE action and INFO severity")
        void logTransactionSuccess_savesCorrectActionAndSeverity() {
            // GIVEN
            UUID transactionId = UUID.randomUUID();

            // WHEN
            auditService.logTransactionSuccess(
                    userId, transactionId, "DEPOSIT", "200.00", "USD", TEST_IP, TEST_UA);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog saved = captor.getValue();
            assertThat(saved.getAction()).isEqualTo(AuditAction.TRANSACTION_COMPLETE);
            assertThat(saved.getSeverityLevel()).isEqualTo(LogSeverity.INFO);
        }

        @Test
        @DisplayName("details JSONB contains transactionId, type, amount, currency and SUCCESS outcome")
        void logTransactionSuccess_detailsContainAllFields() {
            // GIVEN
            UUID transactionId = UUID.randomUUID();

            // WHEN
            auditService.logTransactionSuccess(
                    userId, transactionId, "DEPOSIT", "200.00", "USD", TEST_IP, TEST_UA);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            String details = captor.getValue().getDetails();
            assertThat(details).contains("\"transactionId\":\"" + transactionId + "\"");
            assertThat(details).contains("\"type\":\"DEPOSIT\"");
            assertThat(details).contains("\"amount\":\"200.00\"");
            assertThat(details).contains("\"currency\":\"USD\"");
            assertThat(details).contains("\"outcome\":\"SUCCESS\"");
        }
    }

    @Nested
    @DisplayName("logTransactionFailure()")
    class LogTransactionFailureTests {

        @Test
        @DisplayName("saves audit log with TRANSACTION_FAIL action and ERROR severity")
        void logTransactionFailure_savesCorrectActionAndSeverity() {
            // WHEN
            auditService.logTransactionFailure(
                    userId, "WITHDRAWAL", "Insufficient balance", TEST_IP, TEST_UA);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog saved = captor.getValue();
            assertThat(saved.getAction()).isEqualTo(AuditAction.TRANSACTION_FAIL);
            assertThat(saved.getSeverityLevel()).isEqualTo(LogSeverity.ERROR);
        }

        @Test
        @DisplayName("details JSONB contains type, FAILURE outcome and reason")
        void logTransactionFailure_detailsContainFailureAndReason() {
            // WHEN
            auditService.logTransactionFailure(
                    userId, "WITHDRAWAL", "Insufficient balance", TEST_IP, TEST_UA);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            String details = captor.getValue().getDetails();
            assertThat(details).contains("\"type\":\"WITHDRAWAL\"");
            assertThat(details).contains("\"outcome\":\"FAILURE\"");
            assertThat(details).contains("\"reason\":\"Insufficient balance\"");
        }
    }

    // ─── Wallet Events

    @Nested
    @DisplayName("logWalletCreated()")
    class LogWalletCreatedTests {

        @Test
        @DisplayName("saves audit log with WALLET_CREATE action and INFO severity")
        void logWalletCreated_savesCorrectActionAndSeverity() {
            // GIVEN
            UUID walletId = UUID.randomUUID();

            // WHEN
            auditService.logWalletCreated(userId, walletId, "USD", TEST_IP, TEST_UA);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog saved = captor.getValue();
            assertThat(saved.getAction()).isEqualTo(AuditAction.WALLET_CREATE);
            assertThat(saved.getSeverityLevel()).isEqualTo(LogSeverity.INFO);
        }

        @Test
        @DisplayName("details JSONB contains walletId, currency and SUCCESS outcome")
        void logWalletCreated_detailsContainWalletIdAndCurrency() {
            // GIVEN
            UUID walletId = UUID.randomUUID();

            // WHEN
            auditService.logWalletCreated(userId, walletId, "USD", null, null);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            String details = captor.getValue().getDetails();
            assertThat(details).contains("\"walletId\":\"" + walletId + "\"");
            assertThat(details).contains("\"currency\":\"USD\"");
            assertThat(details).contains("\"outcome\":\"SUCCESS\"");
        }
    }

    @Nested
    @DisplayName("logWalletSuspended()")
    class LogWalletSuspendedTests {

        @Test
        @DisplayName("saves audit log with WALLET_SUSPEND action and WARNING severity")
        void logWalletSuspended_savesCorrectActionAndSeverity() {
            // GIVEN
            UUID walletId = UUID.randomUUID();

            // WHEN
            auditService.logWalletSuspended(userId, walletId, null, null);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog saved = captor.getValue();
            assertThat(saved.getAction()).isEqualTo(AuditAction.WALLET_SUSPEND);
            // WARNING — suspension is a security-relevant admin action
            assertThat(saved.getSeverityLevel()).isEqualTo(LogSeverity.WARNING);
        }
    }

    @Nested
    @DisplayName("logWalletClosed()")
    class LogWalletClosedTests {

        @Test
        @DisplayName("saves audit log with WALLET_CLOSE action and WARNING severity")
        void logWalletClosed_savesCorrectActionAndSeverity() {
            // GIVEN
            UUID walletId = UUID.randomUUID();

            // WHEN
            auditService.logWalletClosed(userId, walletId, null, null);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog saved = captor.getValue();
            assertThat(saved.getAction()).isEqualTo(AuditAction.WALLET_CLOSE);
            assertThat(saved.getSeverityLevel()).isEqualTo(LogSeverity.WARNING);
        }
    }

    // ─── Security Events

    @Nested
    @DisplayName("logCriticalSecurityEvent()")
    class LogCriticalSecurityEventTests {

        @Test
        @DisplayName("saves audit log with CRITICAL severity — OWASP A09")
        void logCriticalSecurityEvent_savesCriticalSeverity() {
            // WHEN
            auditService.logCriticalSecurityEvent(
                    userId, "Brute force detected: 5 failed logins", TEST_IP, TEST_UA);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            AuditLog saved = captor.getValue();
            // CRITICAL — requires immediate human investigation
            assertThat(saved.getSeverityLevel()).isEqualTo(LogSeverity.CRITICAL);
        }

        @Test
        @DisplayName("details JSONB contains reason and FAILURE outcome")
        void logCriticalSecurityEvent_detailsContainReasonAndFailure() {
            // WHEN
            auditService.logCriticalSecurityEvent(
                    userId, "Brute force detected: 5 failed logins", TEST_IP, TEST_UA);

            // THEN
            ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
            verify(auditLogRepository).save(captor.capture());

            String details = captor.getValue().getDetails();
            assertThat(details).contains("\"reason\":\"Brute force detected: 5 failed logins\"");
            assertThat(details).contains("\"outcome\":\"FAILURE\"");
        }
    }

    // ─── Resilience — save failure must NOT crash the app

    @Nested
    @DisplayName("save() resilience")
    class SaveResilienceTests {

        @Test
        @DisplayName("does NOT throw when repository save fails — OWASP A09 best-effort")
        void save_repositoryThrows_doesNotPropagateException() {
            // GIVEN — DB is down or unavailable
            doThrow(new RuntimeException("DB connection lost"))
                    .when(auditLogRepository).save(any(AuditLog.class));

            // WHEN / THEN — the business operation must NOT be affected
            // logLoginSuccess calls save() internally — exception must be swallowed
            assertThatNoException().isThrownBy(() ->
                    auditService.logLoginSuccess(userId, TEST_EMAIL, TEST_IP, TEST_UA));
        }

        @Test
        @DisplayName("does NOT throw when repository fails during transaction audit")
        void save_repositoryThrowsDuringTransaction_doesNotPropagateException() {
            // GIVEN
            doThrow(new RuntimeException("DB connection lost"))
                    .when(auditLogRepository).save(any(AuditLog.class));

            // WHEN / THEN — a failed DB write must not kill the transaction
            assertThatNoException().isThrownBy(() ->
                    auditService.logTransactionFailure(
                            userId, "TRANSFER", "Insufficient balance", TEST_IP, TEST_UA));
        }
    }

    // ─── Brute Force Detection

    @Nested
    @DisplayName("countRecentFailedLogins()")
    class CountRecentFailedLoginsTests {

        @Test
        @DisplayName("delegates to repository with correct time window")
        void countRecentFailedLogins_delegatesToRepository() {
            // GIVEN — repository returns 3 failures in the last 15 minutes
            when(auditLogRepository.countFailedLoginsSince(any(UUID.class), any(Instant.class)))
                    .thenReturn(3L);

            // WHEN
            long count = auditService.countRecentFailedLogins(userId, 15);

            // THEN
            assertThat(count).isEqualTo(3L);
            verify(auditLogRepository).countFailedLoginsSince(eq(userId), any(Instant.class));
        }

        @Test
        @DisplayName("returns 0 when no recent failures exist")
        void countRecentFailedLogins_noFailures_returnsZero() {
            // GIVEN
            when(auditLogRepository.countFailedLoginsSince(any(UUID.class), any(Instant.class)))
                    .thenReturn(0L);

            // WHEN
            long count = auditService.countRecentFailedLogins(userId, 15);

            // THEN
            assertThat(count).isZero();
        }

        @Test
        @DisplayName("passes correct time window — 15 minutes = since 15 min ago")
        void countRecentFailedLogins_passesCorrectTimeWindow() {
            // GIVEN
            when(auditLogRepository.countFailedLoginsSince(any(), any())).thenReturn(0L);

            Instant before = Instant.now().minusSeconds(15 * 60 + 2);

            // WHEN
            auditService.countRecentFailedLogins(userId, 15);

            // THEN — the Instant passed to the repository must be ~15 minutes ago
            ArgumentCaptor<Instant> instantCaptor = ArgumentCaptor.forClass(Instant.class);
            verify(auditLogRepository).countFailedLoginsSince(any(), instantCaptor.capture());

            Instant since = instantCaptor.getValue();
            // Allow 5 seconds of tolerance for test execution time
            assertThat(since).isAfter(before);
            assertThat(since).isBefore(Instant.now());
        }
    }
}