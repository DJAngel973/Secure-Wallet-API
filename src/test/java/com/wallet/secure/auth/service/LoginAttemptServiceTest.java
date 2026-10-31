package com.wallet.secure.auth.service;

import com.wallet.secure.audit.service.AuditService;
import com.wallet.secure.user.entity.User;
import com.wallet.secure.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("LoginAttemptService")
class LoginAttemptServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private AuditService auditService;
    @InjectMocks private LoginAttemptService loginAttemptService;

    private User user;
    private final String email = "angel@test.com";

    @BeforeEach
    void setUp() {
        user = User.builder().id(UUID.randomUUID()).email(email).failedLoginAttempts(0).build();
        ReflectionTestUtils.setField(loginAttemptService, "maxLoginAttempts", 5);
        ReflectionTestUtils.setField(loginAttemptService, "lockoutDurationMinutes", 30L);
    }

    @Nested
    @DisplayName("recordFailure()")
    class RecordFailureTests {

        @Test
        @DisplayName("increments the known user's counter below the configured threshold")
        void recordFailure_belowThreshold_incrementsCounter() {
            // GIVEN
            when(userRepository.findByEmailWithLock(email)).thenReturn(Optional.of(user));

            // WHEN
            loginAttemptService.recordFailure(email, "127.0.0.1", "JUnit");

            // THEN
            assertThat(user.getFailedLoginAttempts()).isEqualTo(1);
            assertThat(user.getLockedUntil()).isNull();
            verify(auditService).logLoginFailure(user.getId(), email, "Bad credentials", "127.0.0.1", "JUnit");
            verify(auditService, never()).logCriticalSecurityEvent(any(), anyString(), anyString(), anyString());
        }

        @Test
        @DisplayName("locks and caps the counter when the configured threshold is reached")
        void recordFailure_thresholdReached_locksAccount() {
            // GIVEN
            user.setFailedLoginAttempts(4);
            when(userRepository.findByEmailWithLock(email)).thenReturn(Optional.of(user));
            Instant before = Instant.now();

            // WHEN
            loginAttemptService.recordFailure(email, "127.0.0.1", "JUnit");

            // THEN
            assertThat(user.getFailedLoginAttempts()).isEqualTo(5);
            assertThat(user.getLockedUntil()).isAfter(before.plusSeconds(1790));
            verify(auditService).logLoginFailure(user.getId(), email,
                    "Account locked after failed attempts", "127.0.0.1", "JUnit");
            verify(auditService).logCriticalSecurityEvent(user.getId(),
                    "Account locked after 5 failed login attempts", "127.0.0.1", "JUnit");
        }

        @Test
        @DisplayName("does not enumerate or mutate an unknown email")
        void recordFailure_unknownEmail_doesNothing() {
            // GIVEN
            when(userRepository.findByEmailWithLock(email)).thenReturn(Optional.empty());

            // WHEN
            loginAttemptService.recordFailure(email, "127.0.0.1", "JUnit");

            // THEN
            verifyNoInteractions(auditService);
        }

        @Test
        @DisplayName("does not increase a counter while an account is still locked")
        void recordFailure_accountLocked_keepsCounter() {
            // GIVEN
            user.setFailedLoginAttempts(5);
            user.setLockedUntil(Instant.now().plusSeconds(60));
            when(userRepository.findByEmailWithLock(email)).thenReturn(Optional.of(user));

            // WHEN
            loginAttemptService.recordFailure(email, "127.0.0.1", "JUnit");

            // THEN
            assertThat(user.getFailedLoginAttempts()).isEqualTo(5);
            verify(auditService).logLoginFailure(user.getId(), email, "Account locked", "127.0.0.1", "JUnit");
        }
    }
}
