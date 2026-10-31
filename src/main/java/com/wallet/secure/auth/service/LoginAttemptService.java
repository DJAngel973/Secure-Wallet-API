package com.wallet.secure.auth.service;

import com.wallet.secure.audit.service.AuditService;
import com.wallet.secure.user.entity.User;
import com.wallet.secure.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Persists failed-login state independently from the failed authentication flow.
 * The caller rethrows BadCredentialsException, which rolls back its transaction;
 * REQUIRES_NEW ensures the counter and forensic record still survive.
 */
@Service
@RequiredArgsConstructor
public class LoginAttemptService {

    private final UserRepository userRepository;
    private final AuditService auditService;

    @Value("${app.security.max-login-attempts}")
    private int maxLoginAttempts;

    @Value("${app.security.lockout-duration-minutes}")
    private long lockoutDurationMinutes;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(String email, String ipAddress, String userAgent) {
        userRepository.findByEmailWithLock(email).ifPresent(user -> recordFailure(user, email, ipAddress, userAgent));
    }

    private void recordFailure(User user, String email, String ipAddress, String userAgent) {
        // OWASP A07: a row lock makes each increment observe the latest count.
        if (user.isAccountLocked()) {
            auditService.logLoginFailure(user.getId(), email, "Account locked", ipAddress, userAgent);
            return;
        }

        user.incrementFailedLoginAttempts();
        boolean locked = user.getFailedLoginAttempts() >= maxLoginAttempts;
        if (locked) {
            user.setFailedLoginAttempts(maxLoginAttempts);
            user.setLockedUntil(Instant.now().plusSeconds(lockoutDurationMinutes * 60));
        }

        auditService.logLoginFailure(user.getId(), email,
                locked ? "Account locked after failed attempts" : "Bad credentials", ipAddress, userAgent);
        if (locked) {
            auditService.logCriticalSecurityEvent(user.getId(),
                    "Account locked after " + maxLoginAttempts + " failed login attempts", ipAddress, userAgent);
        }
    }
}
