package com.wallet.secure.user.service;

import com.wallet.secure.common.enums.UserRole;
import com.wallet.secure.config.AdminBootstrapProperties;
import com.wallet.secure.user.entity.User;
import com.wallet.secure.user.repository.UserRepository;
import jakarta.validation.Validator;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Provisions only the first ADMIN, when explicitly enabled.
 *
 * OWASP A01: the public registration path remains USER-only.
 * OWASP A02: the bootstrap password is BCrypt-hashed before persistence.
 * OWASP A05: credentials are never written to logs or responses.
 */
@Component
@RequiredArgsConstructor
@Log4j2
public class AdminBootstrapService implements ApplicationRunner {

    private final AdminBootstrapProperties properties;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final Validator validator;

    /**
     * Runs once after Spring has created the application context.
     *
     * <p>This is provisioning, not public registration: it is an operational
     * entry point used to create the first business administrator. Keeping it
     * as an {@link ApplicationRunner} means it is not reachable through HTTP
     * or Postman.</p>
     *
     * <p>The operation is idempotent. Re-starting the application with the
     * same variables does not change the existing administrator because the
     * role existence check happens before persistence.</p>
     */
    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!properties.isEnabled()) {
            log.info("Admin bootstrap disabled");
            return;
        }

        validateInput();

        if (userRepository.existsByRole(UserRole.ADMIN)) {
            log.info("Admin bootstrap skipped: an administrator already exists");
            return;
        }

        if (userRepository.existsByEmail(properties.getEmail())) {
            throw new IllegalStateException("Admin bootstrap email is already registered");
        }

        User admin = User.builder()
                .email(properties.getEmail())
                .passwordHash(passwordEncoder.encode(properties.getPassword()))
                .role(UserRole.ADMIN)
                .emailVerified(true)
                .isActive(true)
                .build();

        userRepository.save(admin);
        log.info("Initial administrator provisioned successfully");
    }

    /**
     * Validates only non-secret properties and password policy requirements.
     *
     * <p>Exception messages intentionally describe the violated rule without
     * including the supplied password (OWASP A05/A09: avoid secret leakage in
     * logs and startup diagnostics).</p>
     */
    private void validateInput() {
        if (!validator.validate(properties).isEmpty()) {
            throw new IllegalStateException("Admin bootstrap configuration is invalid");
        }
    }
}
