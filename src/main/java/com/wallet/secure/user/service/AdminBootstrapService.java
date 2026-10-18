package com.wallet.secure.user.service;

import com.wallet.secure.common.enums.UserRole;
import com.wallet.secure.config.AdminBootstrapProperties;
import com.wallet.secure.user.entity.User;
import com.wallet.secure.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.regex.Pattern;

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

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");

    private final AdminBootstrapProperties properties;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

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

    private void validateInput() {
        if (properties.getEmail() == null || !EMAIL_PATTERN.matcher(properties.getEmail()).matches()) {
            throw new IllegalStateException("Admin bootstrap email is invalid");
        }
        if (properties.getPassword() == null || properties.getPassword().length() < 8) {
            throw new IllegalStateException("Admin bootstrap password does not meet minimum requirements");
        }
    }
}
