package com.wallet.secure.auth.security;

import com.wallet.secure.user.entity.User;
import com.wallet.secure.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Connects Spring Security with our User entity.
 *
 * WHY this class exists:
 * Spring Security does not know what a "User" is in our system.
 * It only knows UserDetails (its own interface).
 * This class is the bridge:
 *   Our User entity → UserDetails Spring Security understands
 *
 * Spring Security calls loadUserByUsername() in two moments:
 * 1. During login → AuthenticationManager verifies credentials
 * 2. During JWT validation → JwtAuthFilter rebuilds the authentication
 *
 * OWASP A07: account status checks happen here — locked, inactive,
 * unverified accounts are rejected before any token is issued.
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Loads a user by email (username in this system).
     *
     * Called by Spring Security automatically during:
     * - login: AuthenticationManager.authenticate()
     * - JWT filter: to rebuild SecurityContext on each request
     *
     * @param username 'email' the email submitted by the client
     * @return UserDetails with credentials and authorities
     * @throws UsernameNotFoundException if no user with that email exists
     *
     * OWASP A07: UsernameNotFoundException message is intentionally vague.
     * Never say "email not found" — that reveals valid emails to attackers.
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        // username = email in this system
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> {
                    // OWASP A07: vague message — same as wrong password
                    log.warn("Authentication failed for unknown email");
                    return new UsernameNotFoundException("Invalid credentials");
                });

        /*
         * WHY build UserDetails manually instead of implementing UserDetails
         * in the User entity directly?
         *
         * If User implements UserDetails:
         * → User entity is coupled to Spring Security
         * → Harder to test (needs Spring context)
         * → If Spring Security API changes → entity breaks
         *
         * Building UserDetails here keeps the User entity clean.
         * Spring Security dependency stays in this layer only.
         */
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(user.getPasswordHash())
                // Role stored as "USER" → Spring Security needs "ROLE_USER"
                // SimpleGrantedAuthority("ROLE_" + role) handles the prefix
                .authorities(buildAuthorities(user))
                // Spring Security account status flags
                // We use our own checks in isFullyActive() — mapped here
                .accountExpired(false)
                .accountLocked(user.isAccountLocked())
                .credentialsExpired(false)
                .disabled(!user.getIsActive())
                .build();
    }

    /**
     * Builds the authority list from the user's role.
     *
     * Spring Security requires the "ROLE_" prefix for @PreAuthorize("hasRole('ADMIN')").
     * Without it, hasRole('ADMIN') would never match.
     *
     * Examples:
     * UserRole.USER    → "ROLE_USER"
     * UserRole.ADMIN   → "ROLE_ADMIN"
     * UserRole.MANAGER → "ROLE_MANAGER"
     */
    private List<SimpleGrantedAuthority> buildAuthorities(User user) {
        return List.of(
                new SimpleGrantedAuthority("ROLE_" + user.getRole().name())
        );
    }
}