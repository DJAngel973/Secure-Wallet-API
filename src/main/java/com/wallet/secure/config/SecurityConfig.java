package com.wallet.secure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Central Spring Security configuration.
 *
 * OWASP A01 - Broken Access Control:
 *   "Deny by default" — ALL endpoints are blocked unless explicitly permitted.
 *   Public endpoints are whitelisted in PUBLIC_ENDPOINTS.
 *
 * OWASP A07 - Identification and Authentication Failures:
 *   Stateless JWT (no HTTP session). BCrypt strength 12 for passwords.
 *
 * Roles defined in UserRole enum (maps to DB: user_role):
 *   USER, MANAGER, ADMIN
 *
 * Fine-grained role checks use @PreAuthorize on methods (enabled by
 * @EnableMethodSecurity). URL-level rules are only for broad patterns.
 *
 * NOTE: JwtAuthenticationFilter will be added here once auth/ domain
 * is implemented. Placeholder comment marks the exact insertion point.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity   // Enables @PreAuthorize, @PostAuthorize on methods
public class SecurityConfig {

    /**
     * Public endpoints — accessible without authentication.
     * OWASP A01: Everything NOT listed here is DENIED by default.
     */
    private static final String[] PUBLIC_ENDPOINTS = {
            "/auth/login",
            "/auth/register",
            "/auth/refresh",
            "/actuator/health"
    };

    /**
     * Admin-only endpoints — accessible only with ADMIN role.
     * Fine-grained checks also use @PreAuthorize at method level.
     */
    private static final String[] ADMIN_ENDPOINTS = {
            "/admin/**"
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF: we use stateless JWT, not session cookies
                // OWASP A01: CSRF only needed for cookie-based sessions
                .csrf(AbstractHttpConfigurer::disable)

                // OWASP A07: Stateless — never create or use HTTP sessions
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // URL-level authorization rules
                // Order matters: more specific rules first
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        .requestMatchers(ADMIN_ENDPOINTS).hasRole("ADMIN")
                        // OWASP A01: deny everything not explicitly permitted
                        .anyRequest().authenticated()
                );

        // TODO: Add JWT filter here when auth/ domain is implemented:
        // http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * BCrypt password encoder with strength 12.
     *
     * WHY strength 12 (not default 10):
     * Each +1 doubles computation time.
     * Strength 12 ≈ 250ms/hash — strong against brute force, acceptable UX.
     * OWASP A02: BCrypt is an adaptive algorithm designed for passwords.
     *
     * IMPORTANT: Password COMPLEXITY rules (uppercase, digits, special chars)
     * are enforced in RegisterRequest DTO via @Pattern annotation,
     * NOT here. PasswordEncoder only hashes — it does not validate.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * Exposes AuthenticationManager as a Spring bean.
     *
     * WHY needed:
     * AuthService.login() calls authManager.authenticate(credentials)
     * to trigger Spring Security's built-in username/password validation.
     * Without this bean, AuthService cannot inject AuthenticationManager.
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}