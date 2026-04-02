package com.wallet.secure.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT Authentication Filter — runs ONCE per HTTP request.
 *
 * WHY OncePerRequestFilter:
 * Spring can invoke filters multiple times in a request (forwards, includes).
 * OncePerRequestFilter guarantees execution exactly once per request.
 *
 * Position in the filter chain:
 * Runs BEFORE UsernamePasswordAuthenticationFilter.
 * If the JWT is valid → SecurityContext is populated.
 * If not → request continues unauthenticated.
 * Spring Security then decides 401 or 403 based on the endpoint rules
 * defined in SecurityConfig.
 *
 * OWASP A07: every request is independently validated — no session trust.
 * OWASP A01: SecurityContext is only populated with verified identity.
 */
@Component
@RequiredArgsConstructor
@Log4j2
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsServiceImpl userDetailsService;

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    /**
     * Core filter logic — called exactly once per request.
     *
     * Flow:
     * 1. Extract token from Authorization header
     * 2. Validate token signature and expiration
     * 3. Load user from DB by email in token
     * 4. Populate SecurityContext if everything is valid
     * 5. Continue filter chain regardless of result
     *    (Spring Security handles the 401/403 after this)
     *
     * @param request     incoming HTTP request
     * @param response    HTTP response
     * @param filterChain next filters in the chain
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        // Step 1 — Extract token from header
        final String token = extractToken(request);

        // No token present → continue without authentication
        // Spring Security will reject protected endpoints after this filter
        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // Step 2 — Validate token (signature + expiration + type)
        if (!jwtService.isAccessTokenValid(token)) {
            // Token present but invalid — log for security monitoring
            // OWASP A09: log security events for incident detection
            log.warn("Invalid or expired JWT token — request rejected: {}",
                    sanitizeForLog(request.getRequestURI()));
            filterChain.doFilter(request, response);
            return;
        }

        // Step 3 — Extract email from token and load user
        // Only reached if token is valid
        final String email = jwtService.extractEmail(token);

        // Only authenticate if not already authenticated in this request
        // Prevents re-authentication if another filter already set the context
        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = userDetailsService.loadUserByUsername(email);

            // Step 4 — Build authentication object and populate SecurityContext
            // UsernamePasswordAuthenticationToken(principal, credentials, authorities)
            // credentials = null — we don't need the password after token validation
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,                          // credentials null — JWT replaces password
                            userDetails.getAuthorities()   // ROLE_USER, ROLE_ADMIN, etc.
                    );

            // Attach request metadata (IP, session) to the authentication
            // Used by Spring Security for audit and access decision logging
            authToken.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request));

            // Populate SecurityContext — from this point the user IS authenticated
            // @AuthenticationPrincipal and SecurityContextHolder.getContext() work now
            SecurityContextHolder.getContext().setAuthentication(authToken);

            log.debug("JWT authentication successful for user: {}", email);
        }

        // Step 5 — Always continue the chain
        // SecurityConfig decides whether the endpoint requires authentication
        filterChain.doFilter(request, response);
    }

    /**
     * Extracts the raw JWT from the Authorization header.
     *
     * Expected header format: "Authorization: Bearer eyJhbGc..."
     * Returns null if the header is missing or malformed.
     *
     * WHY return null and not throw:
     * Not all requests need a token (public endpoints).
     * Missing token is not an error — it just means unauthenticated.
     * The filter continues and Spring Security decides what to do.
     *
     * OWASP A09: no sensitive data logged here.
     */
    private String extractToken(HttpServletRequest request) {
        final String authHeader = request.getHeader(AUTHORIZATION_HEADER);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return null;
        }

        // Remove "Bearer " prefix (7 characters) to get the raw token
        return authHeader.substring(BEARER_PREFIX.length());
    }

    /**
     * Sanitizes user-controlled values before logging.
     *
     * WHY needed here:
     * request.getRequestURI() and email come from the client.
     * An attacker can include \n or \r in the URI to inject fake log lines.
     * Example attack: GET /login%0A[WARN] Admin logged in successfully
     * → Without sanitization, that fake line appears in the log.
     *
     * Replaces ISO control characters and Unicode line separators with '_'.
     * OWASP A09: prevents log injection / log forging.
     *
     * @param value original value
     * @return sanitized value safe for logging
     */
    private String sanitizeForLog(String value) {
        if (value == null) return null;
        StringBuilder sanitized = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (Character.isISOControl(ch) || ch == '\u2028' || ch == '\u2029') {
                sanitized.append('_');
            } else {
                sanitized.append(ch);
            }
        }
        return sanitized.toString();
    }
}