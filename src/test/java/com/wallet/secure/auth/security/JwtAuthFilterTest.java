package com.wallet.secure.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtAuthFilter")
class JwtAuthFilterTest {

    private static final String TOKEN = "valid.access.token";
    private static final String EMAIL = "tests@test.com";

    @Mock private JwtService jwtService;
    @Mock private UserDetailsServiceImpl userDetailsService;
    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private FilterChain filterChain;
    @Mock private UserDetails userDetails;

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("rejects a valid access token after its account is disabled — OWASP A07")
    void doFilterInternal_disabledUser_doesNotAuthenticate() throws Exception {
        // GIVEN
        JwtAuthFilter filter = validTokenFilter();
        when(userDetails.isEnabled()).thenReturn(false);

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("rejects a valid access token while its account is locked — OWASP A07")
    void doFilterInternal_lockedUser_doesNotAuthenticate() throws Exception {
        // GIVEN
        JwtAuthFilter filter = validTokenFilter();
        when(userDetails.isEnabled()).thenReturn(true);
        when(userDetails.isAccountNonLocked()).thenReturn(false);

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("authenticates an active and unlocked account with a valid access token")
    void doFilterInternal_activeUnlockedUser_populatesSecurityContext() throws Exception {
        // GIVEN
        JwtAuthFilter filter = validTokenFilter();
        when(userDetails.isEnabled()).thenReturn(true);
        when(userDetails.isAccountNonLocked()).thenReturn(true);
        when(userDetails.getAuthorities()).thenReturn(java.util.List.of());

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(SecurityContextHolder.getContext().getAuthentication())
                .isNotNull()
                .extracting(authentication -> authentication.getPrincipal())
                .isSameAs(userDetails);
        verify(filterChain).doFilter(request, response);
    }

    private JwtAuthFilter validTokenFilter() {
        when(request.getHeader("Authorization")).thenReturn("Bearer " + TOKEN);
        when(jwtService.isAccessTokenValid(TOKEN)).thenReturn(true);
        when(jwtService.extractEmail(TOKEN)).thenReturn(EMAIL);
        when(userDetailsService.loadUserByUsername(EMAIL)).thenReturn(userDetails);
        return new JwtAuthFilter(jwtService, userDetailsService);
    }
}
