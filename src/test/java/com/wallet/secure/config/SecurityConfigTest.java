package com.wallet.secure.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for SecurityConfig.
 *
 * WHY these tests:
 * Security configuration must be tested at integration level —
 * unit tests cannot verify that Spring Security rules are wired correctly.
 * A misconfigured security rule could expose the entire API.
 * OWASP A01: Verify "deny by default" is actually enforced.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("SecurityConfig — Access Control")
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Protected endpoint returns 401 when no token provided")
    void protectedEndpoint_withoutToken_returns401() throws Exception {
        // OWASP A01: Any endpoint not in PUBLIC_ENDPOINTS must require auth
        mockMvc.perform(get("/wallets"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Health actuator is publicly accessible")
    void actuatorHealth_isPublic() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());
    }
}
