package com.wallet.secure.config;

import com.wallet.secure.wallet.service.WalletService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.test.context.support.WithMockUser;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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

    // The filter chain is the subject under test. Mocking business logic keeps
    // authorization evidence independent from database state.
    @MockitoBean
    private WalletService walletService;

    @Test
    @DisplayName("Protected endpoint returns 401 when no token provided")
    void protectedEndpoint_withoutToken_returns401() throws Exception {
        // OWASP A01: Any endpoint not in PUBLIC_ENDPOINTS must require auth
        mockMvc.perform(get("/wallets"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Every wallet route returns 401 when anonymous")
    void walletEndpoints_withoutToken_return401() throws Exception {
        UUID walletId = UUID.randomUUID();

        mockMvc.perform(post("/wallets").contentType("application/json").content("{\"currency\":\"USD\"}"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/wallets/{id}", walletId)).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/wallets/currency/USD")).andExpect(status().isUnauthorized());
        mockMvc.perform(patch("/wallets/{id}/suspend", walletId)).andExpect(status().isUnauthorized());
        mockMvc.perform(patch("/wallets/{id}/restore", walletId)).andExpect(status().isUnauthorized());
        mockMvc.perform(patch("/wallets/{id}/close", walletId)).andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "USER")
    @DisplayName("Regular user receives 403 from every administrative wallet route")
    void administrativeWalletEndpoints_regularUser_return403() throws Exception {
        UUID walletId = UUID.randomUUID();

        mockMvc.perform(patch("/wallets/{id}/suspend", walletId)).andExpect(status().isForbidden());
        mockMvc.perform(patch("/wallets/{id}/restore", walletId)).andExpect(status().isForbidden());
        mockMvc.perform(patch("/wallets/{id}/close", walletId)).andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    @DisplayName("Administrator passes authorization for every wallet lifecycle route")
    void administrativeWalletEndpoints_admin_passesAuthorization() throws Exception {
        UUID walletId = UUID.randomUUID();

        mockMvc.perform(patch("/wallets/{id}/suspend", walletId)).andExpect(status().isOk());
        mockMvc.perform(patch("/wallets/{id}/restore", walletId)).andExpect(status().isOk());
        mockMvc.perform(patch("/wallets/{id}/close", walletId)).andExpect(status().isOk());
    }

    @Test
    @DisplayName("Health actuator is publicly accessible")
    void actuatorHealth_isPublic() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "USER")
    @DisplayName("Regular user receives 403 from an ADMIN user-management endpoint")
    void adminUserEndpoint_regularUser_returns403() throws Exception {
        mockMvc.perform(get("/users/{id}", UUID.randomUUID()))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "USER")
    @DisplayName("Regular user receives 403 when trying to deactivate an account")
    void adminDeactivationEndpoint_regularUser_returns403() throws Exception {
        mockMvc.perform(patch("/users/{id}/deactivate", UUID.randomUUID()))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "USER")
    @DisplayName("No DELETE route exists for user account removal")
    void deleteAccountRoute_returnsMethodNotAllowed() throws Exception {
        mockMvc.perform(delete("/users/me"))
                .andExpect(status().isMethodNotAllowed());
    }
}
