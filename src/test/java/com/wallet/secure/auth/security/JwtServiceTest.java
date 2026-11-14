package com.wallet.secure.auth.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JwtService real signature and claim validation")
class JwtServiceTest {

    private static final String SECRET = "test-only-signing-key-at-least-32-bytes-long";
    private static final String EMAIL = "user@example.test";

    private JwtService service() {
        return new JwtService(SECRET, 900_000, 604_800_000, "secure-wallet-api");
    }

    @Test
    @DisplayName("accepts an issued access token and rejects it as refresh")
    void accessToken_correctType_onlyAccessAccepted() {
        String token = service().generateAccessToken(EMAIL);

        assertThat(service().isAccessTokenValid(token)).isTrue();
        assertThat(service().isRefreshTokenValid(token)).isFalse();
    }

    @Test
    @DisplayName("rejects a refresh token at the access-token boundary — OWASP A07")
    void refreshToken_wrongType_rejectedAsAccess() {
        String token = service().generateRefreshToken(EMAIL);

        assertThat(service().isRefreshTokenValid(token)).isTrue();
        assertThat(service().isAccessTokenValid(token)).isFalse();
    }

    @Test
    @DisplayName("rejects a JWT whose payload was tampered with — OWASP A07")
    void accessToken_tamperedPayload_rejected() {
        String token = service().generateAccessToken(EMAIL);
        String[] parts = token.split("\\.");
        String tamperedPayload = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"admin@example.test\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        assertThat(service().isAccessTokenValid(parts[0] + "." + tamperedPayload + "." + parts[2])).isFalse();
    }

    @Test
    @DisplayName("rejects an expired JWT — OWASP A07")
    void accessToken_expired_rejected() {
        JwtService expiredIssuer = new JwtService(SECRET, -60_000, 604_800_000, "secure-wallet-api");

        assertThat(service().isAccessTokenValid(expiredIssuer.generateAccessToken(EMAIL))).isFalse();
    }

    @Test
    @DisplayName("rejects a correctly signed JWT from a different issuer — OWASP A07")
    void accessToken_wrongIssuer_rejected() {
        JwtService otherIssuer = new JwtService(SECRET, 900_000, 604_800_000, "another-issuer");

        assertThat(service().isAccessTokenValid(otherIssuer.generateAccessToken(EMAIL))).isFalse();
    }
}
