package com.wallet.secure.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;

/**
 * DTO returned after successful login or token refresh.
 *
 * Used by:
 * - POST /auth/login    → returns both tokens
 * - POST /auth/register → returns both tokens (user is logged in immediately)
 * - POST /auth/refresh  → returns new accessToken (refreshToken unchanged)
 *
 * WHY both tokens together:
 * The client receives accessToken for API calls (15 min)
 * and refreshToken to silently renew it (7 days).
 * The client never needs to login again until the refreshToken expires.
 *
 * OWASP A07: tokens are short-lived and revocable via logout.
 */
@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {

    /**
     * Short-lived JWT for API authorization.
     * Sent in every request: Authorization: Bearer <accessToken>
     * Expires in 15 minutes (JWT_EXPIRATION=900000).
     */
    private final String accessToken;

    /**
     * Long-lived token to obtain new access tokens silently.
     * Sent only to POST /auth/refresh.
     * Expires in 7 days (JWT_REFRESH_EXPIRATION=604800000).
     * Stored in DB — invalidated on logout (OWASP A07).
     *
     * NULL on refresh response — client keeps the existing refreshToken.
     */
    private final String refreshToken;

    /**
     * Access token lifetime in seconds — tells the client when to refresh.
     * 900 = 15 minutes.
     * The client uses this to schedule a silent refresh before expiration.
     */
    private final long expiresIn;

    /**
     * Token type — always "Bearer" per RFC 6750.
     * Tells the client how to send the token in the Authorization header.
     */
    private final String tokenType;

    /**
     * Factory method — login and register response (both tokens).
     */
    public static AuthResponse of(String accessToken, String refreshToken, long expiresIn) {
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(expiresIn)
                .tokenType("Bearer")
                .build();
    }

    /**
     * Factory method — refresh response (only new accessToken).
     * refreshToken stays NULL — @JsonInclude NON_NULL hides it from response.
     */
    public static AuthResponse refreshed(String accessToken, long expiresIn) {
        return AuthResponse.builder()
                .accessToken(accessToken)
                .expiresIn(expiresIn)
                .tokenType("Bearer")
                .build();
    }
}