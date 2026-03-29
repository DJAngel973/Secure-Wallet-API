package com.wallet.secure.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

/**
 * DTO for POST /auth/refresh
 *
 * The client sends the refreshToken to obtain a new accessToken
 * without requiring the user to login again.
 *
 * WHY a dedicated DTO and not a query param:
 * Query params appear in server logs and browser history.
 * Tokens in the request body are not logged by default.
 * OWASP A09: sensitive tokens must not appear in logs.
 */
@Getter
public class RefreshTokenRequest {

    /**
     * The refresh token issued at login.
     * Validated against DB — if not found or expired → 401.
     * OWASP A07: each refresh token can only be used while it is stored in DB.
     */
    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
}