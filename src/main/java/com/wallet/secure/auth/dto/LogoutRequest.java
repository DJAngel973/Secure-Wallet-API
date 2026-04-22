package com.wallet.secure.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Request body for POST /auth/logout.
 * <p>
 * WHY the client sends the refreshToken on logout:
 * The server needs to know WHICH session to revoke.
 * A user can be logged in on multiple devices simultaneously.
 * Sending the refreshToken identifies exactly which session
 * to mark as revoked in user_sessions.
 * </p>
 * Without this: logout would have to revoke ALL sessions
 * (user gets logged out from phone AND laptop when logging
 * out from only one device).
 * <p>
 * OWASP A07: precise session revocation — one device logout
 * does NOT affect other active sessions.
 * </p>
 * The accessToken is NOT sent here:
 * → It expires in 15 minutes naturally
 * → Blacklisting access tokens requires a cache/DB lookup on every request
 * → Not worth the overhead for a 15-minute window
 */
@Getter
@NoArgsConstructor
public class LogoutRequest {

    /**
     * The refresh token to revoke.
     * Identifies the specific session to terminate.
     * The server computes SHA-256(refreshToken) and looks up user_sessions.
     */
    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
}