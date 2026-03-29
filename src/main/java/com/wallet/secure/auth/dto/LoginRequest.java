package com.wallet.secure.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

/**
 * DTO for POST /auth/login
 *
 * Intentionally minimal — only email and password.
 * No role, no id, no status — the client cannot influence those.
 * OWASP A01: mass assignment prevention — only accepted fields are mapped.
 */
@Getter
public class LoginRequest {

    /**
     * User email — used as username.
     * @NotBlank: rejects null, empty and whitespace-only strings.
     * @Email: validates format before reaching AuthService.
     * OWASP A03: format validated before any DB query.
     */
    @NotBlank(message = "Email is required")
    @Email(message = "Email format is invalid")
    private String email;

    /**
     * Plain password — compared against BCrypt hash in AuthService.
     * NEVER logged, NEVER stored, NEVER returned in any response.
     * OWASP A02: plain text only lives in this DTO during the request.
     */
    @NotBlank(message = "Password is required")
    private String password;
}