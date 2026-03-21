package com.wallet.secure.user.dto;

import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * DTO for user registration request.
 *
 * WHY a separate DTO and not the User entity directly:
 * - The entity has fields that the client should NEVER send (role, isActive, etc.)
 * - Bean Validation here validates INPUT before it reaches the service
 * - OWASP A03: never bind HTTP request directly to a JPA entity (Mass Assignment)
 */
@Getter
@NoArgsConstructor
public class RegisterRequest {

    /**
     * User email — used as username.
     * Validated at API level here + at DB level in 03-tables.sql (email_format constraint).
     */
    @NotBlank(message = "Email is required")
    @Email(message = "Email format is invalid")
    @Size(max = 255, message = "Email must not exceed 255 characters")
    private String email;

    /**
     * Plain password — NEVER stored, only used to generate BCrypt hash in AuthService.
     * Validation rules match application.yml → app.security.password-* settings.
     * OWASP A07: enforce strong password policy at API entry point.
     */
    @NotBlank(message = "Password is required")
    @Size(min = 12, max = 72, message = "Password must be between 8 and 72 characters")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&_.#^])[A-Za-z\\d@$!%*?&_.#^]{12,}$",
            message = "Password must contain uppercase, lowercase, number and special character"
    )
    private String password;
}
