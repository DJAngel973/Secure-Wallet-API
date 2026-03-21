package com.wallet.secure.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * DTO for profile update requests.
 *
 * All fields are optional — client sends only what they want to change.
 * WHY separate from RegisterRequest: registration and update have different rules.
 * Email change requires re-verification — handled in UserService.
 * OWASP A01: user can only update their own profile (enforced in service layer).
 */
@Getter
@NoArgsConstructor
public class UpdateProfileRequest {

    /**
     * New email — optional.
     * If provided, emailVerified is reset to false → re-verification required.
     */
    @Email(message = "Email format is invalid")
    @Size(max = 255, message = "Email must not exceed 255 characters")
    private String email;

    /**
     * New password — optional.
     * If provided, the old password must be confirmed in service layer.
     * OWASP A07: enforce strong password policy on updates too.
     */
    @Size(min = 12, max = 72, message = "Password must be between 12 and 72 characters")
    private String password;

    /**
     * Current password — required only when changing email or password.
     * Prevents account takeover via stolen session.
     * OWASP A07: re-authentication for sensitive changes.
     */
    private String currentPassword;
}