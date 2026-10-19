package com.wallet.secure.config;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Private, opt-in input for provisioning the first business administrator.
 *
 * Environment variables map to these properties as:
 * ADMIN_BOOTSTRAP_ENABLED, ADMIN_BOOTSTRAP_EMAIL and ADMIN_BOOTSTRAP_PASSWORD.
 */
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "admin.bootstrap")
public class AdminBootstrapProperties {

    private boolean enabled;

    @Email(message = "Email no válido")
    @NotBlank(message = "Email obligatorio")
    private String email;

    @NotBlank(message = "Contraseña obligatoria")
    @Size(min = 12, max = 72, message = "La contraseña debe tener entre 12 y 72 caracteres")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&_.#^])[A-Za-z\\d@$!%*?&_.#^]{12,72}$",
            message = "La contraseña debe incluir mayúscula, minúscula, número y carácter especial"
    )
    private String password;
}
