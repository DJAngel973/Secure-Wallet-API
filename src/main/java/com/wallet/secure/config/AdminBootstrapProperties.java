package com.wallet.secure.config;

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
    private String email;
    private String password;
}
