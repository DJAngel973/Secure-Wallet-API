package com.wallet.secure.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * JWT configuration properties.
 * Values loaded from application.yml under the "jwt:" prefix.
 *
 * WHY @ConfigurationProperties instead of @Value:
 * Groups related properties, enables validation, and is easier to test.
 *
 * OWASP A07: JWT secret must come from environment variable,
 * never hardcoded. Enforced by application.yml → ${JWT_SECRET}.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtConfig {

    /** JWT signing secret — injected from JWT_SECRET env variable */
    private String secret;

    /** Access token expiration in milliseconds — default 15 min */
    private long expiration = 900_000L; // 15 minutes

    /** Refresh token expiration in milliseconds — default 7 days */
    private long refreshExpiration = 604_800_000L; // 7 days

    /** Token issuer identifier */
    private String issuer = "secure-wallet-api";

    /** HTTP header name carrying the token */
    private String header = "Authorization";

    /** Token prefix in the header value */
    private String prefix = "Bearer";
}