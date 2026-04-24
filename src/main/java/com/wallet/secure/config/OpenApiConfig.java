package com.wallet.secure.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * OpenAPI 3.0 configuration — generates Swagger UI and API spec.
 *
 * Accessible at:
 * → Swagger UI:   http://localhost:8080/swagger-ui/index.html
 * → OpenAPI JSON: http://localhost:8080/v3/api-docs
 * → OpenAPI YAML: http://localhost:8080/v3/api-docs.yaml
 *
 * WHY document the API:
 * → Reclutadores pueden probar la API sin Postman
 * → Frontend developers know exactly what each endpoint expects
 * → Auto-generated from annotations — always in sync with code
 *
 * Security scheme: Bearer JWT
 * → "Authorize" button in Swagger UI accepts the access token
 * → All authenticated endpoints show the lock icon
 * → Testers can login, copy the token, paste in Authorize → test everything
 */
@Configuration
public class OpenApiConfig {

    private static final String SECURITY_SCHEME_NAME = "bearerAuth";

    @Bean
    public OpenAPI secureWalletOpenAPI() {
        return new OpenAPI()
                .info(buildInfo())
                .servers(buildServers())
                .addSecurityItem(new SecurityRequirement().addList(SECURITY_SCHEME_NAME))
                .components(new Components()
                        .addSecuritySchemes(SECURITY_SCHEME_NAME, buildSecurityScheme()));
    }

    private Info buildInfo() {
        return new Info()
                .title("Secure Wallet API")
                .version("0.0.1-SNAPSHOT")
                .description("""
                        ## Digital Wallet with OWASP Security Best Practices
                        
                        A production-grade REST API implementing:
                        - **JWT Authentication** with access + refresh tokens
                        - **Multi-device session management** (user_sessions table)
                        - **ACID-compliant financial transactions** with pessimistic locking
                        - **Complete audit trail** (audit_logs + transaction_history)
                        - **OWASP Top 10** mitigations throughout
                        
                        ### How to authenticate:
                        1. `POST /auth/register` or `POST /auth/login`
                        2. Copy the `accessToken` from the response
                        3. Click **Authorize** → paste `Bearer {accessToken}`
                        4. All authenticated endpoints are now accessible
                        
                        ### Roles:
                        - `USER` — standard wallet operations
                        - `ADMIN` — user management, wallet suspension, session audit
                        """)
                .contact(new Contact()
                        .name("DJAngel973")
                        .url("https://github.com/DJAngel973/Secure-Wallet-API"))
                .license(new License()
                        .name("MIT")
                        .url("https://opensource.org/licenses/MIT"));
    }

    private List<Server> buildServers() {
        return List.of(
                new Server()
                        .url("http://localhost:8080")
                        .description("Local development"),
                new Server()
                        .url("https://api.securewallet.dev")
                        .description("Production (future)")
        );
    }

    /**
     * Defines the JWT Bearer security scheme.
     * This adds the "Authorize" button to Swagger UI.
     * Users paste their accessToken once — all endpoints use it automatically.
     */
    private SecurityScheme buildSecurityScheme() {
        return new SecurityScheme()
                .name(SECURITY_SCHEME_NAME)
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT")
                .description("Paste your access token here (without 'Bearer ' prefix)");
    }
}