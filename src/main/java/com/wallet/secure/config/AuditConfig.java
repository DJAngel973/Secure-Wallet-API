package com.wallet.secure.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * Enables JPA Auditing for automatic population of
 * @CreatedDate and @LastModifiedDate fields on entities.
 *
 * WHY: Financial entities need creation/modification timestamps
 * for regulatory traceability (OWASP A09 — Logging & Monitoring).
 * This is automatic — no manual timestamp setting required.
 */
@Configuration
@EnableJpaAuditing
public class AuditConfig {
    // Spring handles the rest via @EntityListeners(AuditingEntityListener.class)
    // on each entity that needs auditing.
}