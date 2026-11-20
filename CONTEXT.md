# Secure Wallet API — Project Context

> [`AGENTS.md`](AGENTS.md) governs agent work; [`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md) is the current implementation and verification status source. This file describes architecture and intent, not proof that every named control is active.

---

## Project Purpose

REST API for a digital wallet built with an **academic-professional** focus, prioritizing:

- **Applied Cybersecurity** (OWASP Top 10)
- **DevSecOps** (security integrated into the CI/CD pipeline)
- **Development best practices**: clean, documented, and testable code
- **Full traceability** of financial operations

The goal is not only to make it work — but to make it **secure, auditable, and maintainable**.

---

## Architecture

**Pattern:** Layered Architecture + Domain-Driven Design (Hybrid)  
**Principle:** Layers organized BY DOMAIN, not by class type

```
com.wallet.secure/
├── config/          # Global configuration (Security, JWT, Audit)
├── auth/            # Domain: Authentication, JWT, Sessions (TOTP pending)
├── user/            # Domain: Users and profile management
├── wallet/          # Domain: Wallets and balances
├── transaction/     # Domain: Transactions (business core)
├── audit/           # Domain: Security and audit logs
└── common/          # Shared: exceptions, responses, enums, validators

```

**Key rule:** Never create root-level folders by type (`controllers/`, `services/`)
Each domain contains its own layers.

---

## Security Approach

- **OWASP Top 10** as the main security decision framework
- **JWT** for stateless authentication (jjwt 0.12.6)
- **TOTP** for high-value operations is a pending design decision, not an active control ([DESIGN-001](docs/IMPLEMENTATION-PLAN.md))
- **BCrypt** for password hashing
- **AuditService** records tested sensitive flows; complete coverage is not claimed ([TX-001](docs/IMPLEMENTATION-PLAN.md))
- **Failed-login lockout** is active (5 failures, 30 minutes); general rate limiting is not established. Transaction-limit values in `application.yml` are not enforced policy ([DESIGN-002](docs/IMPLEMENTATION-PLAN.md))
- **Prepared statements** via Hibernate (SQL Injection prevention)
- **HTTPS** would be required for a future public deployment; local Compose uses HTTP

---

## Database

- **Engine:** PostgreSQL 16
- **ORM:** Hibernate/JPA with `ddl-auto: validate`
- **Important:** The databases is managed using SQL scripts in `/database/`
  Hibernate does NOT create or modify tables — it only validates them.
- **Transactions:** Spring transactional boundaries and pessimistic locking are proven for the tested PostgreSQL debit scenarios ([`TransactionPostgresIntegrationTest`](src/test/java/com/wallet/secure/transaction/integration/TransactionPostgresIntegrationTest.java))
- **Auditing:** `AuditService` writes security/business events; a database trigger records transaction status changes in `transaction_history` ([`05-triggers.sql`](database/05-triggers.sql))

### Main tables:
- `users` → entity `User.java`
- `wallets` → entity `Wallet.java`
- `transactions` → entity `Transaction.java`
- `transaction_history` → entity `TransactionHistory.java`
- `user_sessions` → entity `Session.java` (SHA-256 token hashes)
- `audit_logs` → entity `AuditLog.java`

---

## Technology Stack

| Component | Technology | Version |
|---|---|---|
| Framework | Spring Boot | 3.4.2 |
| Lenguaje | Java | 17 |
| Security | Spring Security + JWT | jjwt 0.12.6 |
| Database | PostgreSQL | 16 |
| ORM | Spring Data JPA / Hibernate | - |
| Logging | Log4j2 | 2.25.3 |
| Validation | Spring Bean Validation | - |
| Boilerplate | Lombok | 1.18.36 |
| Containers | Docker + Docker Compose | - |
| CI/CD | GitHub Actions | - |
| Code analysis | CodeQL | - |
| Dependency scanning | OWASP Dependency Check | 12.2.0 |

---

## Branching Strategy

```
main          ← Production. Protected. Only merged via approved PR
└── feature/  ← One branch per feature: feature/descriptive-name
└── fix/      ← Bug fixes: fix/bug-name
└── docs/     ← Documentation only: docs/name
```

**Commits:** Following [Conventional Commits](https://www.conventionalcommits.org/)
- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation
- `refactor:` refactoring without functional change
- `test:` tests
- `chore:` maintenance tasks

---

## Code Conventions

### Naming
- **Entities:** Singular, PascalCase → `User`, `Wallet`, `Transaction`
- **Request DTOs:** `[Action]Request.java` → `LoginRequest`, `DepositRequest`
- **Response DTOs:** `[Entity]Response.java` → `UserResponse`, `WalletResponse`
- **Services:** `[Domain]Service.java` → `AuthService`, `WalletService`
- **Repositories:** `[Entity]Repository.java`

### API Responses
All responses use the standard wrapper  `ApiResponse<T>` from `common/response/`

### Code Documentation
- Document the **WHY**, not the what
- Security decisions MUST reference OWASP when applicable
- Example: `// OWASP A05: parameterized queries reduce SQL injection risk`

---

## Pull Request Checklist

- [ ] Unit tests for new business logic
- [ ] No hardcoded secrets (use environment variables)
- [ ] Exception handling via  `GlobalExceptionHandler`
- [ ] Input validation using Bean Validation (`@Valid`)
- [ ] Audit logs for sensitive operations
- [ ] No `show-sql: true` and no exposed stack traces

---

## 🚫 Never Do

- Use `ddl-auto: create` or `update` — DB is managed with SQL scripts
- Hardcode passwords, secrets, or API keys
- Expose stack traces in client error responses
- Skip input validation in controllers
- Bypass auditing for financial operations
