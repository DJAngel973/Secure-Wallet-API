# Security Documentation

This is a local simulated-wallet portfolio project, not a production-certified financial service. [The implementation plan](docs/IMPLEMENTATION-PLAN.md) is the authoritative status source; [ADRs](DECISIONS.md) record design intent, not necessarily active controls. OWASP Top 10:2025 is a review framework, not a certification; names and order follow the [official release](https://top10.owasp.org/2025/).

---

## Threat Model — ¿What We Protect?

| Asset | Threat | Current control or status |
|---|---|---|
| User credentials | Brute force | Account lockout after 5 failed logins for 30 minutes ([`LoginAttemptServiceTest`](src/test/java/com/wallet/secure/auth/service/LoginAttemptServiceTest.java)); no general API/IP rate limiter |
| Passwords in DB | Database theft | BCrypt hashing (strength 12) |
| Stolen Access Token | Session hijacking | Short expiration: 15 minutes |
| Stolen Refresh Token | Long-term impersonation | SHA-256 session hashes, rotation, and revocation ([`SessionServiceTest`](src/test/java/com/wallet/secure/auth/service/SessionServiceTest.java)) |
| Sensitive operations | Fraud / unauthorized access | Authorization and audit; TOTP is **not implemented** ([DESIGN-001](docs/IMPLEMENTATION-PLAN.md#design-001--review-totp-based-two-factor-authentication)) |
| Data in transit | MITM | Local Compose uses HTTP; HTTPS is a requirement for any future public deployment, not an active local control |
| SQL Injection | DB manipulation | Prepared statements via Hibernate |
| Sensitive data in logs | Accidental exposure | Audit paths avoid reusable tokens; complete log-safety review is not claimed ([`AuditServiceTest`](src/test/java/com/wallet/secure/audit/service/AuditServiceTest.java)) |

---

## OWASP Top 10 (2025) — Coverage

> This is a mapping of tested evidence and residual work, not a claim that any category has been eliminated. See the [official OWASP Top 10:2025](https://top10.owasp.org/2025/).

| Category | Project evidence | Residual work / boundary |
|---|---|---|
| A01:2025 Broken Access Control | Role and ownership tests ([AUTHZ-001/002](docs/IMPLEMENTATION-PLAN.md), [`SecurityConfigTest`](src/test/java/com/wallet/secure/config/SecurityConfigTest.java)) | Tested route matrix, not an exhaustive assessment |
| A02:2025 Security Misconfiguration | [`SecurityConfig`](src/main/java/com/wallet/secure/config/SecurityConfig.java), schema validation and no SQL seed ([SEC-001](docs/IMPLEMENTATION-PLAN.md)) | Local HTTP and deployment settings require review before public use |
| A03:2025 Software Supply Chain Failures | [CI dependency scan and CodeQL](.github/workflows/ci.yml), [`pom.xml`](pom.xml) | Actual scan results and dependency currency remain environment-dependent |
| A04:2025 Cryptographic Failures | BCrypt and hashed refresh sessions ([SEC-003/004](docs/IMPLEMENTATION-PLAN.md)) | No production key-management or disk-encryption proof |
| A05:2025 Injection | DTO validation and JPA repository patterns ([`src/main/java`](src/main/java)) | No exhaustive injection assessment |
| A06:2025 Insecure Design | PostgreSQL concurrency tests ([`TransactionPostgresIntegrationTest`](src/test/java/com/wallet/secure/transaction/integration/TransactionPostgresIntegrationTest.java)) | TOTP and configurable limits remain pending ([DESIGN-001/002](docs/IMPLEMENTATION-PLAN.md)) |
| A07:2025 Authentication Failures | Refresh, lockout, and JWT account-state tests ([SEC-004/005/006](docs/IMPLEMENTATION-PLAN.md)) | No TOTP or inactivity-timeout enforcement |
| A08:2025 Software or Data Integrity Failures | [Versioned SQL](database/) and [CI tests](.github/workflows/ci.yml) | No complete release/provenance assessment |
| A09:2025 Security Logging and Alerting Failures | [`AuditServiceTest`](src/test/java/com/wallet/secure/audit/service/AuditServiceTest.java) and [TX-001](docs/IMPLEMENTATION-PLAN.md) | External alerting and complete event coverage unverified |
| A10:2025 Mishandling of Exceptional Conditions | [`GlobalExceptionHandler`](src/main/java/com/wallet/secure/common/exception/GlobalExceptionHandler.java), [rollback tests](src/test/java/com/wallet/secure/transaction/integration/TransactionPostgresIntegrationTest.java) | Tested cases only; no universal fail-closed guarantee |

---

## Authentication and Authorization

### Authentication Flow
```
POST /auth/login
  → Validate credentials (username + BCrypt password)
  → Verify account is not locked
  → Generate Access Token (15 min) + Refresh Token (7 days)
  → Store only a SHA-256 refresh-token hash in user_sessions
  → Audit log login event
  → Return tokens to client
```

### Token Refresh
```
POST /auth/refresh
  → Validate Refresh Token (signature + expiration + active session hash)
  → Rotate Refresh Token (invalidate old one, generate new one)
  → Return new Access Token (15 min) + new Refresh Token
```

### Session Invalidation
```
POST /auth/logout
  → Revoke Refresh Token session in user_sessions
  → Audit log logout event
  → Access Token naturally expires within 15 minutes
```

---

## Session Management

| Parameter | Value | Reason |
|---|--|---|
| **Access Token TTL** | **15 minutes** | Short window if stolen |
| **Refresh Token TTL** | **7 days** | Security/UX balance |
| **Max inactivity** | Not enforced | Pending design, not equivalent to token TTL |
| **Reauthentication** | Not enforced for sensitive operations | TOTP policy pending ([DESIGN-001](docs/IMPLEMENTATION-PLAN.md)) |
| **Concurrent sessions** | Allowed (tracked in DB) | Auditable per device |

### Why 15 minutes for the Access Token?
A stolen Access Token (via XSS, log leak, etc.) can only be used for 15 minutes.
With 24h tokens, an attacker gets nearly a full day of access.
For a wallet, 15 minutes is the right balance between security and user experience
(refresh is transparent when implemented correctly).

---

## Two-Factor Authentication (2FA) — pending decision, not active

TOTP is a proposal in [ADR-004](DECISIONS.md#adr-004--2fa-using-totp-rfc-6238-instead-of-sms), not an implemented authentication factor. Enrollment, verification, recovery, secret protection, and the operations requiring it remain undecided ([DESIGN-001](docs/IMPLEMENTATION-PLAN.md)).

### Proposed scenarios (none currently requires 2FA)

| Proposed scenario | Current enforcement |
|---|---|
| Transfers / withdrawals > $100 | None — threshold is not active |
| Password / email change | None via TOTP |
| Administrative operations | Role authorization, not TOTP |
| Login from new device | No TOTP flow |
| Balance inquiry | No TOTP flow |

### Why $100 instead of $5,000?
The `$100` value is a historical proposal in [ADR-005](DECISIONS.md#adr-005--2fa-threshold-set-at-100-not-5000) and a configuration value, **not an enforced rule**. Configurable transaction and daily limits are likewise pending [DESIGN-002](docs/IMPLEMENTATION-PLAN.md).

---

## Encryption and Data Protection

### In transit
- Local Docker Compose uses HTTP. TLS is required before any future public deployment; this project is not intended for one.

### At rest — passwords
- BCrypt with strength 12
- Passwords are **never** stored in plaintext or reversible formats

### At rest — financial data
- Balances and amounts stored as `DECIMAL(19,4)` — no rounding
- Monetary precision is not encryption. Infrastructure encryption is a design delegation, not a verified local control ([ADR-007](DECISIONS.md#adr-007--encryption-at-rest-delegated-to-infrastructure)).
- Audit logs never store sensitive data (passwords, full tokens)

### JWT Secret
- Minimum 256-bit entropy
- Stored exclusively as environment variable `JWT_SECRET`
- Never in source code, never in logs

---

## 🚨 Engineering rules (requirements, not proof of complete coverage)

1. `ddl-auto` is never  `create` or `update` in any environment
2. Stack traces never reach the client
3. Passwords are never logged or returned in any response
4. JWT secret is never hardcoded — always environment variable
5. Financial operations always run inside `@Transactional`
6. Sensitive operations must generate audit evidence; coverage must be verified for each new flow
7. Input validation is required on **all** endpoints (`@Valid`)

---

## Vulnerability Reporting

This is an academic/portfolio project.
If you find a vulnerability, open an issue with the `security` label.
