# Security Documentation

This document describes the security model of the Secure Wallet API,
the controls implemented, and the decisions made following OWASP Top 10 (2025) — the current official version
published on November 6, 2025 at the Global AppSec Conference.

---

## Threat Model — ¿What We Protect?

| Asset | Threat | Implemented Control |
|---|---|---|
| User credentials | Brute force | Rate limiting + lockout (5 attempts, 30 min) |
| Passwords in DB | Database theft | BCrypt hashing (strength 12) |
| Stolen Access Token | Session hijacking | Short expiration: 15 minutes |
| Stolen Refresh Token | Long-term impersonation | Rotation + revocation stored in DB |
| Sensitive operations | Fraud / unauthorized access | Mandatory 2FA |
| Data in transit | MITM | HTTPS required in production |
| SQL Injection | DB manipulation | Prepared statements via Hibernate |
| Sensitive data in logs | Accidental exposure | Log4j2 — no passwords/tokens logged |

---

## OWASP Top 10 (2025) — Coverage

> OWASP Top 10 2025 was published on November 6, 2025
> at the Global AppSec Conference in Washington D.C.
> It is the current and official version.

| # | OWASP 2025 Risk | Status | How it is mitigated in this project                                                                 |
|---|---|---|-----------------------------------------------------------------------------------------------------|
| A01 | Broken Access Control *(includes SSRF)* | ✅ | Spring Security + roles (ADMIN, USER). API performs no outbound calls (SSRF N/A)                    |
| A02 | Cryptographic Failures | ✅ | BCrypt strength 12 + JWT HS256 + HTTPS in production                                                |
| A03 | **Software Supply Chain Failures** 🆕 | ✅ | OWASP Dependency Check en CI (`failOnCVSS ≥ 7`) + pinned dependencies in `pom.xml`                  |
| A04 | Injection | ✅ | Hibernate prepared statements + Bean Validation on all endpoints                                    |
| A05 | Security Misconfiguration | ✅ | Hidden error messages, no stack traces to client, secure headers                                    |
| A06 | Insecure Design | ✅ | Documented threat modeling, transaction limits, threshold-based 2FA                                 |
| A07 | Identification & Authentication Failures | ✅ | Dual-token JWT (15min/7d) + TOTP 2FA + lockout + 30min inactivity                                   |
| A08 | Software and Data Integrity Failures | ✅ | CodeQL in GitHub Actions, SQL scripts versioned in Git                                              |
| A09 | Security Logging & Monitoring Failures | ✅ | Full auditing in `audit_logs`, Log4j2, all security events logged                                   |
| A10 | **Mishandling of Exceptional Conditions** 🆕 | ✅ | Centralized `GlobalExceptionHandler` never “fail open”, no sensitive data in errors |

---

## Authentication and Authorization

### Authentication Flow
```
POST /auth/login
  → Validate credentials (username + BCrypt password)
  → Verify account is not locked
  → If 2FA required → POST /auth/2fa/verify
  → Generate Access Token (15 min) + Refresh Token (7 days)
  → Register session in sessions table
  → Audit log login event
  → Return tokens to client
```

### Token Refresh
```
POST /auth/refresh
  → Validate Refresh Token (signature + expiration + exists in DB)
  → Rotate Refresh Token (invalidate old one, generate new one)
  → Return new Access Token (15 min) + new Refresh Token
```

### Session Invalidation
```
POST /auth/logout
  → Invalidate Refresh Token in DB (sessions table)
  → Audit log logout event
  → Access Token naturally expires within 15 minutes
```

---

## Session Management

| Parameter | Value | Reason |
|---|--|---|
| **Access Token TTL** | **15 minutes** | Short window if stolen |
| **Refresh Token TTL** | **7 days** | Security/UX balance |
| **Max inactivity** | **30 minutes** | Banking standard — invalidates session |
| **Reauthentication** | Required for sensitive operations | See 2FA section |
| **Concurrent sessions** | Allowed (tracked in DB) | Auditable per device |

### Why 15 minutes for the Access Token?
A stolen Access Token (via XSS, log leak, etc.) can only be used for 15 minutes.
With 24h tokens, an attacker gets nearly a full day of access.
For a wallet, 15 minutes is the right balance between security and user experience
(refresh is transparent when implemented correctly).

---

## Two-Factor Authentication (2FA)

### Technology: TOTP (RFC 6238)
Compatible with Google Authenticator, Authy, and similar apps.

### When is 2FA required?

| Scenario | 2FA Required |
|---|---|
| Transfers > $100 | ✅ Required |
| Withdrawals > $100 | ✅ Required |
| Password change | ✅ Required |
| Email change | ✅ Required |
| Administrative operations | ✅ Required |
| Login from new device | ⚠️ Recommended |
| Balance inquiry | ❌ Not required |

### Why $100 instead of $5,000?
For an educational/portfolio wallet, $100 reflects better security practices.
A $5,000 threshold implies smaller amounts are not important — but in financial security,
thresholds must be low to protect everyday transactions.

---

## Encryption and Data Protection

### In transit
- HTTPS/TLS required in production
- HTTP allowed only in local development

### At rest — passwords
- BCrypt with strength 12
- Passwords are **never** stored in plaintext or reversible formats

### At rest — financial data
- Balances and amounts stored as `DECIMAL(19,4)` — no rounding
- Sensitive fields (e.g., account numbers) considered for column-level encryption using
  PostgreSQL (`pgcrypto`) — see ADR-007
- Audit logs never store sensitive data (passwords, full tokens)

### JWT Secret
- Minimum 256-bit entropy
- Stored exclusively as environment variable `JWT_SECRET`
- Never in source code, never in logs

---

## 🚨 Rules That Must NEVER Be Violated

1. `ddl-auto` is never  `create` or `update` in any environment
2. Stack traces never reach the client
3. Passwords are never logged or returned in any response
4. JWT secret is never hardcoded — always environment variable
5. Financial operations always run inside `@Transactional`
6. Every security event generates an entry in `audit_logs`
7. Input validation is required on **all** endpoints (`@Valid`)

---

## Vulnerability Reporting

This is an academic/portfolio project.
If you find a vulnerability, open an issue with the `security` label.