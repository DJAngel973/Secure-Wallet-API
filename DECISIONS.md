# Architecture Decision Records (ADR)

---

## ADR-001 — Architecture: Layered + Hybrid DDD
**Date:** 2026-03 | **Status:** Accepted

**Context:** A structured architecture was needed to reflect the financial business domains.

**Options considered:**
- Classic layered structure  (`controllers/`, `services/` at root level)
- Microservices
- Hybrid DDD (layers inside each domain)

**Decision:** Hybrid DDD

**Rationale:** The classic layered structure mixes all domains and does not scale well.
Microservices are excessive without orchestration infrastructure.
Hybrid DDD provides domain cohesion (`auth/`, `user/`, `wallet/`, `transaction/`)
without the operational complexity of microservices.

---

## ADR-002 — Database managed with SQL scripts, not Hibernate DDL

**Date:** 2026-03 | **Status:** Accepted

**Context:** Spring Boot can auto‑create tables using `ddl-auto`.

**Options considered:**
- `ddl-auto: update` — automatic schema updates
- `ddl-auto: create-drop` — recreate schema on each startup
- Manual SQL scripts + `ddl-auto: validate`

**Decision:** SQL scripts + `validate`

**Rationale:** In a financial application, the database is critical and must be auditable.
Hibernate DDL auto does not provide control over custom indexes, constraints,
ACID triggers, or PostgreSQL functions.
SQL scripts are versioned in Git and fully reproducible.

---

## ADR-003 — Dual‑Token JWT (Access + Refresh) instead of long single session

**Date:** 2026-03 | **Status:** Accepted

**Context:** Needed secure authentication for a financial REST API.

**Options considered:**
- Single JWT (24h)
- Single JWT (15min, no refresh — frequent re‑login)
- Dual‑token JWT: Access (15min) + Refresh (7 days)
- Stateful HTTP sessions

**Decision:** Dual‑token JWT

**Rationale:**
- 24h tokens are unacceptable in finance — a stolen token grants nearly a full day of access
- 15min without refresh harms UX
- Dual‑token provides a short exposure window (15min) with smooth UX
- Stateless design scales horizontally without shared sessions
- Refresh Tokens stored in DB allow explicit revocation (real logout)

**Consequence:** Requires `/auth/refresh` endpoint and  `sessions` table in DB..

---

## ADR-004 — 2FA using TOTP (RFC 6238) instead of SMS

**Date:** 2026-03 | **Status:** Accepted

**Context:** Needed a second authentication factor for sensitive operations.

**Options considered:**
- SMS OTP
- Email OTP
- TOTP (Google Authenticator / Authy)
- WebAuthn / FIDO2

**Decision:** TOTP (RFC 6238)

**Rationale:**

| Method | Issue |
|---|---|
| SMS | Vulnerable to SIM swapping — common fintech attack vector |
| Email OTP | Depends on email security; variable latency |
| WebAuthn | Requires hardware keys — too complex for a portfolio project |
| **TOTP** | Offline, standard, no third‑party dependency, widely supported |

NIST SP 800‑63B discourages SMS for high‑value authentication since 2016.
TOTP is the standard for serious financial applications.

**Consequence:** Users must configure an authenticator app (Google Authenticator, Authy, etc.).

---

## ADR-005 — 2FA threshold set at $100, not $5,000

**Date:** 2026-03 | **Status:** Accepted

**Context:** Determine the amount at which 2FA is required for transfers.

**Decision:** $100

**Rationale:**
A $5,000 threshold implies that $499 transactions are “not important,” which is incorrect in financial security.
Most real‑world user damage occurs in small, frequent transactions, not large one‑off transfers.
A $100 threshold protects ~95% of everyday operations without harming UX for low‑risk payments (< $100).

---

## ADR-006 — Log4j2 instead of Logback

**Date:** 2026-03 | **Status:** Accepted

**Context:** Spring Boot uses Logback by default.

**Decision:** Log4j2 2.25.3 with exclusion of  `spring-boot-starter-logging`

**Rationale:**
- High‑performance async logging — critical with heavy audit logging
- Version 2.25.3 fully patched (CVE‑2021‑44228 Log4Shell)
- More granular configuration to separate security logs from application logs

---

## ADR-007 — Encryption at rest delegated to infrastructure

**Date:** 2026-03 | **Status:** Accepted (with note)

**Context:** Evaluate encryption of sensitive data (balances, account numbers).

**Options considered:**
- Application‑level encryption (Java) before persisting
- Column‑level encryption with PostgreSQL (`pgcrypto`)
- Disk/volume‑level encryption (infrastructure)
- No additional encryption (only BCrypt for passwords)

**Decision:** Delegate encryption to infrastructure + BCrypt for passwords

**Rationale:**
- Encrypting balances at application level breaks arithmetic operations in DB
- `pgcrypto` adds significant operational complexity for queries
- For a portfolio project, explicitly delegating encryption is more honest and professional than implementing it poorly
- **In real production:** encrypted volumes (AWS EBS encrypted, etc.)
    + `pgcrypto` for highly sensitive fields (account number, IBAN)

**Note:** This decision would be revisited before a real production deployment.
Documented explicitly to show it was evaluated, not ignored.

---

## ADR-008 — Auditing as an independent domain

**Date:** 2026-03 | **Status:** Accepted

**Context:** Auditing could be implemented as a cross‑cutting concern (AOP) or as its own domain.

**Options considered:**
- AOP with `@Around` on service methods
- Audit logic inside each service
- Independent `audit/` domain with `AuditService`

**Decision:** Independent `audit/` domain

**Rationale:**
In financial systems, auditing is a regulatory business requirement, not just a technical concern.
Having it as a domain makes it visible, testable, and modifiable without side effects on other domains.
AOP is convenient but opaque — it becomes unclear what is being audited and why without reading the aspect code.