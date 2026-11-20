# Secure Wallet API

Educational-professional REST API for a simulated multi-currency savings wallet, with an emphasis on applied security, traceability, and DevSecOps practices.

Built with **Java 17**, **Spring Boot 3.4.2**, and **PostgreSQL 16**.

> This project is designed for local learning and portfolio demonstration. All balances and operations are simulated: it does not process real money and is not intended for public production deployment.
>
> The agreed educational implementation scope is closed. [`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md) records what was verified and its limits; it is not a backlog of promised features or a production-readiness certificate.

---

## What is this

Secure Wallet API explores how the main components of a savings-wallet backend work together:

- User registration and profile management
- Savings wallets in USD, EUR, COP, MXN, and ARS
- Simulated deposits, withdrawals, and transfers
- JWT authentication with access and refresh tokens
- Role- and ownership-based authorization
- Security and transaction audit trails
- PostgreSQL constraints and ACID transaction boundaries
- Automated build, test, dependency scanning, and static analysis workflows

The goal is to study both successful flows and failure scenarios: unauthorized access, invalid tokens, insufficient balances, concurrent updates, session revocation, and auditability.
It is a learning reference for **Spring Security authentication and authorization**, not a template that can be deployed unchanged for real users or money.

---

## Feature status

Status labels used below:

- **Implemented** — code for the capability exists.
- **Verified** — automated or documented functional evidence exists.
- **Partial** — some parts exist, but the complete requirement is not yet satisfied or verified.
- **Out of scope** — intentionally not implemented in this educational release; assess separately for a real-world system.

### User Management

- **Implemented:** public registration creates `USER` accounts; profile read/update and soft deactivation are available.
- **Implemented:** the target business roles are `USER` and `ADMIN`; privileged access uses Spring Security method authorization.
- **Verified:** controlled first-`ADMIN` bootstrap, with no SQL-seeded administrator ([SEC-001/002](docs/IMPLEMENTATION-PLAN.md#sec-001--separate-development-seed-data-from-automatic-initialization), [`AdminBootstrapServiceTest`](src/test/java/com/wallet/secure/user/service/AdminBootstrapServiceTest.java)).
- **Verified:** `ADMIN` may deactivate `USER` accounts, but no API creates or promotes administrators ([AUTHZ-001](docs/IMPLEMENTATION-PLAN.md#authz-001--implement-controlled-management-of-regular-users), [`UserServiceTest`](src/test/java/com/wallet/secure/user/service/UserServiceTest.java)).
- **Verified:** five failed logins cause a 30-minute lock; disabled/locked accounts cannot authenticate with existing access tokens ([SEC-005/006](docs/IMPLEMENTATION-PLAN.md#sec-005--correct-login-attempt-lockout), [`LoginAttemptServiceTest`](src/test/java/com/wallet/secure/auth/service/LoginAttemptServiceTest.java), [`JwtAuthFilterTest`](src/test/java/com/wallet/secure/auth/security/JwtAuthFilterTest.java)).

### Multi-Currency Savings Wallets

- **Implemented:** one wallet per user and currency.
- **Implemented:** USD, EUR, COP, MXN, and ARS currencies.
- **Implemented:** `ACTIVE`, `SUSPENDED`, and `CLOSED` wallet states.
- **Verified:** ownership and administrative wallet route matrix ([AUTHZ-002](docs/IMPLEMENTATION-PLAN.md#authz-002--review-wallet-permissions-and-ownership), [`SecurityConfigTest`](src/test/java/com/wallet/secure/config/SecurityConfigTest.java)).

### Financial Transactions

| Operation | Description | Status |
|-----------|-------------|--------|
| Deposit | Add simulated external funds to a wallet | Implemented |
| Withdrawal | Remove simulated funds from a wallet | Implemented |
| Transfer | Move simulated funds between wallets | Implemented |
| History | Read transaction state changes | Implemented |

- **Implemented:** `BigDecimal`/`DECIMAL(19,4)` amounts, transactional service boundaries, reference codes, and pessimistic balance locking.
- **Verified for tested cases:** concurrent debits, rollback, ownership, history, and audit evidence in PostgreSQL; the local Postman collection was also reported passing ([TX-001](docs/IMPLEMENTATION-PLAN.md#tx-001--verify-transactions-concurrency-rollback-and-audit-behavior), [`TransactionPostgresIntegrationTest`](src/test/java/com/wallet/secure/transaction/integration/TransactionPostgresIntegrationTest.java), [Postman guide](POSTMAN_PORTFOLIO_PLAN.md)). Rejected operations roll back their transaction/history rows and retain failure audit evidence.
- **Out of scope:** configurable transaction/daily limits are not enforced; a real-money system would need a per-currency, concurrency-safe policy ([security guidance](SECURITY.md#considerations-for-real-world-projects)).

### Authentication & Security

- **Implemented:** short-lived access JWTs and longer-lived refresh JWTs.
- **Implemented:** JWT signature, expiration, issuer, and token-type validation.
- **Implemented:** BCrypt password hashing and Spring Security authentication.
- **Implemented:** refresh-session tracking and revocation support.
- **Verified:** refresh-token rotation and revocation use SHA-256 hashes in `user_sessions`; legacy raw-token storage was removed ([SEC-003/004](docs/IMPLEMENTATION-PLAN.md#sec-003--remove-original-refresh-token-storage-from-the-user-record), [`SessionServiceTest`](src/test/java/com/wallet/secure/auth/service/SessionServiceTest.java)).
- **Verified:** disabled or locked accounts are rejected during login and JWT-authenticated requests ([SEC-005/006](docs/IMPLEMENTATION-PLAN.md#sec-005--correct-login-attempt-lockout)).
- **Out of scope:** TOTP-based MFA is not implemented; evaluate it for real accounts and privileged access ([security guidance](SECURITY.md#considerations-for-real-world-projects)).

### Audit Trail

- **Implemented:** authentication, wallet, transaction, and account events have audit-writing support.
- **Implemented:** audit entries can include user, IP address, User-Agent, timestamp, severity, and contextual JSON details.
- **Verified for tested flows:** authentication, wallet, account deactivation, and financial success/failure audit evidence; this is not a claim of exhaustive event coverage ([`AuditServiceTest`](src/test/java/com/wallet/secure/audit/service/AuditServiceTest.java), [TX-001](docs/IMPLEMENTATION-PLAN.md#tx-001--verify-transactions-concurrency-rollback-and-audit-behavior)).

---

## Architecture

**Pattern:** domain-oriented layered architecture inspired by Domain-Driven Design. Code is grouped by business domain rather than by global technical layer.

```text
com.wallet.secure/
├── config/          # Security, JWT, OpenAPI, and audit configuration
├── auth/            # Authentication, JWT validation, and sessions
│   ├── controller/, dto/, entity/, repository/, security/, service/
├── user/            # Users and profiles
├── wallet/          # Wallet ownership, balances, and lifecycle
├── transaction/     # Financial operations and state history
├── audit/           # Security and business audit trail
└── common/          # Shared responses, exceptions, enums, and utilities
```

Each domain owns its controllers, DTOs, entities, repositories, and services. Controllers handle HTTP concerns, services enforce business rules, repositories provide persistence access, and DTOs limit the data accepted from or returned to clients.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Java 17 |
| Framework | Spring Boot 3.4.2 |
| Security | Spring Security + jjwt 0.12.6 |
| Database | PostgreSQL 16 |
| ORM | Spring Data JPA / Hibernate |
| Logging | Log4j2 2.25.3 |
| Validation | Spring Bean Validation |
| API Docs | SpringDoc OpenAPI 2.8.8 |
| Boilerplate | Lombok 1.18.36 |
| Tests | JUnit 5 + Mockito + AssertJ + focused security and PostgreSQL/Testcontainers integration tests |
| DevSecOps | GitHub Actions + CodeQL + OWASP Dependency Check |
| Local runtime | Docker Compose |

---

## Getting Started with Docker Compose

Docker Compose is the primary way to run the complete local environment: PostgreSQL and the Spring Boot API.

### Prerequisites

- Docker Engine or Docker Desktop
- Docker Compose v2
- Git

Java and Maven are not required to run the packaged application through Docker Compose. Java 17 is required for local development and for running Maven tests outside the containers.

### Setup

```bash
git clone https://github.com/DJAngel973/Secure-Wallet-API.git
cd Secure-Wallet-API

# Create the local, untracked environment file
cp .env.example .env

# Replace every CHANGE_ME value and configure FILE_DATA_POSTGRES

# Build and start PostgreSQL and the API
docker compose up -d --build

# Confirm container health and startup status
docker compose ps

# Follow API logs when troubleshooting startup
docker compose logs -f wallet-api
```

The API is available at `http://localhost:8080` unless `SERVER_PORT` is changed in `.env`.

> PostgreSQL executes files mounted under `docker-entrypoint-initdb.d` only when initializing an empty data directory. No SQL seed creates default users. The first administrator requires the controlled, opt-in bootstrap described in [SEC-002](docs/IMPLEMENTATION-PLAN.md#sec-002--add-controlled-one-time-bootstrap-for-the-first-administrator).

### Stop the environment

```bash
docker compose down
```

This does not delete the configured PostgreSQL data directory.

### Run automated tests

```bash
./scripts/test.sh
```

The suite combines unit tests, focused Spring Security tests, and PostgreSQL/Testcontainers concurrency tests. See [TEST-001](docs/IMPLEMENTATION-PLAN.md#test-001--expand-automated-security-and-integration-tests) for scope and limits; local Postman evidence is user-reported rather than independently reproduced by the agent.

### Explore with Postman

The versioned [Postman regression guide](POSTMAN_PORTFOLIO_PLAN.md) explains how to import
`postman/wallet.postman_collection.json` and the sanitized
`postman/wallet.local.postman_environment.json` template, set a private
fictitious password, and run the ordered collection. It covers positive and
negative wallet, transaction, authorization, and refresh-token flows without
requiring public administrator credentials. The user-reported local Collection
Runner result (29 requests, 89/89 assertions) is recorded in the guide;
it has not been independently rerun by the agent.

### Interactive API documentation

Swagger UI is available locally at:

[http://localhost:8080/swagger-ui/index.html](http://localhost:8080/swagger-ui/index.html)

All API responses use a standard wrapper:

```json
{
  "success": true,
  "message": "Operation completed",
  "data": {}
}
```

---

## Database

PostgreSQL 16 is managed through numbered SQL scripts. The published application configuration uses `ddl-auto: validate`, so Hibernate validates the schema instead of creating or updating it.

| # | Script | Purpose | Current status |
|---|--------|---------|----------------|
| 01 | `extensions.sql` | PostgreSQL extensions | Implemented |
| 02 | `types.sql` | Roles, currencies, and status enums | Implemented |
| 03 | `tables.sql` | Tables, constraints, and foreign keys | Implemented |
| 04 | `index.sql` | Partial, composite, and GIN indexes | Implemented |
| 05 | `triggers.sql` | Timestamp, balance, and history triggers | Implemented |
| 06 | `functions.sql` | Database transaction-processing functions | Implemented |
| 07 | — | No SQL seed or default administrator | Verified |
| 08 | `08-migrations.sql` | Incremental changes for existing databases; not a fresh-init seed | Implemented |

The database schema is part of the security boundary: unique constraints, ownership relationships, non-negative balances, transaction consistency, and append-oriented audit/history records complement application-layer validation.

---

## OWASP Top 10:2025 alignment

OWASP Top 10 is used as an awareness and review framework, not as a certification that every risk has been eliminated.

| Category | Current project alignment | Status |
|----------|---------------------------|--------|
| A01:2025 Broken Access Control | [Role and ownership tests](src/test/java/com/wallet/secure/config/SecurityConfigTest.java) | Tested routes only |
| A02:2025 Security Misconfiguration | [Security configuration](src/main/java/com/wallet/secure/config/SecurityConfig.java), [seed removal](docs/IMPLEMENTATION-PLAN.md#sec-001--separate-development-seed-data-from-automatic-initialization) | Local deployment is not public-ready |
| A03:2025 Software Supply Chain Failures | [Dependency Check and CodeQL workflows](.github/workflows/ci.yml) | Actual scan results must be checked |
| A04:2025 Cryptographic Failures | [Hashed/rotated refresh sessions](src/test/java/com/wallet/secure/auth/service/SessionServiceTest.java) | Key management and infrastructure encryption unverified |
| A05:2025 Injection | [DTO validation and JPA code](src/main/java) | No exhaustive injection assessment |
| A06:2025 Insecure Design | [PostgreSQL concurrency tests](src/test/java/com/wallet/secure/transaction/integration/TransactionPostgresIntegrationTest.java) | TOTP and limits are out of scope, not implemented |
| A07:2025 Authentication Failures | [Lockout](src/test/java/com/wallet/secure/auth/service/LoginAttemptServiceTest.java), [JWT state](src/test/java/com/wallet/secure/auth/security/JwtAuthFilterTest.java) | No TOTP or inactivity timeout; assess for real users |
| A08:2025 Software or Data Integrity Failures | [Versioned SQL](database/), [CI](.github/workflows/ci.yml) | Release provenance unassessed |
| A09:2025 Security Logging and Alerting Failures | [Audit tests](src/test/java/com/wallet/secure/audit/service/AuditServiceTest.java) | Complete coverage/external alerting unverified |
| A10:2025 Mishandling of Exceptional Conditions | [Exception handler](src/main/java/com/wallet/secure/common/exception/GlobalExceptionHandler.java), [rollback tests](src/test/java/com/wallet/secure/transaction/integration/TransactionPostgresIntegrationTest.java) | Tested cases only |

Category names/order follow the [official OWASP release](https://top10.owasp.org/2025/). See [`SECURITY.md`](SECURITY.md) for the threat model; the implementation plan is the authoritative status tracker.

---

## CI/CD

| Job | Trigger | Purpose | Status |
|-----|---------|---------|--------|
| Build & Test | Push to `main` / PR targeting `main` | Compile and run automated tests | Implemented |
| OWASP Dependency Check | Push to `main` / PR targeting `main` | Scan dependencies for known vulnerabilities | Implemented |
| CodeQL Analysis | Push/PR to `main` and weekly schedule | Static security analysis | Implemented |
| Package | Push to `main` after prior jobs | Generate and upload the application JAR | Implemented |

These workflows provide automated evidence, but passing CI does not replace functional security testing or a production-readiness assessment.

---

## Closed scope and implementation evidence

The completed educational-scope remediation and verification record is:

[`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md)

The plan distinguishes:

- Confirmed architectural requirements
- Detected implementation defects
- Controls deliberately left outside this educational release
- Automated and Postman acceptance evidence

---

## Project documentation

| Document | What it covers |
|----------|---------------|
| [`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md) | Prioritized remediation, implementation, and verification work |
| [`CONTEXT.md`](CONTEXT.md) | Architecture, conventions, and stack context |
| [`DECISIONS.md`](DECISIONS.md) | Architecture Decision Records and rationale |
| [`SECURITY.md`](SECURITY.md) | Threat model and target security controls |
| [`database/README.md`](database/README.md) | Database model, constraints, and local setup |

---

## License

[MIT](LICENSE) © 2025–2026 DJAngel973
