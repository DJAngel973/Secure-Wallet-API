# Secure Wallet API

Educational-professional REST API for a simulated multi-currency savings wallet, with an emphasis on applied security, traceability, and DevSecOps practices.

Built with **Java 17**, **Spring Boot 3.4.2**, and **PostgreSQL 16**.

> This project is designed for local learning and portfolio demonstration. All balances and operations are simulated: it does not process real money and is not intended for public production deployment.
>
> The project is under active development. Confirmed requirements, detected defects, pending decisions, and verification work are tracked in [`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md).

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

---

## Feature status

Status labels used below:

- **Implemented** — code for the capability exists.
- **Verified** — automated or documented functional evidence exists.
- **Partial** — some parts exist, but the complete requirement is not yet satisfied or verified.
- **Planned** — confirmed requirement or candidate decision that has not been fully implemented.

### User Management

- **Implemented:** public registration creates `USER` accounts; profile read/update and soft deactivation are available.
- **Implemented:** the target business roles are `USER` and `ADMIN`; privileged access uses Spring Security method authorization.
- **Planned:** the first `ADMIN` will be created through a controlled one-time bootstrap without public default credentials.
- **Planned:** administrators will manage regular users but will not create other administrators through the public API.
- **Partial:** account-state and failed-login controls exist in the model, but the complete lockout flow still requires correction and functional verification.

### Multi-Currency Savings Wallets

- **Implemented:** one wallet per user and currency.
- **Implemented:** USD, EUR, COP, MXN, and ARS currencies.
- **Implemented:** `ACTIVE`, `SUSPENDED`, and `CLOSED` wallet states.
- **Partial:** ownership and administrative wallet operations are implemented but still require complete authorization tests.

### Financial Transactions

| Operation | Description | Status |
|-----------|-------------|--------|
| Deposit | Add simulated external funds to a wallet | Implemented |
| Withdrawal | Remove simulated funds from a wallet | Implemented |
| Transfer | Move simulated funds between wallets | Implemented |
| History | Read transaction state changes | Implemented |

- **Implemented:** `BigDecimal`/`DECIMAL(19,4)` amounts, transactional service boundaries, reference codes, and pessimistic balance locking.
- **Partial:** concurrency, rollback, ownership, and complete audit behavior require PostgreSQL-backed and Postman verification.
- **Pending decision:** configurable transaction limits and thresholds must be reviewed before full implementation.

### Authentication & Security

- **Implemented:** short-lived access JWTs and longer-lived refresh JWTs.
- **Implemented:** JWT signature, expiration, issuer, and token-type validation.
- **Implemented:** BCrypt password hashing and Spring Security authentication.
- **Implemented:** refresh-session tracking and revocation support.
- **Partial:** refresh-token rotation and removal of legacy raw-token storage remain required.
- **Partial:** disabled or locked accounts must be rejected consistently during both login and JWT-authenticated requests.
- **Pending decision:** TOTP-based 2FA requires a separate design review before full implementation.

### Audit Trail

- **Implemented:** authentication, wallet, transaction, and account events have audit-writing support.
- **Implemented:** audit entries can include user, IP address, User-Agent, timestamp, severity, and contextual JSON details.
- **Partial:** complete event coverage and failure resilience still require end-to-end verification.

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
| Tests | JUnit 5 + Mockito + AssertJ + H2 security integration test |
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

> PostgreSQL executes files mounted under `docker-entrypoint-initdb.d` only when initializing an empty data directory. The current development seed is tracked as a remediation item because public default administrative credentials must not be part of the standard initialization path.

### Stop the environment

```bash
docker compose down
```

This does not delete the configured PostgreSQL data directory.

### Run automated tests

```bash
./mvnw test
./mvnw test -Dtest=TransactionServiceTest
```

The current suite primarily contains Mockito unit tests plus a small Spring Security integration test using H2. It does not yet prove complete PostgreSQL or HTTP end-to-end behavior.

### Explore with Postman

Postman is the primary tool for demonstrating complete local API flows. The planned functional verification covers:

1. Register and login as a regular user.
2. Store the access and refresh tokens as environment variables.
3. Send `Authorization: Bearer <accessToken>` to protected endpoints.
4. Create wallets and perform simulated deposits, withdrawals, and transfers.
5. Verify ownership failures, insufficient-balance failures, refresh, logout, and session revocation.
6. Use a controlled bootstrap administrator to verify `USER` versus `ADMIN` authorization.

A versioned Postman collection is planned and tracked in the implementation plan.

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
| 07 | `seed.sql` | Current development-only test data | Must be separated from automatic initialization |
| 08 | `migrations.sql` | Incremental schema changes | Implemented |

The database schema is part of the security boundary: unique constraints, ownership relationships, non-negative balances, transaction consistency, and append-oriented audit/history records complement application-layer validation.

---

## OWASP Top 10:2025 alignment

OWASP Top 10 is used as an awareness and review framework, not as a certification that every risk has been eliminated.

| Category | Current project alignment | Status |
|----------|---------------------------|--------|
| A01 — Broken Access Control | JWT-derived identity, role checks, ownership-aware repository queries, and non-enumerating `404` patterns | Partial — broader authorization tests required |
| A02 — Security Misconfiguration | Environment-based secrets, controlled error responses, container hardening, and restricted published Actuator exposure | Partial — development settings and seed initialization require review |
| A03 — Software Supply Chain Failures | Pinned key dependency versions, OWASP Dependency Check, and CodeQL workflows | Implemented; scan results remain environment-dependent |
| A04 — Cryptographic Failures | BCrypt passwords, signed JWTs, short access-token lifetime, and hashed session tokens | Partial — legacy raw refresh-token storage must be removed |
| A05 — Injection | DTO validation plus parameterized persistence through Spring Data JPA/Hibernate | Implemented; complete endpoint verification pending |
| A06 — Insecure Design | Transaction boundaries, pessimistic locking, database constraints, audit design, and documented threat decisions | Partial — configurable limits and TOTP remain pending decisions |
| A07 — Authentication Failures | Dual-token authentication, account-state modeling, session revocation, and authentication auditing | Partial — rotation, lockout, and account-state enforcement require correction and tests |
| A08 — Software or Data Integrity Failures | Versioned SQL, CI analysis, controlled schema validation, and transaction-history records | Partial — release and integration verification can be expanded |
| A09 — Security Logging & Alerting Failures | Database audit events, severity levels, IP/User-Agent context, and fallback logging design | Partial — coverage and alert behavior require functional verification |
| A10 — Mishandling of Exceptional Conditions | Centralized exception handling and transactional rollback boundaries | Partial — HTTP failure paths require end-to-end verification |

See [`SECURITY.md`](SECURITY.md) for the threat model. Where that document describes a target control not yet verified, the implementation plan is the authoritative status tracker.

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

## Roadmap and implementation status

The prioritized remediation and verification plan is maintained in:

[`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md)

The plan distinguishes:

- Confirmed architectural requirements
- Detected implementation defects
- Decisions that require further review
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
