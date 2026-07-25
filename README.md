# Secure Wallet API

Multi-currency digital savings wallet — REST API with authentication, transactions, and audit trail.

Built with **Java 17**, **Spring Boot 3.4.2**, and **PostgreSQL 16**.

> This is a learning project built with AI assistance to explore how a savings wallet API works under the hood — authentication flows, ACID financial transactions, audit logging, and security practices. Some sections still need review and polish.

---

## What is this

A REST API for a digital savings wallet where users can:

- Register and manage their profile
- Create savings wallets in multiple currencies (USD, EUR, COP, MXN, ARS)
- Deposit, withdraw, and transfer funds between wallets
- Track every operation through a full audit trail
- Authenticate with dual-token JWT and optional two-factor authentication

The idea came from wanting to understand the moving parts of a real savings wallet — not just the happy path, but edge cases, concurrency, token rotation, and what happens when things go wrong.

---

## Features

### User Management
- Registration, profile updates, and soft-delete accounts
- Role-based access: `USER`, `ADMIN`, `MANAGER`
- Account lockout after repeated failed login attempts
- Two-Factor Authentication via TOTP (compatible with Google Authenticator, Authy)

### Multi-Currency Savings Wallets
- One wallet per user per currency
- Supported currencies: USD, EUR, COP, MXN, ARS
- Wallet states: `ACTIVE`, `SUSPENDED`, `CLOSED`
- Balance updates with pessimistic locking

### Financial Transactions
| Operation | Description |
|-----------|-------------|
| Deposit | Add funds from an external source |
| Withdrawal | Move funds out to an external destination |
| Transfer | Move funds between two wallets in the system |
| History | State-change log per transaction |

- Configurable limits: max per transaction, max per day
- 2FA threshold: operations above a configurable amount require a TOTP code
- Pessimistic locking on balance reads to prevent race conditions
- Unique reference code per transaction

### Authentication & Security
- Dual-token JWT: Access Token (short-lived) + Refresh Token (longer-lived with rotation)
- Refresh token stored as SHA-256 hash — real revocation on logout
- UUID primary keys on all entities (no sequential IDs)
- Stack traces never reach the client — all errors go through a centralized handler
- Input validation on every endpoint

### Audit Trail
- Every sensitive operation generates a log entry
- IP address, User-Agent, timestamp, and contextual details per event
- Database triggers for automatic state-change tracking

---

## Architecture

**Pattern:** Domain-Driven Design — code organized by business domain, not by layer type.

```
com.wallet.secure/
├── config/          # SecurityConfig, OpenApiConfig, AuditConfig, JwtConfig
├── auth/            # Authentication: JWT, 2FA, sessions
│   ├── controller/, dto/, entity/, repository/, security/, service/
├── user/            # Users and profiles
├── wallet/          # Wallets and balances
├── transaction/     # Transactions and history (business core)
├── audit/           # Security audit log
└── common/          # ApiResponse<T>, exceptions, enums, validators
```

Each domain owns its controllers, DTOs, entities, repositories, and services. Nothing lives at the root level grouped by type.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Java 17 |
| Framework | Spring Boot 3.4.2 |
| Security | Spring Security + jjwt 0.12.6 |
| Database | PostgreSQL 16 (Docker) |
| ORM | Spring Data JPA / Hibernate |
| Logging | Log4j2 |
| Validation | Spring Bean Validation |
| API Docs | SpringDoc OpenAPI 2.8.8 (Swagger) |
| Boilerplate | Lombok |
| Tests | JUnit 5 + Mockito + AssertJ |
| CI/CD | GitHub Actions + CodeQL + OWASP Dependency Check |

---

## Getting Started

### Prerequisites
- Java 17+
- Docker and Docker Compose

### Setup

```bash
git clone https://github.com/DJAngel973/Secure-Wallet-API.git
cd Secure-Wallet-API

# Copy and fill in the environment variables
cp .env.example .env

# Start PostgreSQL
docker compose up -d

# Run the application (dev profile)
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

### Run tests

```bash
./mvnw test                              # All unit tests (uses H2 in-memory, no DB needed)
./mvnw test -Dtest=TransactionServiceTest  # Single test class
```

### Interactive API docs

Once running: [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)

All responses follow a standard wrapper:

```json
{
  "success": true,
  "message": "Operation completed",
  "data": { }
}
```

---

**Note:** endpoints listed in Features above have not been tested end-to-end yet. The Swagger UI at `http://localhost:8080/swagger-ui.html` lists all available endpoints for exploration when the app is running.

---

## Database

PostgreSQL 16 with schema managed through versioned SQL scripts — Hibernate validates but never creates or modifies tables.

| # | Script | Purpose |
|---|--------|---------|
| 01 | `extensions.sql` | PostgreSQL extensions (pgcrypto, uuid-ossp) |
| 02 | `types.sql` | Custom ENUMs (roles, currencies, statuses) |
| 03 | `tables.sql` | Core tables with constraints and foreign keys |
| 04 | `index.sql` | Partial, composite, and GIN indexes |
| 05 | `triggers.sql` | Auto-timestamps, balance validation, state-change audit |
| 06 | `functions.sql` | `process_transaction()` with ACID guarantees |
| 07 | `seed.sql` | Development test data |
| 08 | `migrations.sql` | Incremental schema changes |

---

## OWASP Top 10 (2025) coverage

This project uses the OWASP Top 10 as a guide for security decisions. Here is what is currently addressed:

| # | Risk | How it is handled |
|---|------|-------------------|
| A01 | Broken Access Control | `userId` always from JWT — never from request body. `404` on ownership mismatch. RBAC via Spring Security. |
| A02 | Cryptographic Failures | BCrypt strength 12 for passwords. SHA-256 for token hashing. `DECIMAL(19,4)` for amounts. |
| A03 | Software Supply Chain Failures | OWASP Dependency Check in CI. Pinned dependency versions. |
| A04 | Injection | Hibernate prepared statements. Bean Validation on all inputs. |
| A05 | Security Misconfiguration | No internals exposed in errors. No default credentials. Secure headers. |
| A06 | Insecure Design | Transaction and daily limits. 2FA threshold. Pessimistic locking on balance reads. |
| A07 | Auth Failures | Dual-token JWT with rotation. Account lockout. TOTP 2FA. |
| A08 | Data Integrity Failures | CodeQL in CI. SQL scripts versioned in Git. `ddl-auto: validate`. |
| A09 | Logging & Monitoring | All security events written to `audit_logs`. No passwords or tokens in logs. |
| A10 | Mishandled Exceptions | Centralized exception handler. Never "fail open". |

---

## CI/CD

| Job | When | What |
|-----|------|------|
| Build & Test | Every push / PR | Compile + unit tests (H2 in-memory) |
| OWASP Dependency Check | Every push / PR | CVE scan |
| CodeQL Analysis | Every push / PR + weekly | Static security analysis |
| Package | Merge to main | Production JAR |

---

## Future plans

- Review and test all endpoints end-to-end
- Polish existing code sections marked for improvement
- Postman collection for easier API exploration

---

## Project documentation

| Document | What it covers |
|----------|---------------|
| [`CONTEXT.md`](CONTEXT.md) | Architecture, conventions, full stack details |
| [`DECISIONS.md`](DECISIONS.md) | 8 Architecture Decision Records with reasoning |
| [`SECURITY.md`](SECURITY.md) | Threat model and security decisions in depth |
| [`database/README.md`](database/README.md) | ER diagram, foreign key rules, DB design |

---

## License

[MIT](LICENSE) © 2025–2026 DJAngel973
