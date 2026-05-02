# 🔐 Secure Wallet API

A **learning project** built to explore real-world security practices in the context of a digital savings wallet REST API.

Built with **Java 17**, **Spring Boot 3.4.2**, **PostgreSQL 16** and **Docker**.

> **Security is a first-class concern here — not an afterthought.**
> Every architectural decision is documented, every security rule references OWASP, and every sensitive operation is audited.

---

## 🎯 What This Project Is

This is an academic/portfolio project designed to answer a specific question:

> *How would a financial API look if security, auditability, and correctness were treated as requirements from day one — before a single line of business code is written?*

The result is a digital savings wallet where users can deposit, withdraw, and transfer money between accounts — built with the same security discipline you'd expect in a real fintech product.

**Core priorities (in order):**
1. **Security** — OWASP Top 10 (2025) compliance throughout
2. **Correctness** — ACID financial transactions, no money lost
3. **Auditability** — every sensitive operation logged and traceable
4. **Maintainability** — clean, documented, testable code

---

## ✨ Features

### 👤 User Management
- Register, update profile, and soft-delete accounts
- Role-based access control: `USER`, `ADMIN`, `MANAGER`
- Account lockout after 5 failed login attempts (30-minute cooldown)
- Two-Factor Authentication (2FA / TOTP — RFC 6238, Google Authenticator compatible)
- Email verification flag and login tracking

### 💰 Savings Wallets
- One wallet per user per currency
- Multi-currency support: USD, EUR, COP, MXN, ARS
- Real-time balance with ACID-guaranteed updates
- Wallet states: `ACTIVE`, `SUSPENDED`, `CLOSED`

### 💸 Financial Transactions
| Operation | Description |
|-----------|-------------|
| **Deposit** | Add funds from an external source into a wallet |
| **Withdrawal** | Move funds from a wallet to an external destination |
| **Transfer** | Move funds between any two wallets in the system |
| **History** | Full state-change log per transaction |

- 2FA required for operations above **$100**
- Transaction limit: $10,000 | Daily limit: $50,000
- Pessimistic locking (`FOR UPDATE`) on all balance reads
- Unique reference code per transaction
- JSONB metadata (IP, device, geolocation) for fraud detection

### 🔒 Security & DevSecOps
- Dual-token JWT: Access Token (15 min) + Refresh Token (7 days)
- Refresh Token rotation and revocation stored in the database
- SHA-256 for token hashing — BCrypt only for passwords
- UUID primary keys on all entities (prevents enumeration)
- Stack traces never exposed to the client
- OWASP Dependency Check in CI — **fails build on CVSS ≥ 7**
- CodeQL static analysis on every PR

### 📋 Audit Trail
- Independent `audit/` domain — auditing is a business requirement, not a cross-cutting concern
- Every sensitive operation generates an `audit_logs` entry
- IP address, User-Agent, timestamp, and JSONB details per event
- PostgreSQL triggers for automatic state-change auditing

---

## 🏗️ Architecture

**Pattern:** Hybrid Domain-Driven Design — layers organized **by domain**, never by class type.

```
com.wallet.secure/
├── config/          # SecurityConfig, OpenApiConfig, AuditConfig, JwtConfig
├── auth/            # Authentication: JWT, 2FA, sessions
│   ├── controller/  # AuthController, SessionController
│   ├── dto/         # LoginRequest, AuthResponse, RefreshTokenRequest
│   ├── entity/      # Session
│   ├── repository/  # SessionRepository
│   ├── security/    # JwtAuthFilter, JwtService, UserDetailsServiceImpl
│   └── service/     # AuthService, SessionService
├── user/            # Users and profiles
├── wallet/          # Wallets and balances
├── transaction/     # Transactions + history (business core)
├── audit/           # Security audit trail
└── common/          # ApiResponse<T>, exceptions, enums, validators
```

**Architecture rule:** NEVER create root-level folders by type (`controllers/`, `services/`). Each domain owns its own layers.

> 📖 [`CONTEXT.md`](CONTEXT.md) — Single source of truth: full architecture, stack, conventions, and rules.
> 📖 [`DECISIONS.md`](DECISIONS.md) — 8 Architecture Decision Records with full reasoning for every major choice.

---

## 🛡️ Security Model

### Why Authentication and Authorization Matter Here

A wallet API without a solid auth model is not a wallet — it's an open bank account.

This project enforces two distinct layers:

**Authentication** — *Who are you?*
Dual-token JWT ensures a stolen Access Token is useless after 15 minutes. The Refresh Token is stored as a SHA-256 hash in the database, enabling real revocation on logout. Sessions are tracked per device.

**Authorization** — *What are you allowed to do?*
`userId` is **always** extracted from the JWT — never from the request body or path parameters. This means a user cannot access another user's wallet by simply changing an ID in the URL. Resources respond with `404` (not `403`) to prevent enumeration.

```
POST /auth/login
  → Validate credentials (BCrypt password check)
  → Check account not locked
  → If operation requires 2FA → POST /auth/2fa/verify
  → Issue Access Token (15 min) + Refresh Token (7 days)
  → Register session in DB
  → Audit log event
  → Return tokens

POST /auth/refresh
  → Validate Refresh Token (signature + expiry + exists in DB)
  → Rotate token (invalidate old, issue new)
  → Return new Access Token + new Refresh Token

POST /auth/logout
  → Revoke Refresh Token in DB
  → Audit log event
  → Access Token expires naturally within 15 min
```

### Session Parameters

| Parameter | Value | Reason |
|-----------|-------|--------|
| Access Token TTL | 15 minutes | Limits exposure if stolen |
| Refresh Token TTL | 7 days | Security/UX balance |
| Max inactivity | 30 minutes | Banking standard |
| Concurrent sessions | Allowed | Tracked per device in DB |
| 2FA threshold | $100 | Protects everyday transactions, not just large ones |

### OWASP Top 10 (2025) Coverage

> OWASP Top 10 2025 was published on November 6, 2025 at the Global AppSec Conference in Washington D.C.

| # | Risk | Status | How it is addressed |
|---|------|--------|---------------------|
| A01 | Broken Access Control *(includes SSRF)* | ✅ | `userId` from JWT only — never from request. `404` on ownership mismatch. RBAC via Spring Security. API makes no outbound calls (SSRF N/A) |
| A02 | Cryptographic Failures | ✅ | BCrypt strength 12 for passwords. SHA-256 for token hashing. JWT signed with HS256. HTTPS required in production. `DECIMAL(19,4)` for money — no float precision errors |
| A03 | Software Supply Chain Failures 🆕 | ✅ | OWASP Dependency Check in CI (`failOnCVSS ≥ 7`). All dependency versions pinned in `pom.xml` |
| A04 | Injection | ✅ | Hibernate prepared statements on all queries. Bean Validation (`@Valid`) on every endpoint input |
| A05 | Security Misconfiguration | ✅ | Error messages never expose internals. Stack traces never sent to client. No default credentials. Secure HTTP headers. Limited Actuator exposure |
| A06 | Insecure Design | ✅ | Documented threat model. Transaction limits. 2FA threshold at $100. Pessimistic locking for concurrent balance reads |
| A07 | Identification & Authentication Failures | ✅ | Dual-token JWT (15 min / 7 days). TOTP 2FA (RFC 6238). Account lockout. 30-min inactivity. Refresh Token rotation and revocation |
| A08 | Software and Data Integrity Failures | ✅ | CodeQL static analysis in GitHub Actions. SQL schema versioned in Git. Hibernate `ddl-auto: validate` |
| A09 | Security Logging & Monitoring Failures | ✅ | Every security event logged to `audit_logs`. Log4j2 async logging. No passwords or tokens ever written to logs |
| A10 | Mishandling of Exceptional Conditions 🆕 | ✅ | Centralized `GlobalExceptionHandler` — never "fail open". No sensitive data in error responses |

---

## 🗄️ Database

PostgreSQL 16 with schema managed exclusively by versioned SQL scripts. Hibernate only validates — never creates or modifies tables.

| # | Script | Purpose |
|---|--------|---------|
| 01 | `extensions.sql` | PostgreSQL extensions: `pgcrypto`, `uuid-ossp` |
| 02 | `types.sql` | 7 custom ENUMs (roles, currencies, statuses) |
| 03 | `tables.sql` | 6 core tables with constraints and FK rules |
| 04 | `index.sql` | Partial, composite, and GIN indexes |
| 05 | `triggers.sql` | Auto-update timestamps, balance validation, state-change audit |
| 06 | `functions.sql` | `process_transaction()` ACID, `cleanup_expired_sessions()` |
| 07 | `seed.sql` | Development test data only |
| 08 | `migrations.sql` | Incremental schema changes |

> 📖 [`database/README.md`](database/README.md) — Full ER diagram, FK rules, and DB security design decisions.

---

## 🛠️ Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Language | Java | 17 |
| Framework | Spring Boot | 3.4.2 |
| Security | Spring Security + JWT | jjwt 0.12.6 |
| Database | PostgreSQL | 16-alpine |
| ORM | Spring Data JPA / Hibernate | — |
| Logging | Log4j2 | 2.25.3 |
| Validation | Spring Bean Validation | — |
| Boilerplate | Lombok | 1.18.36 |
| API Docs | SpringDoc OpenAPI | 2.8.8 |
| Tests | JUnit 5 + Mockito + AssertJ | — |
| Containers | Docker + Docker Compose | — |
| CI/CD | GitHub Actions | — |
| Static Analysis | CodeQL | — |
| Dependency Scanning | OWASP Dependency Check | 12.2.0 |

---

## 🚀 Getting Started

### Prerequisites
- Java 17+
- Docker & Docker Compose
- Maven 3.9+ (Maven wrapper `./mvnw` included)

### Run locally

```bash
# 1. Clone the repository
git clone https://github.com/DJAngel973/Secure-Wallet-API.git
cd Secure-Wallet-API

# 2. Set up environment variables
cp .env.example .env
# Edit .env with your local values (DB credentials, JWT secret, ports)

# 3. Start everything (automated script)
./script/dev-start.sh

# Or step by step:
docker compose up -d                     # PostgreSQL only
docker compose --profile tools up -d    # PostgreSQL + pgAdmin at http://localhost:5050
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

### Stop

```bash
./script/dev-stop.sh
```

### Run tests

```bash
./mvnw test                                        # All unit tests (H2 in-memory, no DB needed)
./mvnw test -Dtest=TransactionServiceTest          # Single test class
```

---

## 📡 Using the API

Once the application is running, the full interactive API documentation is available at:

```
http://localhost:8080/swagger-ui.html
```

All endpoints return a standard `ApiResponse<T>` envelope:

```json
{
  "success": true,
  "message": "Operation completed",
  "data": { }
}
```

### 1. Register a new user

```http
POST /auth/register
Content-Type: application/json

{
  "email": "alice@example.com",
  "password": "SecureP@ss1",
  "firstName": "Alice",
  "lastName": "Smith"
}
```

### 2. Login and get tokens

```http
POST /auth/login
Content-Type: application/json

{
  "email": "alice@example.com",
  "password": "ExampleSecureP@ss1"
}
```

```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "accessToken": "ExampleekeypracticeyJhbGc...",
    "refreshToken": "ExampleekeypracticeyJhbGcNiJ9...",
    "tokenType": "Bearer",
    "expiresIn": 900
  }
}
```

> Use the `accessToken` as a Bearer token in the `Authorization` header for all protected requests.

### 3. Get your own profile

```http
GET /users/me
Authorization: Bearer <accessToken>
```

### 4. Create a wallet

```http
POST /wallets
Authorization: Bearer <accessToken>
Content-Type: application/json

{
  "currency": "USD"
}
```

### 5. Deposit funds

```http
POST /transactions/deposit
Authorization: Bearer <accessToken>
Content-Type: application/json

{
  "walletId": "ExampleekeypracticeyJhbGcafa6",
  "amount": 500.00,
  "description": "Initial deposit"
}
```

### 6. Transfer between wallets

> Amounts above **$100** require a valid TOTP code. Add the `X-2FA-Code` header with the 6-digit code from your authenticator app.

```http
POST /transactions/transfer
Authorization: Bearer <accessToken>
X-2FA-Code: 123456
Content-Type: application/json

{
  "sourceWalletId": "ExampleekeypracticeyJhbGc-2c963f66afa6",
  "targetWalletId": "ExampleekeypracticeyJhbGc-3d074g77bgb7",
  "amount": 150.00,
  "description": "Splitting dinner"
}
```

### 7. Get transaction history for a wallet

```http
GET /transactions/wallet/ExampleekeypracticeyJhbGcafa6
Authorization: Bearer <accessToken>
```

### 8. Refresh your access token

```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "ExampleekeypracticeyJhbGcNiJ9..."
}
```

### 9. Logout

```http
POST /auth/logout
Authorization: Bearer <accessToken>
Content-Type: application/json

{
  "refreshToken": "ExampleekeypracticeyJhbGcNiJ9..."
}
```

---

## 🔄 CI/CD Pipeline

| Job | Trigger | Description |
|-----|---------|-------------|
| **Build & Test** | Every PR / push | Compile + unit tests (JUnit 5, `test` profile with H2) |
| **OWASP Dependency Check** | Every PR / push | CVE scan — **fails on CVSS ≥ 7** |
| **CodeQL Analysis** | Every PR / push | Static security analysis |
| **Package JAR** | Merge to `main` | Builds production artifact |

---

## 📚 Project Documentation

| Document | Description |
|----------|-------------|
| [`CONTEXT.md`](CONTEXT.md) | Single source of truth: architecture, stack, conventions, and rules |
| [`DECISIONS.md`](DECISIONS.md) | 8 Architecture Decision Records with full reasoning |
| [`SECURITY.md`](SECURITY.md) | Threat model, OWASP Top 10 (2025) full coverage, unbreakable rules |
| [`AGENTS.md`](AGENTS.md) | Instructions for AI agents working on this codebase |
| [`database/README.md`](database/README.md) | ER diagram, FK rules, DB security design decisions |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Community standards |

---

## 🔐 Security Vulnerability Reporting

This is an academic/portfolio project.
If you find a vulnerability, please open an issue with the `security` label.

---

## 📄 License

[MIT](LICENSE) © 2025–2026 DJAngel973
