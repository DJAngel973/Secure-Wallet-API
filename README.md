# Secure Wallet API

A secure, production-ready RESTful API for digital wallet management, built with **Java 17**, **Spring Boot 3**, **PostgreSQL 16**, and **Docker**. Designed with a **DevSecOps-first** approach: security, automation, testing, and code quality are built in from day one.

---

## Features

### User Management (Admin)
- Create, update, and soft-delete users
- Role-based access control: `USER`, `ADMIN`, `MANAGER`
- Account locking after failed login attempts
- Full audit trail of administrative actions

### Wallet Service (User)
- Digital savings account (wallet) per user, per currency
- Multi-currency support (USD, EUR, COP, MXN, ARS)
- Real-time balance with ACID-guaranteed updates

### Transaction Service (User)
- **Deposit**: add funds from an external source
- **Withdrawal**: withdraw funds to an external destination
- **Transfer**: move funds between any two wallets
- Full transaction history and account statements

### Security (DevSecOps)
- JWT authentication with refresh token rotation
- Two-Factor Authentication (2FA / TOTP)
- OWASP Dependency Check on every PR
- CodeQL static security analysis on every PR
- BCrypt password hashing — passwords never stored in plain text
- Rate limiting and brute-force protection

---

## Architecture

```
src/
├── auth/           # JWT, 2FA, login/logout
├── user/           # User CRUD (Admin)
├── wallet/         # Wallet management
├── transaction/    # Deposits, withdrawals, transfers
├── audit/          # Security audit logs
└── common/         # Shared utilities, exceptions, config

database/
├── 01-extensions   # pgcrypto, uuid-ossp
├── 02-types        # ENUMs (roles, status, currencies)
├── 03-tables       # Core schema
├── 04-index        # Performance indexes
├── 05-triggers     # Auto-audit, balance validation
├── 06-functions    # ACID transaction processor
└── 07-seed         # Development test data
```

---

## Getting Started

### Prerequisites
- Java 17+
- Docker & Docker Compose
- Maven 3.9+

### Run locally

```bash
# 1. Clone the repository
git clone https://github.com/DJAngel973/Secure-Wallet-API.git
cd Secure-Wallet-API

# 2. Copy environment variables
cp .env.example .env
# Edit .env with your local values

# 3. Start PostgreSQL
docker compose up -d

# 4. Run the application
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

---

## Testing

```bash
# Unit tests
./mvnw test

# With coverage report
./mvnw test jacoco:report
```

---

## CI/CD Pipeline

| Job | Trigger | Description |
|-----|---------|-------------|
| Build & Test | Every PR / push | Compile + unit tests |
| OWASP Dependency Check | Every PR / push | CVE scan (fails on CVSS ≥ 7) |
| CodeQL Analysis | Every PR / push | Static security analysis |
| Package JAR | Merge to `main` | Build production artifact |

---

## Project Documentation

| Document | Description |
|----------|-------------|
| [`database/README.md`](database/README.md) | Database schema, ER diagram, and setup guide |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Community standards |

---

## Security Policy

If you discover a vulnerability, please **do not open a public issue**.  
Contact via GitHub private security advisory.

---

## License

[MIT](LICENSE) © 2025 DJAngel973