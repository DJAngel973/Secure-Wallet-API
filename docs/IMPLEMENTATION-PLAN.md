# Secure Wallet API — Implementation Plan

This plan records the work required to align the implementation, tests, and documentation with the confirmed architecture of Secure Wallet API. An item listed here is not evidence that the behavior is already implemented.

## Scope and status model

Secure Wallet API is an educational-professional backend for a simulated multi-currency savings wallet. It runs locally through Docker Compose and demonstrates its HTTP flows primarily with Postman. It does not process real money and is not intended for public production deployment.

| Label | Meaning |
|-------|---------|
| **Confirmed requirement** | Approved target behavior that implementation must satisfy |
| **Detected defect** | Current behavior contradicts an approved requirement or security expectation |
| **Pending decision** | Design must be confirmed before implementation |

Priorities:

- **P0 — Security blocker:** resolve before treating the related control as functional.
- **P1 — Core correctness:** required for reliable authorization, transactions, or evidence.
- **P2 — Verification/documentation:** required for repeatable demonstration and accurate claims.
- **P3 — Future design:** intentionally deferred until its requirements are approved.

## Dependency order

```text
Development seed separation
        ↓
First-admin bootstrap
        ↓
Administrative user management

Session storage cleanup
        ↓
Refresh-token rotation
        ↓
Session and JWT functional tests

Account lockout correction
        ↓
JWT account-state enforcement
        ↓
Authentication security tests

Wallet ownership review
        ↓
Transaction/concurrency/audit verification
        ↓
Postman critical-flow collection
```

---

## P0 — Security blockers

### SEC-001 — Separate development seed data from automatic initialization

**Classification:** Detected defect  
**Priority:** P0  
**Depends on:** None

**Current problem**

The former `database/07-seed.sql` created an administrator with publicly known credentials during PostgreSQL initialization. It has been removed from the database initialization directory.

**Expected behavior**

- Remove the seed from the repository's initialization directory; provision administrators through the controlled application bootstrap instead.
- Configure Docker Compose to initialize only the required database schema.
- Do not create default users or administrators during SQL initialization.
- Keep Docker Compose as the primary way to start PostgreSQL and Spring Boot.

**Acceptance criteria**

- [x] No default administrator is created by SQL initialization path (verified with a temporary clean PostgreSQL container).
- [x] No public administrator password remains in the repository's database scripts.
- [x] PostgreSQL initializes correctly using Docker Compose and the current schema scripts.
- [x] Existing tests continue to pass (111 tests, 0 failures, 0 errors; verified 2026-10-20).

### SEC-002 — Add controlled one-time bootstrap for the first administrator

**Classification:** Confirmed requirement  
**Priority:** P0  
**Depends on:** SEC-001

**Current problem**

The former public seed is no longer used and a controlled bootstrap now exists. Runtime verification confirms that it creates only the first administrator, skips creation when an administrator already exists, and fails closed for missing or invalid configuration. The registration audit transaction ordering was corrected and verified against PostgreSQL (see the verification note below).

**Expected behavior**

- The first `ADMIN` is created exactly once through a controlled bootstrap.
- Bootstrap credentials come from an untracked environment or secret input and are never logged.
- Public registration always creates `USER`.
- The bootstrap refuses to create additional administrators after the first valid administrator exists.

**Possibly affected files**

- New bootstrap component under the `auth` or `user` domain
- `UserRepository.java`
- Security configuration properties
- `.env.example`
- Bootstrap unit/integration tests
- Docker environment wiring

**Acceptance criteria**

- [x] First startup with valid bootstrap input creates one BCrypt-hashed `ADMIN`.
- [x] A second startup creates no additional administrator and changes no existing credentials (verified against the Docker PostgreSQL database; count remained one).
- [x] Missing or invalid bootstrap input fails safely without exposing secrets. Both cases stopped startup with the generic message `Admin bootstrap configuration is invalid`; the administrator count remained one.
- [x] Bootstrap secrets are absent from application logs, API responses, tracked configuration and the `.env` Git history path. The secret is supplied only as a runtime environment value; the database stores the BCrypt hash, not the original password.
- [x] `POST /auth/register` cannot create an `ADMIN`, including when the JSON includes a `role` field. A real request with `"role":"ADMIN"` returned `201`, persisted `USER`, created one `USER_REGISTER` audit record and left the administrator count at one.

**Verification note — 2026-10-20**

- `ADMIN_BOOTSTRAP_ENABLED=true` with an existing administrator logged that bootstrap was skipped; the database still contained exactly one `ADMIN`.
- Invalid bootstrap password caused startup to fail with `Admin bootstrap configuration is invalid`, and the database still contained exactly one `ADMIN`; the application was then restored with bootstrap disabled.
- The initial registration test exposed that `AuditService.logRegister()` opened a separate transaction before the enclosing registration transaction committed, violating `audit_logs_user_id_fkey`. The correction makes registration audit join the registration transaction after `UserRepository.flush()`; a repeated real request returned `201`, stored a `USER` and its audit row, and did not add an administrator.

### SEC-003 — Remove original refresh-token storage from the user record

**Classification:** Detected defect  
**Priority:** P0  
**Depends on:** None

**Current problem**

`SessionService` stores a SHA-256 token hash in `user_sessions`, but `AuthService` also assigns the original refresh JWT to `User.refreshToken`. This contradicts the requirement that reusable tokens are not stored directly.

**Expected behavior**

- Only a non-reusable token identifier or approved one-way representation is persisted.
- Refresh validation and revocation use the session model as the single source of truth.
- Database disclosure does not expose a directly reusable refresh token.

**Possibly affected files**

- `AuthService.java`
- `User.java`
- `SessionService.java`
- `SessionRepository.java`
- `database/03-tables.sql`
- `database/08-migrations.sql`
- Authentication/session tests

**Acceptance criteria**

- [ ] No database column stores the original refresh JWT.
- [ ] Login, refresh, logout, single-session revocation, and all-session revocation still work.
- [ ] Tests prove that a stored session value cannot be sent as a refresh token.
- [ ] Schema migration preserves or explicitly invalidates existing sessions safely.

### SEC-004 — Implement and verify refresh-token rotation

**Classification:** Confirmed requirement  
**Priority:** P0  
**Depends on:** SEC-003

**Current problem**

The refresh endpoint issues only a new access token and keeps the same refresh token. Reuse detection and atomic rotation are not implemented.

**Expected behavior**

- Every successful refresh returns a new access token and a new refresh token.
- The previous refresh token is invalidated atomically.
- Reuse of an already-rotated token is rejected and produces an auditable security event.
- Concurrent refresh attempts cannot both succeed with the same token.

**Possibly affected files**

- `AuthService.java`
- `SessionService.java`
- `Session.java`
- `SessionRepository.java`
- `AuthResponse.java`
- Authentication/session tests
- Database indexes or migration if token-family tracking is selected

**Acceptance criteria**

- [ ] A successful refresh returns two new tokens.
- [ ] The previous refresh token fails immediately afterward.
- [ ] Exactly one of two concurrent refresh requests with the same token succeeds.
- [ ] Rotation and reuse failures create audit evidence without logging token values.
- [ ] Logout revokes the current rotated session.

### SEC-005 — Correct failed-login lockout

**Classification:** Detected defect  
**Priority:** P0  
**Depends on:** None

**Current problem**

Failed login events are audited, but the authentication flow does not demonstrably call repository operations that increment attempts and set `lockedUntil`. Values also conflict: application configuration states five attempts while the database constrains the counter to three.

**Expected behavior**

- One authoritative, configurable threshold and lock duration are used.
- Failed attempts are incremented atomically.
- Reaching the threshold locks the account for the configured duration.
- A successful login resets the counter.
- Unknown-email and wrong-password responses remain non-enumerating.

**Possibly affected files**

- `AuthService.java`
- `UserRepository.java`
- `User.java`
- Security configuration properties
- `application.yml`
- `database/03-tables.sql`
- `database/08-migrations.sql`
- `GlobalExceptionHandler.java`
- Authentication tests

**Acceptance criteria**

- [ ] The configured number of consecutive failures locks the account.
- [ ] PostgreSQL accepts every valid counter state under the selected policy.
- [ ] A correct password during the lock period cannot authenticate.
- [ ] Authentication succeeds after expiry according to the chosen unlock policy.
- [ ] Success resets failed attempts to zero.
- [ ] Unit and PostgreSQL-backed tests cover boundary and concurrency cases.

### SEC-006 — Reject JWT authentication for disabled or locked accounts

**Classification:** Detected defect  
**Priority:** P0  
**Depends on:** SEC-005

**Current problem**

Password authentication maps active/locked state into Spring Security. During access-token authentication, however, `JwtAuthFilter` constructs an authenticated token after loading `UserDetails` without explicitly rejecting disabled or locked state.

**Expected behavior**

- Disabled or locked users cannot establish a `SecurityContext`, even with an unexpired access token.
- Account deactivation and administrative suspension revoke relevant refresh sessions.
- Response behavior is consistent and does not expose sensitive account details.

**Possibly affected files**

- `JwtAuthFilter.java`
- `UserDetailsServiceImpl.java`
- `UserService.java`
- `SessionService.java`
- Security integration tests

**Acceptance criteria**

- [ ] An existing access token fails after its user is disabled.
- [ ] An existing access token fails while its user is locked.
- [ ] Disabling an account revokes all refresh sessions.
- [ ] Active, unlocked users continue to authenticate normally.

---

## P1 — Authorization and financial correctness

### AUTHZ-001 — Implement controlled management of regular users

**Classification:** Confirmed requirement  
**Priority:** P1  
**Depends on:** SEC-002, SEC-006

**Current problem**

Administrative read/deactivation operations exist, but there is no consolidated and verified administrative user-management contract. The confirmed model allows an administrator to manage regular users but not create or promote other administrators through the API.

**Expected behavior**

- `ADMIN` can perform explicitly approved management operations on `USER` accounts.
- `USER` cannot invoke administrative operations.
- No public or administrative API operation creates, promotes, or modifies another `ADMIN`.
- Every administrative action is audited with actor and target identifiers.

**Possibly affected files**

- `UserController.java`
- `UserService.java`
- User administration DTOs if approved
- `SecurityConfig.java`
- `AuditService.java`
- Authorization tests

**Acceptance criteria**

- [ ] `USER` receives `403` for every administrative endpoint.
- [ ] `ADMIN` can manage only operations explicitly allowed for regular users.
- [ ] API requests containing privileged role changes are rejected or ignored safely and never persisted.
- [ ] No API route can create or promote another administrator.
- [ ] Administrative actions produce immutable audit records.

### AUTHZ-002 — Review wallet permissions and ownership

**Classification:** Confirmed requirement  
**Priority:** P1  
**Depends on:** AUTHZ-001

**Current problem**

Wallet controllers derive identity from the JWT and services include ownership patterns, but complete endpoint-by-endpoint authorization evidence is missing.

**Expected behavior**

- Users can read and operate only their own wallets.
- Ownership mismatches use non-enumerating responses where appropriate.
- Administrative wallet lifecycle operations require `ADMIN` and are audited.
- Request bodies cannot override the authenticated owner.

**Possibly affected files**

- `WalletController.java`
- `WalletService.java`
- `WalletRepository.java`
- Wallet DTOs
- `SecurityConfig.java`
- Wallet authorization tests

**Acceptance criteria**

- [ ] User A cannot read, debit, close, suspend, or restore User B's wallet.
- [ ] User-controlled input cannot assign a wallet to a different owner.
- [ ] Administrative actions require `ROLE_ADMIN` and generate audit records.
- [ ] Automated tests cover every wallet endpoint with owner, non-owner, anonymous, and admin actors.

### TX-001 — Verify transactions, concurrency, rollback, and audit behavior

**Classification:** Confirmed requirement  
**Priority:** P1  
**Depends on:** AUTHZ-002

**Current problem**

Transaction services use transactional boundaries and pessimistic locking, but unit tests do not prove real PostgreSQL locking, concurrent updates, trigger behavior, or complete rollback/audit semantics.

**Expected behavior**

- Deposits, withdrawals, and transfers preserve financial invariants.
- Concurrent requests cannot lose updates, create negative balances, or double-spend.
- Failed operations leave balances unchanged.
- Ownership, currency, wallet state, and reference-code rules are enforced.
- Success and failure paths create the required audit/history evidence.

**Possibly affected files**

- `TransactionService.java`
- `TransactionRepository.java`
- `WalletRepository.java`
- `TransactionHistoryService.java`
- `AuditService.java`
- Transaction and wallet entities
- Database functions, triggers, and migrations if defects are confirmed
- PostgreSQL integration tests

**Acceptance criteria**

- [ ] Failed withdrawals and transfers leave all balances unchanged.
- [ ] Concurrent withdrawal/transfer tests preserve balance invariants.
- [ ] Duplicate reference codes are rejected deterministically.
- [ ] Users cannot transact from wallets they do not own.
- [ ] Transaction status history and security audit records match the final outcome.
- [ ] PostgreSQL-backed tests demonstrate locking and rollback behavior.

---

## P2 — Verification and delivery evidence

### TEST-001 — Expand automated security and integration tests

**Classification:** Confirmed requirement  
**Priority:** P2  
**Depends on:** SEC-004, SEC-005, SEC-006, AUTHZ-001, AUTHZ-002, TX-001

**Current problem**

The suite primarily proves service logic through Mockito and contains limited Spring Security integration coverage. It does not provide complete evidence for PostgreSQL, JWT lifecycle, role matrices, or financial concurrency.

**Expected behavior**

- Fast unit tests continue to cover business branches.
- Focused security integration tests prove filter-chain and method-authorization behavior.
- PostgreSQL-backed tests prove schema, locking, and transaction behavior.
- Security regression tests map to confirmed requirements.

**Possibly affected files**

- `src/test/java/**`
- `src/test/resources/**`
- `pom.xml` if a PostgreSQL integration-test dependency is approved
- CI workflows if an integration-test job is approved

**Acceptance criteria**

- [ ] Tests cover anonymous `401`, authenticated `USER` `403`, and authorized `ADMIN` success.
- [ ] Tests cover tampered, expired, wrong-type, revoked, and rotated JWTs.
- [ ] Tests cover account lockout and access-token rejection after state changes.
- [ ] Tests cover wallet ownership and transaction rollback/concurrency.
- [ ] CI publishes readable unit and integration test results.

### TEST-002 — Create a functional Postman verification suite

**Classification:** Confirmed requirement  
**Priority:** P2  
**Depends on:** TEST-001

**Current problem**

Postman is the intended local demonstration tool, but no versioned collection currently provides repeatable critical-flow verification.

**Expected behavior**

- A collection and local environment exercise the API in dependency order.
- Tests capture identifiers/tokens safely and assert HTTP status plus response contracts.
- Positive and negative scenarios are both represented.
- No real or reusable credentials are committed.

**Possibly affected files**

- New Postman collection under a documentation/testing directory
- Sanitized Postman environment template
- `README.md`
- API functional-test instructions

**Acceptance criteria**

- [ ] Collection covers register, login, refresh rotation, logout, and revoked-token failure.
- [ ] Collection covers `USER`/`ADMIN` authorization and wallet ownership.
- [ ] Collection covers deposit, withdrawal, transfer, insufficient funds, and history.
- [ ] Collection contains assertions for expected `2xx`, `400`, `401`, `403`, and non-enumerating `404` cases.
- [ ] Exported files contain no tokens, passwords, local paths, or private environment values.

### DOC-001 — Keep security documentation synchronized with evidence

**Classification:** Detected defect  
**Priority:** P2  
**Depends on:** All completed tasks that change documented behavior

**Current problem**

Some documentation currently describes target controls—such as token rotation, lockout, TOTP, and limits—as fully implemented.

**Expected behavior**

- Documentation differentiates implemented, verified, partial, and planned capabilities.
- Architecture decisions remain documented even when implementation work is pending.
- OWASP mapping describes evidence and residual work rather than claiming certification.

**Possibly affected files**

- `README.md`
- `SECURITY.md`
- `CONTEXT.md`
- `DECISIONS.md`
- `database/README.md`

**Acceptance criteria**

- [ ] Every security claim links to implementation or test evidence.
- [ ] Planned controls are not described as active controls.
- [ ] Conflicting documents identify the implementation plan as the current status source.
- [ ] OWASP Top 10:2025 names and ordering match the official release.

---

## P3 — Decisions pending confirmation

### DESIGN-001 — Review TOTP-based two-factor authentication

**Classification:** Pending decision  
**Priority:** P3  
**Depends on:** Stable authentication, session, and administrative provisioning flows

**Current problem**

The model and architecture documents reference TOTP, but enrollment, secret protection, recovery, verification, reauthentication, and administrative policy are not fully designed or implemented.

**Expected behavior if approved**

- A written decision defines which operations require TOTP.
- Enrollment requires identity verification and protected secret handling.
- Recovery and reset flows are abuse-resistant and audited.
- Tests prove bypass resistance and recovery behavior.

**Possibly affected files**

- `DECISIONS.md`
- Authentication entities, DTOs, controllers, and services
- Encryption/key-management configuration
- Audit actions
- Security and functional tests

**Acceptance criteria for the decision phase**

- [ ] Threat model and protected operations are approved.
- [ ] Secret storage and recovery strategy are approved.
- [ ] UX and Postman demonstration flow are documented.
- [ ] Implementation is not started until the decision is accepted.

### DESIGN-002 — Review configurable financial limits

**Classification:** Pending decision  
**Priority:** P3  
**Depends on:** TX-001

**Current problem**

Configuration contains transaction and daily-limit values, but their semantics, currency handling, enforcement point, concurrency behavior, and administrative ownership are not fully defined.

**Expected behavior if approved**

- Limits have an explicit business meaning and currency strategy.
- Enforcement is atomic and cannot be bypassed with concurrent requests.
- Configuration ownership and administrative override rules are documented.
- Limit failures do not change balances and are audited.

**Possibly affected files**

- `DECISIONS.md`
- Transaction configuration properties
- `TransactionService.java`
- Transaction repositories/queries
- Database constraints or aggregation queries if selected
- Transaction tests and Postman collection

**Acceptance criteria for the decision phase**

- [ ] Per-transaction and daily-limit semantics are approved.
- [ ] Multi-currency handling is defined.
- [ ] Concurrency and reset-window behavior are defined.
- [ ] Implementation is not started until the decision is accepted.

---

## Known decision conflicts

These conflicts must be resolved explicitly during implementation rather than silently in documentation:

| Conflict | Current sources | Required resolution |
|----------|-----------------|---------------------|
| Functional roles | PostgreSQL and `UserRole` currently include `MANAGER`; confirmed target business roles are `USER` and `ADMIN` | Decide whether `MANAGER` is removed through migration or retained as a non-functional reserved value |
| Login-attempt threshold | Database allows up to 3; application configuration and security documentation state 5 | Select one policy, migrate schema/configuration, and test it |
| Refresh-token storage | Session model stores SHA-256 hashes; user model stores the original token | Make the session model authoritative and remove legacy storage safely |
| Refresh behavior | Architecture requires rotation; current implementation reuses the refresh token | Define atomic rotation and reuse handling before implementation |
| Email verification | Model/documentation describe verification as required; authentication currently does not consistently enforce it | Confirm whether verification is required for this educational scope |
| Administrative provisioning | Public seed creates an administrator; confirmed architecture requires controlled bootstrap | Separate development data and implement one-time bootstrap |
| TOTP and limits | Architecture documents describe them as controls; current decision marks them pending | Keep them pending until separate design decisions are accepted |

## Definition of project verification

The project should not be described as fully verified until all applicable checks are satisfied:

- [ ] Docker Compose starts a clean local environment without public default administrative credentials.
- [ ] Bootstrap, authentication, authorization, session, wallet, and transaction acceptance criteria pass.
- [ ] Unit, security integration, and PostgreSQL-backed tests pass.
- [ ] The Postman critical-flow collection passes from a clean local environment.
- [ ] README, security documentation, and architecture decisions describe the same behavior.
- [ ] No source, exported collection, logs, or artifacts contain secrets or reusable tokens.
