# AGENTS.md — Secure Wallet API

> This file is the single source of truth for any AI agent working on this project.
> Read it completely before generating, modifying, or reviewing any code.

---

## What This Project Is

A production-grade REST API for a digital wallet.
Academic/portfolio focus — security and traceability are first-class concerns.

**Core priorities (in order):**
1. Security — OWASP Top 10 (2025) compliance throughout
2. Correctness — ACID financial transactions, no money lost
3. Auditability — every sensitive operation logged
4. Maintainability — clean, documented, testable code

---

## Technology Stack

| Component   | Technology                  | Version       |
|-------------|-----------------------------|---------------|
| Framework   | Spring Boot                 | 3.4.2         |
| Language    | Java                        | 17            |
| Security    | Spring Security + JWT       | jjwt 0.12.6   |
| Database    | PostgreSQL                  | 16            |
| ORM         | Spring Data JPA / Hibernate | —             |
| Logging     | Log4j2                      | 2.25.3        |
| Validation  | Spring Bean Validation      | —             |
| Boilerplate | Lombok                      | 1.18.36       |
| Docs        | SpringDoc OpenAPI           | 2.8.8         |
| Tests       | JUnit 5 + Mockito           | —             |
| CI/CD       | GitHub Actions + CodeQL     | —             |

---

## Project Structure — Domain-Driven

```
com.wallet.secure/
├── config/       # SecurityConfig, OpenApiConfig, AuditConfig
├── auth/         # Authentication: AuthService, JwtService, SessionService
│   ├── controller, dto, entity, repository, security, service
├── user/         # Users and profiles
├── wallet/       # Wallets and balances
├── transaction/  # Transactions + TransactionHistory (business core)
├── audit/        # AuditService, AuditLog — security event trail
└── common/       # ApiResponse<T>, exceptions, enums, validators
```

**Rule: NEVER create root-level folders by type.**
Each domain contains its own controller/, dto/, entity/, repository/, service/.

---

## Architecture Rules — ALWAYS Follow

### 1. API Responses
Every endpoint returns `ApiResponse<T>` from `common/response/`:
```java
return ResponseEntity.ok(ApiResponse.ok("Message", data));
return ResponseEntity.ok(ApiResponse.error("Message"));
```
Never return raw objects or entities directly.

### 2. Database
- `ddl-auto: validate` — Hibernate NEVER creates or modifies tables
- Schema is managed exclusively via SQL scripts in `/database/`
- Before adding any entity field, add the column to the SQL script first
- Migrations go in `database/08-migrations.sql`

### 3. Security — userId Always From JWT
```java
// CORRECT — identity from trusted JWT:
@AuthenticationPrincipal UserDetails userDetails
UUID userId = resolveUserId(userDetails.getUsername());

// WRONG — never trust userId from request body or path for ownership:
@RequestBody SomeRequest request  // where request contains userId
```

### 4. Transactions
Financial operations MUST be `@Transactional`:
```java
@Transactional
public ApiResponse<TransactionResponse> deposit(...) { ... }
```
Pessimistic locking for balance updates: `walletRepository.findByIdWithLock(id)`

### 5. OWASP Comments
Every security decision must reference OWASP:
```java
// OWASP A07: brute force detection — 5 failures in 15 min → CRITICAL alert
// OWASP A01: userId from JWT — user cannot access another user's data
// OWASP A02: SHA-256 for token hashing — BCrypt unnecessary for random tokens
```

---

## Code Conventions

### Naming
- Entities: singular PascalCase → `User`, `Wallet`, `Transaction`
- Request DTOs: `[Action]Request` → `LoginRequest`, `DepositRequest`
- Response DTOs: `[Entity]Response` → `UserResponse`, `WalletResponse`
- Services: `[Domain]Service` → `AuthService`, `TransactionHistoryService`

### Comments
Document the **WHY**, not the what:
```java
// WHY @Async: audit writes must never slow down a financial transaction
// WHY Propagation.REQUIRES_NEW: failure audit must survive parent transaction rollback
```

### Lombok
Use `@Getter`, `@Builder`, `@RequiredArgsConstructor`, `@NoArgsConstructor`, `@AllArgsConstructor`.
Never use `@Data` on entities — too broad, causes issues with JPA proxies.

---

## Testing Rules — CRITICAL

### Pattern: Unit tests only (no Spring context)
```java
@ExtendWith(MockitoExtension.class)  // ← always this, never @SpringBootTest
class SomeServiceTest {
    @Mock private SomeDependency dep;
    @InjectMocks private SomeService service;
}
```

### Reference implementations
Before writing any test, read these existing tests as reference:
- `AuditServiceTest.java` → how to test a service with `ArgumentCaptor`
- `AuthServiceTest.java` → how to mock `HttpServletRequest`
- `TransactionServiceTest.java` → how to test financial operations with `@Nested`

### Test structure
```java
@Test
@DisplayName("action_condition_expectedResult")
void methodName_condition_expectation() {
    // GIVEN
    // WHEN
    // THEN
}
```

### What to always test
- Happy path ✅
- Failure path (insufficient balance, not found, unauthorized) ✅
- Balance unchanged after failed operation (ACID) ✅
- Exception type AND message ✅
- `assertThatNoException()` for fire-and-forget operations ✅

### What NOT to test
- `@Async` behavior → requires Spring context
- `@Transactional` behavior → requires Spring context
- Hibernate queries → requires DB

---

## Security Rules — NEVER Violate

1. Never `ddl-auto: create` or `update` in any environment
2. Stack traces never reach the client — `GlobalExceptionHandler` handles all
3. Passwords never logged, never returned in any response
4. JWT secret always from environment variable `JWT_SECRET`
5. Financial operations always inside `@Transactional`
6. Every sensitive operation generates an `audit_logs` entry via `AuditService`
7. Input validation required on ALL endpoints (`@Valid` in controller)
8. `userId` always from JWT — never from request body for ownership checks
9. SHA-256 for token hashing (not BCrypt — tokens are random, not passwords)
10. Raw tokens never stored in DB — only their SHA-256 hash

---

## Existing Security Patterns — Reuse Them

### Audit on every sensitive operation
```java
// Called after any auth event, wallet change, or transaction:
auditService.logLoginSuccess(userId, email, ip, userAgent);
auditService.logTransactionSuccess(userId, txId, type, amount, currency, ip, ua);
auditService.logWalletCreated(userId, walletId, currency, ip, ua);
```

### IP + UserAgent extraction
```java
// Already implemented in AuthService — copy this pattern:
private String extractIp(HttpServletRequest request) { ... }
private String extractUserAgent(HttpServletRequest request) { ... }
```

### Session validation on refresh
```java
// AuthService.refresh() — dual validation pattern:
if (!refreshToken.equals(user.getRefreshToken())) { throw ... }  // legacy
sessionService.validateSession(refreshToken);                     // new
```

### Ownership check pattern
```java
// User can only access their own resources:
transactionRepository.findByIdAndUserId(id, userId)
    .orElseThrow(() -> new ResourceNotFoundException("Not found"));
// Returns 404 (not 403) — prevents resource enumeration (OWASP A01)
```

---

## Domain Summary — What Exists

| Domain      | Entity                | Key Service                  | Status    |
|-------------|----------------------|------------------------------|-----------|
| auth        | —                    | AuthService, SessionService  | ✅ Complete |
| user        | User                 | UserService                  | ✅ Complete |
| wallet      | Wallet               | WalletService                | ✅ Complete |
| transaction | Transaction          | TransactionService           | ✅ Complete |
| history     | TransactionHistory   | TransactionHistoryService    | ✅ Complete |
| audit       | AuditLog             | AuditService                 | ✅ Complete |
| sessions    | Session              | SessionService               | ✅ Complete |
| docs        | —                    | OpenApiConfig                | ✅ Complete |

---

## Branching Strategy

```
main          ← Production. Protected. Merge via PR only.
feature/*     ← New features: feature/descriptive-name
fix/*         ← Bug fixes: fix/bug-name
```

**Commit format (Conventional Commits):**
```
feat(domain): short description
fix(domain): short description
test(domain): short description
docs: short description
refactor(domain): short description
```

---

## Pull Request Checklist

Before opening a PR, verify:
- [ ] Unit tests for all new business logic
- [ ] No hardcoded secrets — environment variables only
- [ ] All exceptions handled via `GlobalExceptionHandler`
- [ ] `@Valid` on all controller endpoints
- [ ] `AuditService` called for sensitive operations
- [ ] `@Transactional` on financial operations
- [ ] OWASP comments on security decisions
- [ ] `@Schema` on new DTOs for Swagger
- [ ] `@Tag` on new controllers for Swagger grouping

## Git Safety Rules
- Do not create commits unless the user explicitly authorizes the commit in the current message.
- Do not run `git push`, `git merge`, rebase, revert, cherry-pick, or create pull requests unless explicitly.
- Reading git history, status, and diffs is allowed.
- Before any Git write operation, explain the exact command and wait for confirmation.
