# TEST-002: Postman regression verification

This collection is an ordered, repeatable **local** API check. It does not create an administrator or require public ADMIN credentials. The collection and environment template are `postman/wallet.postman_collection.json` and `postman/wallet.local.postman_environment.json`.

## Quick run

1. Start PostgreSQL and the API with Docker Compose; confirm the API is reachable at `baseUrl`.
2. Import both JSON files into Postman. Select the imported **Secure Wallet Local (template)** environment.
3. Set `demoPassword` **locally** to a fictitious password (12–72 characters, upper/lowercase letters, a digit, and a symbol). Keep it as a Postman secret. Change `baseUrl` if your local port differs.
4. Run **Secure Wallet TEST-002 regression** in **Collection Runner**, with every request enabled and in order. Do not run individual middle steps against stale variables.
5. Review the Runner summary: all 29 requests and their assertions should pass. A failure means a mismatch to investigate, **not** permission to mark TEST-002 complete.

The first request creates unique Alice and Bob addresses under `example.test` for each run. Subsequent logins obtain fresh access and refresh tokens; scripts keep IDs and tokens in the selected local environment. A unique deposit reference avoids rerun collisions. Do not export the populated environment, publish Runner reports containing request bodies/headers, or print credentials or tokens. The versioned environment template contains no credentials or usable tokens.

## Why this is regression testing

Regression tests rerun previously expected behavior after changes, so an authorization, balance, or session fix does not silently break another flow. In this API, the collection checks the full HTTP path, while JUnit/Mockito tests isolate service behavior and PostgreSQL/Testcontainers tests prove database boundaries such as locking and rollback.

Manual Postman testing lets a person inspect a specific response and capture evidence; Collection Runner executes the same requests and assertions in order, making failures repeatable. **Passing the collection does not replace unit or integration tests**, prove all concurrency cases, establish production security, or implement the documented but absent 30-minute JWT inactivity policy.

## Coverage and expected results

| Flow | Expected evidence |
|---|---|
| Register, login, create/read wallet | 201, 200, 201/200; new USD wallet starts at zero |
| Deposit 100, withdraw 20, insufficient withdraw 81 | 201, 201, 409; Alice's balance is 100, then 80, then unchanged |
| Register/login Bob, create USD wallet, transfer 10 | Bob starts at zero; 201 transfer; Alice 70, Bob 10 |
| General and wallet transaction history | 200 with completed operation IDs |
| Anonymous, USER-on-ADMIN, other user's wallet | 401, 403, 404; the other-user 404 matches an unknown-wallet 404 |
| Invalid deposit amount | 400; Alice's balance stays 70 |
| Refresh rotation, reused token, logout, revoked refresh | 200, 401, 200, 401 |

The anonymous 401 is asserted by status only: Spring Security may return an empty or non-JSON body. Other cases assert the API JSON contract. The 409 is intentional: insufficient funds are a business conflict, not a malformed request. Balance checks assume this collection's unique wallets are not modified concurrently by another client. An access JWT lasts 15 minutes; if a run is paused too long, restart from the beginning rather than reuse expired tokens.

No ADMIN-success test is included because this suite must not depend on a published or pre-existing administrator. Administrative success is covered separately by `SecurityConfigTest` with `@WithMockUser(roles = "ADMIN")`; this is not equivalent to a live ADMIN login.

## Interpreting failures

- **HTTP assertion failed:** compare the actual status with the expected contract. A 401 in the middle often indicates an expired or missing access token; restart the run.
- **Balance or ID assertion failed:** stop and inspect the *first* failed request. Later failures are usually consequences of that failure.
- **Registration failed:** verify the local password policy and that a fresh run was started. The generated addresses are intentionally unique.
- **Runner passes:** record the date, local environment, request/assertion counts, and any sanitized screenshots. Do not claim a pass before an actual Runner execution.

## Recorded local result

On 2026-11-18, the user reported that Collection Runner passed all 29 requests
and 89/89 assertions after the API container was rebuilt with the transaction
history query fix. This is user-reported local evidence, not an agent-executed
Postman run. The earlier 88/89 run correctly detected a backend defect; the
history assertion was not weakened.

The manual screenshots in `docs/images/` are separate evidence and must remain redacted; they do not by themselves prove that this collection passes. Do not export a populated environment after a run.
