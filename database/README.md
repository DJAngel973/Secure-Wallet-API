# Database — Secure Wallet API

PostgreSQL 16 schema for a secure digital wallet system.
All scripts run automatically on first Docker startup via `docker-entrypoint-initdb.d`, in numbered order.

---

## File Structure

| File | Order | Description |
|------|-------|-------------|
| `01-extensions.sql` | 1st | PostgreSQL extensions: `pgcrypto`, `uuid-ossp` |
| `02-types.sql` | 2nd | Custom ENUMs: roles, currencies, statuses |
| `03-tables.sql` | 3rd | 6 core tables with constraints |
| `04-index.sql` | 4th | Performance indexes (partial, composite, GIN) |
| `05-triggers.sql` | 5th | Auto-update timestamps, balance validation, audit triggers |
| `06-functions.sql` | 6th | ACID transaction processor, session cleanup |
| `07-seed.sql` | 7th | Development test data only |

---

## Entity Relationship Diagram

```
                          ┌──────────────────────────────────┐
                          │              users                │
                          ├──────────────────────────────────┤
                          │ id UUID PK                        │
                          │ email VARCHAR(255) UNIQUE         │
                          │ password_hash TEXT                │
                          │ role user_role                    │
                          │ is_active BOOLEAN                 │
                          │ failed_login_attempts INT         │
                          │ locked_until TIMESTAMP            │
                          │ email_verified BOOLEAN            │
                          │ two_factor_enabled BOOLEAN        │
                          │ two_factor_secret TEXT            │
                          │ last_login_at TIMESTAMP           │
                          │ created_at / updated_at           │
                          └────┬──────────┬────────┬─────────┘
                               │          │        │
                    CASCADE    │          │        │  SET NULL
              ┌────────────────┘          │        └──────────────────────┐
              │                           │ CASCADE                       │
              ▼                           ▼                               ▼
┌─────────────────────────┐  ┌────────────────────────┐  ┌───────────────────────────┐
│         wallets          │  │      user_sessions      │  │        audit_logs          │
├─────────────────────────┤  ├────────────────────────┤  ├───────────────────────────┤
│ id UUID PK               │  │ id UUID PK              │  │ id UUID PK                 │
│ user_id UUID FK → users  │  │ user_id UUID FK → users │  │ user_id UUID FK → users    │
│ balance DECIMAL(19,4)    │  │ token_hash TEXT UNIQUE  │  │   (nullable, SET NULL)     │
│ currency currency_code   │  │ ip_address INET         │  │ action audit_action        │
│ status wallet_status     │  │ user_agent TEXT         │  │ details JSONB              │
│ created_at / updated_at  │  │ expires_at TIMESTAMP    │  │ ip_address INET            │
│                          │  │ revoked BOOLEAN         │  │ user_agent TEXT            │
│ UNIQUE(user_id,currency) │  │ revoked_at TIMESTAMP    │  │ severity_level log_severity│
└────────┬────────┬────────┘  └────────────────────────┘  │ created_at                 │
         │        │                                         └───────────────────────────┘
RESTRICT │        │ RESTRICT
         ▼        ▼
┌──────────────────────────────────────────────────────┐
│                     transactions                      │
├──────────────────────────────────────────────────────┤
│ id UUID PK                                            │
│ source_wallet_id UUID FK → wallets (nullable)         │
│ target_wallet_id UUID FK → wallets (nullable)         │
│ amount DECIMAL(19,4) CHECK > 0                        │
│ transaction_type transaction_type                     │
│ status transaction_status DEFAULT 'PENDING'           │
│ description TEXT                                      │
│ reference_code VARCHAR(100) UNIQUE                    │
│ fee DECIMAL(19,4)                                     │
│ currency currency_code                                │
│ metadata JSONB  ← IP, device, geolocation             │
│ created_at / completed_at                             │
│                                                       │
│ CHECK: DEPOSIT  → source NULL,  target NOT NULL       │
│ CHECK: WITHDRAWAL → source NOT NULL, target NULL      │
│ CHECK: TRANSFER → source NOT NULL, target NOT NULL    │
└──────────────────────┬───────────────────────────────┘
                       │ CASCADE
                       ▼
         ┌─────────────────────────────────────┐
         │         transaction_history          │
         ├─────────────────────────────────────┤
         │ id UUID PK                           │
         │ transaction_id UUID FK → transactions│
         │ old_status transaction_status        │
         │ new_status transaction_status        │
         │ changed_by UUID FK → users (SET NULL)│
         │ reason TEXT                          │
         │ created_at TIMESTAMP                 │
         │ CHECK old_status ≠ new_status        │
         └─────────────────────────────────────┘
```

---

## Table Relationships Summary

| From | To | Type | Rule |
|------|----|------|------|
| `wallets` | `users` | Many-to-One | `ON DELETE CASCADE` — deleting a user removes all their wallets |
| `transactions` | `wallets` (source) | Many-to-One | `ON DELETE RESTRICT` — cannot delete a wallet with transactions |
| `transactions` | `wallets` (target) | Many-to-One | `ON DELETE RESTRICT` — same protection |
| `transaction_history` | `transactions` | Many-to-One | `ON DELETE CASCADE` — history follows the transaction |
| `transaction_history` | `users` (changed_by) | Many-to-One | `ON DELETE SET NULL` — keeps record even if user is deleted |
| `audit_logs` | `users` | Many-to-One | `ON DELETE SET NULL` — keeps log even if user is deleted |
| `user_sessions` | `users` | Many-to-One | `ON DELETE CASCADE` — deleting a user revokes all sessions |

---

## Security Design Decisions

| Decision | Reason |
|----------|--------|
| `UUID` primary keys | Prevents enumeration attacks (no sequential IDs) |
| `BCrypt` for passwords | Industry standard — never store plain text |
| `DECIMAL(19,4)` for money | Avoids floating-point precision errors in financial calculations |
| `FOR UPDATE` in triggers | Prevents race conditions on concurrent balance reads |
| `ON DELETE RESTRICT` on transactions | Financial records are never deleted |
| `JSONB metadata` on transactions | Stores IP, device, geolocation for fraud detection |
| `INET` type for IP addresses | Native PostgreSQL type — allows range queries |
| `token_hash` (SHA-256) in sessions | JWT tokens never stored in plain text |
| Partial indexes | Improves query performance on active/relevant records only |
| `GIN` index on JSONB | Enables fast search inside JSON audit log details |

---

## ENUMs Reference

### `user_role`
| Value | Description |
|-------|-------------|
| `USER` | Regular client |
| `ADMIN` | Full system access |
| `MANAGER` | Support / audit access |

### `transaction_type`
| Value | Description |
|-------|-------------|
| `DEPOSIT` | External funds added to a wallet |
| `WITHDRAWAL` | Funds removed to an external destination |
| `TRANSFER` | Funds moved between two wallets |

### `transaction_status`
| Value | Description |
|-------|-------------|
| `PENDING` | Created, awaiting processing |
| `PROCESSING` | Being executed (lock held) |
| `COMPLETED` | Successfully finished |
| `FAILED` | Error — automatically rolled back |
| `REVERSED` | Manually reversed after completion |

### `wallet_status`
| Value | Description |
|-------|-------------|
| `ACTIVE` | Operating normally |
| `SUSPENDED` | Temporarily blocked |
| `CLOSED` | Permanently closed |

---

## 🐳 Local Setup

```bash
# Start database only
docker compose up -d

# Start with pgAdmin (UI tool)
docker compose --profile tools up -d

# pgAdmin: http://localhost:5050
# PostgreSQL: localhost:5432
```