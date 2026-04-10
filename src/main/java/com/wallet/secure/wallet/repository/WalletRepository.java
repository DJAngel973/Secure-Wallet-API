package com.wallet.secure.wallet.repository;

import com.wallet.secure.common.enums.CurrencyCode;
import com.wallet.secure.common.enums.WalletStatus;
import com.wallet.secure.wallet.entity.Wallet;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Currency;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Data access layer for wallets
 * CRITICAL - two types of queries here:
 * 1. Regular queries (findBy...) - for READ operations
 * -> No locking, fast, used by WalletService for profile/display
 * 2. Locking queries (@Lock PESSIMISTIC_WRITE) - for WRITE operations
 * -> Used EXCLUSIVELY by TransactionService
 * -> Prevents race conditions on concurrent balance updates
 * -> "SELECT ... FOR UPDATE" in SQL
 * Why pessimistic locking and not optimistic (@Version):
 * Optimistic locking retries on conflict - in financial systems
 * a failed transaction should fail fast, not retry silently.
 * Pessimistic locking blocks the row - only one transaction
 * modifies the balance at a time. Correct for ACID compliance
 * OWASP: prevents TOCTOU (Time-of-Check-Time-of-Use) race conditions.
 */
@Repository
public interface WalletRepository extends JpaRepository<Wallet, UUID> {

    // --- Read Queries - no locking

    /**
     * Finds all wallets belonging to a user
     * Used by WalletService.getMyWallets() - display only
     * OWASP A01: WalletService verifies the requesting user owns these wallets
     */
    List<Wallet> findByUserId(UUID userId);

    /**
     * Finds a specific wallet by user and currency
     * Used to check if a wallet already exists before creating a new one
     * Enforces the business rule: one wallet per currency per user.
     */
    Optional<Wallet> findByUserIdAndCurrency(UUID userId, CurrencyCode currency);

    /**
     * Finds a specific wallet by ID - verifies ownership at the same time
     * Used by WalletService for any operation that needs ownership verification
     * Why combine id + userId in one query instead of two separate calls:
     * findById(id) -> then check wallet.getUser().getId().equals(userId)
     * -> requires loading the User (extra JOIN or lazy load)
     * -> two round trips or N+1 risk
     * findByIdAndUserId(id, userId) -> one query, one round trip
     * -> if returns empty -> either wallet doesn't exist OR doesn't belong to user
     * -> OWASP A01: same response for "not found" and "not yours"
     * (prevents wallet enumeration by other users)
     */
    Optional<Wallet> findByIdAndUserId(UUID id, UUID userId);

    /**
     * Finds all wallets with a specific status
     * Used by admin operations - suspend/close wallet management
     * OWASP A01: only called from admin-protected service methods
     */
    List<Wallet> findByUserIdAndStatus(UUID id, WalletStatus status);

    /**
     * Checks if a wallet already exists for a user+currency combination
     * Used before creation to return a clear error instead of
     * letting the DB UNIQUE constraint throw a cryptic exception
     */
    boolean existsByUserIdAndCurrency(UUID userId, CurrencyCode currency);

    // --- Locking Queries - FOR UPDATE - TRANSACTION USE ONLY

    /**
     * Finds a wallet by ID and acquires a PESSIMISTIC WRITE lock
     * Translates to: SELECT * FROM wallets WHERE id = ? FOR UPDATE
     * ONLY called from TransactionService - never from WalletService
     * Caller MUST be inside a @Transactional method - the lock is
     * released when the transaction commits or rolls back
     * Why FOR UPDATE:
     * Without locking - race condition example
     *    Thread A reads balance = 100
     *    Thread B reads balance = 100 <- same value, B doesn't know about A
     *    Thread A withdraws 80 -> writes 20
     *    Thread B withdraws 80 -> writes 20 <- WRONG: should have failed (100-80=20, not enough for another 80)
     *    Result: balance goes negative <- financial disaster
     * With FOR UPDATE:
     *    Thread A reads balance = 100 -> acquires lock
     *    Thread B tries to read -> BLOCKED, waits for A to finish
     *    Thread A withdraws 80 -> writes 20 -> commits -> releases lock
     *    Thread B reads balance = s20 -> withdrawal of 80 fails -> correct
     * OWASP: prevents race conditions and negative balance exploits
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT w FROM Wallet w WHERE w.id = :id")
    Optional<Wallet> findByIdWithLock(@Param("id") UUID id);

    /**
     * Finds a wallet by owner + currency and acquires a PESSIMISTIC WRITE lock
     * Used for DEPOSIT operations where the target is identified by currency
     * Same locking rules as findByIdWithLock - must be @Transactional
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT w FROM Wallet w WHERE w.user.id = :userId AND w.currency = :currency")
    Optional<Wallet> findByIdAndCurrencyWithLock(
            @Param("userId") UUID userId,
            @Param("currency") CurrencyCode currency);
}