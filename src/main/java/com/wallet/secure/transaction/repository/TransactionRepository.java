package com.wallet.secure.transaction.repository;

import com.wallet.secure.common.enums.TransactionStatus;
import com.wallet.secure.common.enums.TransactionType;
import com.wallet.secure.transaction.entity.Transaction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Data access layer for transactions.
 *
 * CRITICAL DESIGN RULE:
 * Transactions are NEVER deleted - only status changes.
 * There is intentionally NO deleteById() usage - inherited from JpaRepository but NEVER called in this project.
 *
 * Why Pageable on history queries:
 * A user can have thousands of transactions.
 * Loading all of them at once -> OutOfMemoryError in production.
 * Pageable = DB-level pagination -> SELECT ... LIMIT x OFFSET y
 * The client requests pages: GET /transactions?page=0&size=20
 *
 * OWASP A01: every query that returns user data filters by userId
 * or walletId ownership - users can only see their own transactions.
 */
@Repository
public interface TransactionRepository extends JpaRepository<Transaction, UUID> {

    // --- History Queries - paginated

    /**
     * Returns all transactions where the user is sender OR receiver.
     * Paginated - never load all transactions at once.
     *
     * Why JPQL and not findBy...:
     * The condition "source OR target" cannot be expressed with
     * Spring Data method naming - requires explicit JPQL query.
     * OWASP A01: filters by wallet ownership via userId check in service.
     * This query is only called after WalletService.validateWalletForTransaction()
     * confirms the wallet belongs to the requesting user
     */
    @Query("""
            SELECT t FROM Transaction t
            WHERE t.sourceWallet.id = :walletId
                OR t.targetWallet.id = :walletId
            ORDER BY t.createdAt DESC
            """)
    Page<Transaction> findByWalletId(@Param("walletId") UUID walletId, Pageable pageable);

    /**
     * Returns all transactions for a user across all their wallets.
     * Joins through the wallet -> user relationship.
     * Used by: GET /transactions/me - full transaction history
     * OWASP A01: userId from JWT - user can only see their own history.
     */
    @Query("""
            SELECT t FROM Transaction t
            WHERE t.sourceWallet.user.id = :userId
                OR t.targetWallet.user.id = :userId
            ORDER BY t.createdAt DESC
            """)
    Page<Transaction> findAllByUserId(@Param("userId") UUID userId, Pageable pageable);

    /**
     * Returns transaction filtered by type for a specific wallet.
     * User by: GET /transactions?type=DEPOSIT for filtered history
     */
    @Query("""
            SELECT t FROM Transaction t
            WHERE (t.sourceWallet.id = :walletId
                OR t.targetWallet.id = :walletId)
                AND t.transactionType = :type
            ORDER BY t.createdAt DESC
            """)
    Page<Transaction> findByWalletIdAndType(@Param("walletId") UUID walletId, @Param("type") TransactionType type, Pageable pageable);

    /**
     * Returns transactions filtered by status for a specific wallet.
     * Used by admin monitoring: find all FAILED transactions.
     */
    @Query("""
            SELECT t FROM Transaction t
            WHERE (t.sourceWallet.id = :walletId
                OR t.targetWallet.id = :walletId)
                AND t.status = :status
            ORDER BY t.createdAt DESC
            """)
    Page<Transaction> findByWalletIdAndStatus(@Param("walletId") UUID walletId, @Param("status") TransactionStatus status, Pageable pageable);

    /**
     * Returns transactions within a date range for a wallet.
     * Used by: GET /transactions?from=2026-01-01&to=2026-03-31
     * Useful for monthly statements and audit reports
     */
    @Query("""
            SELECT t FROM Transaction t
            WHERE (t.sourceWallet.id = :walletId
                OR t.targetWallet.id = :walletId)
                AND t.createdAt BETWEEN = :from AND :to
            ORDER BY t.createdAt DESC
            """)
    Page<Transaction> findByWalletIdAndDataRange(@Param("walletId") UUID walletId, @Param("from") Instant from, @Param("to") Instant to, Pageable pageable);

    // --- Single Transaction Lookup

    /**
     * Finds a transaction by ID - verifies the requesting user
     * is involved (as sender or receiver)
     *
     * Why verify ownership here and not just findById():
     * findById(id) -> any authenticated user could see any transaction
     * by guessing UUIDs (unlikely but possible).
     * This query adds userId ownership check at DB level.
     * OWASP A01: a user can only see transactions where they
     * are the sender or receiver - not all transactions in the system.
     */
    @Query("""
            SELECT t FROM Transaction t
            WHERE t.id = :transactionId
                AND (t.sourceWallet.user.id = :userId
                OR t.targetWallet.user.id = :userId)
            """)
    Optional<Transaction> findByIdAndUserId(@Param("transactionId") UUID transactionId, @Param("userId") UUID userId);

    // --- Admin Queries

    /**
     * Returns all transactions with a specific status - ADMIN only.
     * Used to monitor PENDING/PROCESSING stuck transactions.
     * A transaction stuck in PROCESSING > 5 min -> needs investigation
     */
    List<Transaction> findByStatus(TransactionStatus status);

    /**
     * Checks if a reference code already exists - prevents duplicates.
     * Called before saving a transaction with an external reference.
     * DB also enforces UNIQUE on reference_code - this gives a
     * clear error message before hitting the DB constraint.
     */
    boolean existsByReferenceCode(String referenceCode);
}