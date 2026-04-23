package com.wallet.secure.transaction.repository;

import com.wallet.secure.common.enums.TransactionStatus;
import com.wallet.secure.transaction.entity.TransactionHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/**
 * Data access for transaction state history.
 *
 * All queries return ordered by createdAt ASC — chronological timeline.
 * This makes it easy to reconstruct "what happened to this transaction"
 * in the order it happened.
 */
@Repository
public interface TransactionHistoryRepository extends JpaRepository<TransactionHistory, UUID> {

    /**
     * Returns the complete state timeline for a transaction.
     * Ordered ASC — first entry is always PENDING (the creation).
     *
     * Use case: "Show me every state change for transaction X"
     * Example result:
     *   null       → PENDING     (14:01:00) ← creation
     *   PENDING    → PROCESSING  (14:01:02) ← execution started
     *   PROCESSING → COMPLETED   (14:01:03) ← success
     */
    List<TransactionHistory> findByTransactionIdOrderByCreatedAtAsc(UUID transactionId);

    /**
     * Returns all FAILED transitions — useful for failure analysis.
     * "How many transactions failed today and why?"
     * Used by admin dashboard for monitoring.
     */
    @Query("SELECT th FROM TransactionHistory th WHERE th.transaction.id = :transactionId AND th.newStatus = :status ORDER BY th.createdAt ASC")
    List<TransactionHistory> findByTransactionIdAndNewStatus(
            @Param("transactionId") UUID transactionId,
            @Param("status") TransactionStatus status);

    /**
     * Returns the full history for all transactions of a wallet.
     * Used by admin for wallet-level audit.
     * "Show me all state changes for all transactions through wallet X"
     *
     * Why join through transaction and then wallet:
     * transaction_history has no direct wallet FK.
     * We navigate: history → transaction → source/target wallet.
     */
    @Query("SELECT th FROM TransactionHistory th WHERE th.transaction.sourceWallet.id = :walletId OR th.transaction.targetWallet.id = :walletId ORDER BY th.createdAt DESC")
    List<TransactionHistory> findByWalletId(@Param("walletId") UUID walletId);

    /**
     * Checks if a transaction has already been processed (has non-PENDING history).
     * Used as a safety check before reprocessing a transaction.
     * Prevents double-execution of financial operations.
     */
    @Query("SELECT COUNT(th) > 0 FROM TransactionHistory th WHERE th.transaction.id = :transactionId AND th.newStatus != com.wallet.secure.common.enums.TransactionStatus.PENDING")
    boolean hasBeenProcessed(@Param("transactionId") UUID transactionId);
}