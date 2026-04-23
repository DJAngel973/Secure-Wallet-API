package com.wallet.secure.transaction.service;

import com.wallet.secure.common.enums.TransactionStatus;
import com.wallet.secure.common.exception.ResourceNotFoundException;
import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.transaction.dto.TransactionHistoryResponse;
import com.wallet.secure.transaction.entity.Transaction;
import com.wallet.secure.transaction.entity.TransactionHistory;
import com.wallet.secure.transaction.repository.TransactionHistoryRepository;
import com.wallet.secure.transaction.repository.TransactionRepository;
import com.wallet.secure.user.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Manages the transaction state history trail.
 *
 * TWO responsibilities:
 *
 * 1. WRITE — record state changes (called by TransactionService)
 *    Every time a transaction changes status:
 *    PENDING → PROCESSING → COMPLETED/FAILED
 *    A new TransactionHistory entry is created.
 *
 * 2. READ — query history (called by TransactionHistoryController)
 *    Users see their own transaction timeline.
 *    Admins see full history including wallet-level audit.
 *
 * WHY a separate service and not inline in TransactionService:
 * TransactionService is already large (deposit, withdraw, transfer).
 * History recording is a cross-cutting concern — it happens in ALL operations.
 * Extracting it keeps TransactionService focused on financial logic.
 * Single Responsibility: TransactionService moves money,
 *                        TransactionHistoryService records the trail.
 *
 * OWASP A09: history entries are NEVER updated or deleted.
 * They are append-only — each INSERT is a permanent forensic record.
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class TransactionHistoryService {

    private final TransactionHistoryRepository historyRepository;
    private final TransactionRepository transactionRepository;

    // ─── Write Operations (called by TransactionService)

    /**
     * Records an automatic (system-initiated) status change.
     * Called by TransactionService at each lifecycle step.
     *
     * Usage in TransactionService:
     *   historyService.record(transaction, null, PENDING)              // creation
     *   historyService.record(transaction, PENDING, PROCESSING)        // started
     *   historyService.record(transaction, PROCESSING, COMPLETED)      // success
     *   historyService.record(transaction, PROCESSING, FAILED)         // failure
     *
     * @param transaction the transaction changing state
     * @param oldStatus   previous status (null for initial PENDING)
     * @param newStatus   new status after the change
     */
    @Transactional
    public void record(Transaction transaction,
                       TransactionStatus oldStatus,
                       TransactionStatus newStatus) {

        TransactionHistory entry = TransactionHistory.system(transaction, oldStatus, newStatus);
        historyRepository.save(entry);

        log.debug("History recorded: txId={} {} → {}",
                transaction.getId(), oldStatus, newStatus);
    }

    /**
     * Records a manual (human-initiated) status change.
     * Called when an admin reverses or cancels a transaction.
     *
     * @param transaction the transaction changing state
     * @param oldStatus   previous status
     * @param newStatus   new status
     * @param changedBy   the user making the change
     * @param reason      mandatory explanation for the change
     */
    @Transactional
    public void recordManual(Transaction transaction,
                             TransactionStatus oldStatus,
                             TransactionStatus newStatus,
                             User changedBy,
                             String reason) {

        TransactionHistory entry = TransactionHistory.manual(
                transaction, oldStatus, newStatus, changedBy, reason);
        historyRepository.save(entry);

        log.info("Manual history recorded: txId={} {} → {} by userId={} reason={}",
                transaction.getId(), oldStatus, newStatus, changedBy.getId(), reason);
    }

    // ─── Read Operations (called by TransactionHistoryController)

    /**
     * Returns the complete chronological state timeline for a transaction.
     * Verifies the requesting user owns the transaction before returning.
     *
     * OWASP A01: users can only see history of their OWN transactions.
     * findByIdAndUserId ensures ownership — same pattern as TransactionService.
     *
     * @param transactionId UUID of the transaction
     * @param userId        authenticated user's ID (from JWT)
     */
    @Transactional(readOnly = true)
    public ApiResponse<List<TransactionHistoryResponse>> getTransactionTimeline(
            UUID transactionId, UUID userId) {

        // Ownership check — user must be sender or receiver of this transaction
        transactionRepository.findByIdAndUserId(transactionId, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Transaction not found"));

        List<TransactionHistoryResponse> timeline = historyRepository
                .findByTransactionIdOrderByCreatedAtAsc(transactionId)
                .stream()
                .map(TransactionHistoryResponse::fromEntity)
                .toList();

        return ApiResponse.ok("Transaction timeline retrieved", timeline);
    }

    /**
     * Returns the complete state timeline for a transaction — ADMIN only.
     * No ownership check — admin can see any transaction's history.
     *
     * @param transactionId UUID of the transaction
     */
    @Transactional(readOnly = true)
    public ApiResponse<List<TransactionHistoryResponse>> getTransactionTimelineAdmin(
            UUID transactionId) {

        // Verify the transaction exists
        transactionRepository.findById(transactionId)
                .orElseThrow(() -> new ResourceNotFoundException("Transaction not found"));

        List<TransactionHistoryResponse> timeline = historyRepository
                .findByTransactionIdOrderByCreatedAtAsc(transactionId)
                .stream()
                .map(TransactionHistoryResponse::fromEntity)
                .toList();

        return ApiResponse.ok("Transaction timeline retrieved", timeline);
    }

    /**
     * Returns full history for all transactions through a specific wallet.
     * ADMIN only — used for wallet-level forensic investigation.
     *
     * Use case: "Show me every state change for every transaction
     *            that touched wallet X"
     *
     * @param walletId UUID of the wallet to audit
     */
    @Transactional(readOnly = true)
    public ApiResponse<List<TransactionHistoryResponse>> getWalletHistory(UUID walletId) {

        List<TransactionHistoryResponse> history = historyRepository
                .findByWalletId(walletId)
                .stream()
                .map(TransactionHistoryResponse::fromEntity)
                .toList();

        return ApiResponse.ok("Wallet transaction history retrieved", history);
    }
}