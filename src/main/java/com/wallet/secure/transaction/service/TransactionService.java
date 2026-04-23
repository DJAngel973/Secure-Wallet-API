package com.wallet.secure.transaction.service;

import com.wallet.secure.audit.service.AuditService;
import com.wallet.secure.common.enums.CurrencyCode;
import com.wallet.secure.common.enums.TransactionStatus;
import com.wallet.secure.common.enums.TransactionType;
import com.wallet.secure.common.exception.ResourceNotFoundException;
import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.common.util.LogSanitizer;
import com.wallet.secure.transaction.dto.DepositRequest;
import com.wallet.secure.transaction.dto.TransactionResponse;
import com.wallet.secure.transaction.dto.TransferRequest;
import com.wallet.secure.transaction.dto.WithdrawRequest;
import com.wallet.secure.transaction.entity.Transaction;
import com.wallet.secure.transaction.repository.TransactionRepository;
import com.wallet.secure.wallet.entity.Wallet;
import com.wallet.secure.wallet.repository.WalletRepository;
import com.wallet.secure.wallet.service.WalletService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.wallet.secure.transaction.service.TransactionHistoryService;
import com.wallet.secure.common.enums.TransactionStatus;

import java.util.UUID;

/**
 * Core financial operations service — ACID compliance is the #1 priority.
 *
 * The 4 ACID properties guaranteed here:
 *
 * A — Atomicity:
 *   @Transactional ensures ALL operations in a method succeed together
 *   or NONE of them persist. If balance deduction succeeds but credit fails,
 *   the entire operation rolls back. No partial money movement.
 *
 * C — Consistency:
 *   Business rules validated BEFORE any DB write:
 *   → wallet must be ACTIVE
 *   → balance must be sufficient
 *   → currencies must match for transfers
 *   → amount must be positive
 *   DB constraints (CHECK balance >= 0) are the final safety net.
 *
 * I — Isolation:
 *   PESSIMISTIC_WRITE locks (FOR UPDATE) via WalletRepository.findByIdWithLock()
 *   ensure concurrent transactions on the same wallet are serialized.
 *   Thread A and Thread B cannot modify the same wallet balance simultaneously.
 *
 * D — Durability:
 *   @Transactional commit writes to PostgreSQL's WAL (Write-Ahead Log).
 *   Data survives server crashes after commit.
 *
 * TRANSACTION LIFECYCLE:
 *   1. Create Transaction record with status=PENDING → save to DB
 *   2. Mark as PROCESSING → prevents duplicate processing
 *   3. Acquire locks on wallets (FOR UPDATE)
 *   4. Validate business rules
 *   5. Move balances
 *   6. Mark as COMPLETED → set completedAt
 *   7. @Transactional commits everything atomically
 *
 *   On ANY exception:
 *   → markAsFailed() on the transaction
 *   → @Transactional rolls back ALL balance changes
 *   → Transaction record remains in DB with FAILED status (audit trail)
 *
 * OWASP A01: userId always from JWT — never from request body.
 * OWASP A09: every financial operation is logged with transaction ID.
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class TransactionService {

    private final TransactionRepository transactionRepository;
    private final WalletRepository walletRepository;
    private final WalletService walletService;
    private final AuditService auditService;
    private final TransactionHistoryService historyService;

    // --- DEPOSIT

    /**
     * Adds external funds into the authenticated user's wallet.
     *
     * DEPOSIT rules:
     * → sourceWallet = NULL  (external money, no source wallet)
     * → targetWallet = NOT NULL (the wallet that receives funds)
     *
     * No locking needed on DEPOSIT:
     * Only one wallet is modified (the target).
     * Concurrent deposits to the same wallet are safe because
     * each @Transactional read-modify-write is atomic at DB level.
     * We still use findByIdWithLock() for consistency with other operations.
     *
     * @param userId  authenticated user's ID (from JWT)
     * @param request DTO with currency and amount
     */
    @Transactional
    public ApiResponse<TransactionResponse> deposit(UUID userId, DepositRequest request) {

        // Validate reference code uniqueness before any DB write
        validateReferenceCode(request.getReferenceCode());

        // Resolve and validate target wallet - must exist, belong to user, be ACTIVE
        Wallet targetWallet = walletService.validateWalletForTransaction(
                walletRepository.findByUserIdAndCurrency(userId, request.getCurrency())
                        .orElseThrow(() -> new ResourceNotFoundException(
                                String.format("You don't have a %s wallet", request.getCurrency())))
                        .getId(),
                userId);

        // Step 1: Create transaction record as PENDING
        Transaction transaction = Transaction.builder()
                .targetWallet(targetWallet)
                .amount(request.getAmount())
                .currency(request.getCurrency())
                .transactionType(TransactionType.DEPOSIT)
                .description(request.getDescription())
                .referenceCode(request.getReferenceCode())
                .build();
        transactionRepository.save(transaction);
        historyService.record(transaction, null, TransactionStatus.PENDING);

        try {
            // Step 2: Mark as PROCESSING - prevents duplicate execution
            transaction.markAsProcessing();
            historyService.record(transaction, TransactionStatus.PENDING, TransactionStatus.PROCESSING);

            // Step 3: Acquire lock on target wallet
            Wallet lockedTarget = walletRepository.findByIdWithLock(targetWallet.getId())
                    .orElseThrow(() -> new ResourceNotFoundException("Wallet not found"));

            // Strep 4: Credit funds
            lockedTarget.setBalance(lockedTarget.getBalance().add(request.getAmount()));
            walletRepository.save(lockedTarget);

            // Step 5: Mark as COMPLETED
            transaction.markAsCompleted();
            transactionRepository.save(transaction);
            historyService.record(transaction, TransactionStatus.PROCESSING, TransactionStatus.COMPLETED);

            auditService.logTransactionSuccess(
                    userId,
                    transaction.getId(),
                    TransactionType.DEPOSIT.name(),
                    request.getAmount().toPlainString(),
                    request.getCurrency().name(),
                    null, null);

            log.info("DEPOSIT completed: txId={} amount={} currency={} userId={}",
                    transaction.getId(),
                    request.getAmount(),
                    request.getCurrency(),
                    LogSanitizer.sanitize(userId.toString()));

            return ApiResponse.ok("Deposit successful", TransactionResponse.fromEntity(transaction));

        } catch (Exception e) {
            // Mark transaction as FAILD - keeps audit trail
            // @Transactional will roll back the balance change
            transaction.markAsFailed();
            transactionRepository.save(transaction);
            historyService.record(transaction, TransactionStatus.PROCESSING, TransactionStatus.FAILED);
            auditService.logTransactionFailure(
                    userId,
                    TransactionType.DEPOSIT.name(),
                    e.getMessage(),
                    null, null);
            log.error("DEPOSIT failed: txId={} reason={}", transaction.getId(), e.getMessage());
            throw e; // rethrow - @Transactional needs the exception to trigger rollback
        }
    }

    // --- WITHDRAWAL

    /**
     * Removes funds from the authenticated user's wallet to external destination.
     *
     * WITHDRAWAL rules:
     * → sourceWallet = NOT NULL (the wallet that loses funds)
     * → targetWallet = NULL  (external destination, no wallet in system)
     *
     * Balance check:
     * sourceWallet.balance >= amount + fee
     * Prevents negative balance — enforced here AND by DB CHECK (balance >= 0).
     *
     * @param userId  authenticated user's ID (from JWT)
     * @param request DTO with currency and amount
     */
    @Transactional
    public ApiResponse<TransactionResponse> withdraw(UUID userId, WithdrawRequest request) {

        validateReferenceCode(request.getReferenceCode());

        // Resolve source wallet by currency
        Wallet sourceWallet = walletService.validateWalletForTransaction(
                walletRepository.findByUserIdAndCurrency(userId, request.getCurrency())
                        .orElseThrow(() -> new ResourceNotFoundException(
                                String.format("You don't have a %s wallet", request.getCurrency())))
                        .getId(),
                userId);

        // Step 1: Create transaction as PENDING
        Transaction transaction = Transaction.builder()
                .sourceWallet(sourceWallet)
                .amount(request.getAmount())
                .currency(request.getCurrency())
                .transactionType(TransactionType.WITHDRAWAL)
                .description(request.getDescription())
                .referenceCode(request.getReferenceCode())
                .build();
        transactionRepository.save(transaction);
        historyService.record(transaction, null, TransactionStatus.PENDING);

        try {
            transaction.markAsProcessing();
            historyService.record(transaction, TransactionStatus.PENDING, TransactionStatus.PROCESSING);

            // Step 3: Acquire lock on source wallet
            Wallet lockedSource = walletRepository.findByIdWithLock(sourceWallet.getId())
                    .orElseThrow(() -> new ResourceNotFoundException("Wallet not found"));

            // Step 4: Validate sufficient balance (amount + fee)
            if (!lockedSource.hasSufficientBalance(transaction.getTotalDebit())) {
                throw new IllegalStateException(
                        String.format("Insufficient balance. Available: %,.2f Required: %,.2f",lockedSource.getBalance(), transaction.getTotalDebit()));
            }

            // Step 5: Debit funds
            lockedSource.setBalance(lockedSource.getBalance().subtract(transaction.getTotalDebit()));
            walletRepository.save(lockedSource);

            transaction.markAsCompleted();
            transactionRepository.save(transaction);
            historyService.record(transaction, TransactionStatus.PROCESSING, TransactionStatus.COMPLETED);

            auditService.logTransactionSuccess(
                    userId,
                    transaction.getId(),
                    TransactionType.WITHDRAWAL.name(),
                    request.getAmount().toPlainString(),
                    request.getCurrency().name(),
                    null, null);

            log.info("WITHDRAWAL completed: txId={} amount={} currency={} userId={}",
                    transaction.getId(),
                    request.getAmount(),
                    request.getCurrency(),
                    LogSanitizer.sanitize(userId.toString()));

            return ApiResponse.ok("Withdrawal successful", TransactionResponse.fromEntity(transaction));

        } catch (Exception e) {
            transaction.markAsFailed();
            transactionRepository.save(transaction);
            historyService.record(transaction, TransactionStatus.PROCESSING, TransactionStatus.FAILED);

            auditService.logTransactionFailure(
                    userId,
                    "WITHDRAWAL",
                    e.getMessage(),
                    null, null);

            log.error("WITHDRAWAL failed: txId={} reason={}", transaction.getId(), e.getMessage());
            throw e;
        }
    }

    // ─── TRANSFER

    /**
     * Moves funds between two wallets inside the system.
     *
     * TRANSFER rules:
     * → sourceWallet = NOT NULL (sender's wallet)
     * → targetWallet = NOT NULL (recipient's wallet)
     * → source != target (DB CHECK: source IS DISTINCT FROM target)
     * → both wallets must share the same currency
     *
     * LOCKING ORDER — prevents deadlocks:
     * Always lock the wallet with the LOWER UUID first.
     * If Thread A locks wallet-1 then wallet-2,
     * and Thread B locks wallet-2 then wallet-1 → DEADLOCK.
     * By always locking in UUID order → both threads lock in
     * the same order → one waits for the other → no deadlock.
     *
     * @param userId  authenticated user's ID — must own sourceWallet
     * @param request DTO with sourceWalletId, targetWalletId, amount
     */
    @Transactional
    public ApiResponse<TransactionResponse> transfer(UUID userId, TransferRequest request) {

        // Validate source != target
        if (request.getSourceWalletId().equals(request.getTargetWalletId())) {
            throw new IllegalStateException("Source and target wallets must be different");
        }

        // Validate source wallet — must belong to authenticated user
        Wallet sourceWallet = walletService.validateWalletForTransaction(
                request.getSourceWalletId(), userId);

        // Validate target wallet — just needs to exist and be ACTIVE
        // (belongs to any user — the recipient)
        Wallet targetWallet = walletRepository.findById(request.getTargetWalletId())
                .orElseThrow(() -> new ResourceNotFoundException("Target wallet not found"));

        if (!targetWallet.isOperational()) {
            throw new IllegalStateException("Target wallet is not available for transactions");
        }

        // Validate same currency — cross-currency transfers not supported
        if (!sourceWallet.getCurrency().equals(targetWallet.getCurrency())) {
            throw new IllegalStateException(
                    String.format("Currency mismatch: source is %s but target is %s",sourceWallet.getCurrency(), targetWallet.getCurrency()));
        }

        // Step 1: Create transaction as PENDING
        Transaction transaction = Transaction.builder()
                .sourceWallet(sourceWallet)
                .targetWallet(targetWallet)
                .amount(request.getAmount())
                .currency(sourceWallet.getCurrency())
                .transactionType(TransactionType.TRANSFER)
                .description(request.getDescription())
                .build();
        transactionRepository.save(transaction);
        historyService.record(transaction, null, TransactionStatus.PENDING);

        try {
            transaction.markAsProcessing();
            historyService.record(transaction, TransactionStatus.PENDING, TransactionStatus.PROCESSING);

            // Step 3: Acquire locks in UUID order — deadlock prevention
            UUID firstLock  = sourceWallet.getId().compareTo(targetWallet.getId()) < 0
                    ? sourceWallet.getId() : targetWallet.getId();
            UUID secondLock = firstLock.equals(sourceWallet.getId())
                    ? targetWallet.getId() : sourceWallet.getId();

            Wallet first  = walletRepository.findByIdWithLock(firstLock)
                    .orElseThrow(() -> new ResourceNotFoundException("Wallet not found"));
            Wallet second = walletRepository.findByIdWithLock(secondLock)
                    .orElseThrow(() -> new ResourceNotFoundException("Wallet not found"));

            // Reassign to semantic names after locking
            Wallet lockedSource = first.getId().equals(sourceWallet.getId()) ? first : second;
            Wallet lockedTarget = first.getId().equals(targetWallet.getId()) ? first : second;

            // Step 4: Validate sufficient balance
            if (!lockedSource.hasSufficientBalance(transaction.getTotalDebit())) {
                throw new IllegalStateException(
                        String.format("Insufficient balance. Available: %,.2f Required: %,.2f",lockedSource.getBalance(), transaction.getTotalDebit()));
            }

            // Step 5: Move funds atomically
            lockedSource.setBalance(lockedSource.getBalance().subtract(transaction.getTotalDebit()));
            lockedTarget.setBalance(lockedTarget.getBalance().add(request.getAmount()));

            walletRepository.save(lockedSource);
            walletRepository.save(lockedTarget);

            transaction.markAsCompleted();
            transactionRepository.save(transaction);
            historyService.record(transaction, TransactionStatus.PROCESSING, TransactionStatus.COMPLETED);

            auditService.logTransactionSuccess(
                    userId,
                    transaction.getId(),
                    TransactionType.TRANSFER.name(),
                    request.getAmount().toPlainString(),
                    sourceWallet.getCurrency().name(),
                    null, null);

            log.info("TRANSFER completed: txId={} amount={} currency={} from={} to={}",
                    transaction.getId(),
                    request.getAmount(),
                    sourceWallet.getCurrency(),
                    LogSanitizer.sanitize(sourceWallet.getId().toString()),
                    LogSanitizer.sanitize(targetWallet.getId().toString()));

            return ApiResponse.ok("Transfer successful", TransactionResponse.fromEntity(transaction));

        } catch (Exception e) {
            transaction.markAsFailed();
            transactionRepository.save(transaction);
            historyService.record(transaction, TransactionStatus.PROCESSING, TransactionStatus.FAILED);

            auditService.logTransactionFailure(
                    userId, TransactionType.TRANSFER.name(), e.getMessage(), null, null);

            log.error("TRANSFER failed: txId={} reason={}", transaction.getId(), e.getMessage());
            throw e;
        }
    }

    // ─── History

    /**
     * Returns paginated transaction history for the authenticated user.
     * OWASP A01: userId from JWT — only their own transactions.
     */
    @Transactional(readOnly = true)
    public ApiResponse<Page<TransactionResponse>> getMyTransactions(UUID userId, Pageable pageable) {
        Page<TransactionResponse> page = transactionRepository
                .findAllByUserId(userId, pageable)
                .map(TransactionResponse::fromEntity);
        return ApiResponse.ok("Transactions retrieved", page);
    }

    /**
     * Returns paginated transaction history for a specific wallet.
     * Verifies wallet ownership before returning data.
     * OWASP A01: findByIdAndUserId ensures wallet belongs to user.
     */
    @Transactional(readOnly = true)
    public ApiResponse<Page<TransactionResponse>> getWalletTransactions(UUID walletId, UUID userId, Pageable pageable) {

        // Verify ownership
        walletService.getMyWallet(walletId, userId);

        Page<TransactionResponse> page = transactionRepository
                .findByWalletId(walletId, pageable)
                .map(TransactionResponse::fromEntity);
        return ApiResponse.ok("Transactions retrieved", page);
    }

    /**
     * Returns a specific transaction by ID.
     * Verifies the user is involved (sender or receiver).
     * OWASP A01: findByIdAndUserId — cannot see other users' transactions.
     */
    @Transactional(readOnly = true)
    public ApiResponse<TransactionResponse> getTransaction(UUID transactionId, UUID userId) {
        Transaction transaction = transactionRepository
                .findByIdAndUserId(transactionId, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Transaction not found"));
        return ApiResponse.ok("Transaction retrieved", TransactionResponse.fromEntity(transaction));
    }

    // ─── Private Helpers

    /**
     * Validates that a reference code is not already used.
     * Called before creating any transaction with an external reference.
     * Provides a clear business error before hitting the DB UNIQUE constraint.
     */
    private void validateReferenceCode(String referenceCode) {
        if (referenceCode != null && transactionRepository.existsByReferenceCode(referenceCode)) {
            throw new IllegalStateException(
                    String.format("Reference code already exists: %s", referenceCode));
        }
    }
}