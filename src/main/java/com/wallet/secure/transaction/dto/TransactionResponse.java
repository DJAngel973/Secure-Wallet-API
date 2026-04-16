package com.wallet.secure.transaction.dto;

import com.wallet.secure.common.enums.CurrencyCode;
import com.wallet.secure.common.enums.TransactionStatus;
import com.wallet.secure.common.enums.TransactionType;
import com.wallet.secure.transaction.entity.Transaction;
import lombok.Builder;
import lombok.Getter;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * DTO returned for all transaction read operations.
 *
 * OWASP A02 — what is intentionally NOT exposed:
 * - sourceWallet / targetWallet full objects → would expose other users' data
 * - metadata (JSONB) → contains IP and device info — internal audit only
 * - fee breakdown details → internal pricing logic
 *
 * What IS exposed and why:
 * - sourceWalletId / targetWalletId → client needs to know which wallets
 *   were involved (can be null for DEPOSIT/WITHDRAWAL)
 * - amount, currency, status → core transaction data the client needs
 * - transactionType ��� client needs to know if it was a deposit/transfer/etc
 * - referenceCode → useful for client reconciliation with external systems
 * - createdAt / completedAt → when it happened
 */
@Getter
@Builder
public class TransactionResponse {

    private final UUID id;

    /**
     * Source wallet UUID - null for DEPOSIT.
     * Client can cross-reference with GET /wallets to see which wallet
     */
    private final UUID sourceWalletId;

    /**
     * Target wallet UUID - null for WITHDRAWAL
     */
    private final UUID targetWalletId;

    private final BigDecimal amount;
    private final BigDecimal fee;
    private final CurrencyCode currency;
    private final TransactionType transactionType;
    private final TransactionStatus status;
    private final String description;
    private final String referenceCode;
    private final Instant createdAt;

    /**
     * Null while PENDING or PROCESSING
     * Set when status reaches COMPLETED or FAILED
     */
    private final Instant completedAt;

    /**
     * Static factory — converts Transaction entity to TransactionResponse.
     * Extracts only the wallet IDs — never the full Wallet objects.
     * OWASP A02: no sensitive wallet or user data leaked through this DTO.
     */
    public static TransactionResponse fromEntity(Transaction transaction) {

        return TransactionResponse.builder()
                .id(transaction.getId())
                .sourceWalletId(
                        transaction.getSourceWallet() != null
                            ? transaction.getSourceWallet().getId() : null)
                .targetWalletId(
                        transaction.getTargetWallet() != null
                            ? transaction.getTargetWallet().getId() : null)
                .amount(transaction.getAmount())
                .fee(transaction.getFee())
                .currency(transaction.getCurrency())
                .transactionType(transaction.getTransactionType())
                .status(transaction.getStatus())
                .description(transaction.getDescription())
                .referenceCode(transaction.getReferenceCode())
                .createdAt(transaction.getCreatedAt())
                .completedAt(transaction.getCompletedAt())
                .build();
    }
}