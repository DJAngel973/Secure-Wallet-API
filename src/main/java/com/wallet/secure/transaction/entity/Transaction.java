package com.wallet.secure.transaction.entity;

import com.wallet.secure.common.enums.CurrencyCode;
import com.wallet.secure.common.enums.TransactionStatus;
import com.wallet.secure.common.enums.TransactionType;
import com.wallet.secure.wallet.entity.Wallet;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * Represents a financial transaction between wallets.
 * Maps to: transactions table
 * Why sourceWallet and targetWallet are nullable:
 * DEPOSIT -> sourceWallet = NULL (money comes from outside)
 *         -> targetWallet = NOT NULL (money goes into a wallet)
 * WITHDRAWAL -> sourceWallet = NOT NULL (money leaves a wallet)
 *            -> targetWallet = NULL (money goes outside)
 * TRANSFER -> sourceWallet = NOT NULL
 *          -> targetWallet = NOT NULL
 * DB enforces this with CHECK constraints
 * TransactionService enforces this at application level.
 * Defense in depth: two layers of validation.
 *
 * FINANCIAL IMMUTABILITY:
 * Transactions are NEVER updated or deleted - only status changes.
 * Money movement is recorded permanently for audit compliance.
 * OWASP A09: complete audit trail of all financial operations.
 */
@Entity
@Table(name = "transactions")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Transaction {

    // --- Identity

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    // --- Wallets Involved

    /**
     * Source wallet - where money leaves from.
     * NULL for DEPOSIT (external money coming in)
     * NOT NULL for WITHDRAWAL and TRANSFER
     *
     * ON DELETE RESTRICT in DB - prevents deleting a wallet
     * that has transaction history. Financial records must be preserved.
     * FetchType.LAZY - wallet data loaded only when explicitly accessed.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "source_wallet_id")
    private Wallet sourceWallet;

    /**
     * Target wallet - where money arrives.
     * NULL for WITHDRAWAL (money going outside)
     * NOT NULL for DEPOSIT and TRANSFER
     *
     * ON DELETE RESTRICT - same as sourceWallet
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "target_wallet_id")
    private Wallet targetWallet;

    // --- Financial Data

    /**
     * Amount - DECIMAL(19, 4) in DB
     * BigDecimal - mandatory for financial precision
     * DB CHECK: amount > 0  (cannot transfer zero or negative amounts)
     * TransactionService also validates amount > 0 before reaching DB
     */
    @Column(name = "amount", nullable = false, precision = 19, scale = 4)
    private BigDecimal amount;

    /**
     * Transaction fee - charged on top of amount.
     * DEFAULT 0 - free transaction in current version
     * Future: fee logic will be added to TransactionService
     * DB CHECK: fee >= 0 (cannot have negative fees)
     */
    @Column(name = "fee", nullable = false, precision = 19, scale = 4)
    @Builder.Default
    private BigDecimal fee = BigDecimal.ZERO;

    /**
     * Currency of this transaction
     * Must match the currency of both wallets involved
     * Cross-currency transactions are NOT supported - validated in service
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "currency", nullable = false, length = 10)
    private CurrencyCode currency;

    // --- Type and Status

    /**
     * TRANSFER, DEPOSIT, or WITHDRAWAL
     * Determines which wallet fields are required (null rules above)
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "transaction_type", nullable = false, length = 20)
    private TransactionType transactionType;

    /**
     * Currency lifecycle status.
     * PENDING -> PROCESSING -> COMPLETED or FAILED
     * COMPLETED -> REVERSED (admin only)
     *
     * Why starts as PENDING and not COMPLETED:
     * Allows detecting interrupted transactions (server crash mid-process)
     * A transaction stuck in PENDING or PROCESSING -> needs manual review.
     * Immediate COMPLETED would hide failed partial operations
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    @Builder.Default
    private TransactionStatus status = TransactionStatus.PENDING;

    // --- Metadata

    /**
     * Human-readable description - optional
     * Example: "Payment for invoice #1234" or "Monthly rent"
     */
    @Column(name = "description")
    private String description;

    /**
     * External reference code — for payment gateway reconciliation.
     * Example: PSE code, PayPal transaction ID.
     * DB constraint: UNIQUE — no duplicate external references.
     * NULL for internal transfers.
     */
    @Column(name = "reference_code", length = 100, unique = true)
    private String referenceCode;

    /**
     * Flexible JSON metadata — IP, device, geolocation.
     * Maps to PostgreSQL JSONB column.
     * OWASP A09: stores request context for fraud detection and audit.
     * Example: {"ip": "192.168.1.1", "device": "Mozilla/5.0..."}
     */
    @Column(name = "metadata", columnDefinition = "jsonb")
    private String metadata;

    // --- Timestamps

    /**
     * When the transaction was created — immutable.
     * Set automatically by AuditingEntityListener.
     */
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * When the transaction reached COMPLETED or FAILED status.
     * NULL while PENDING or PROCESSING.
     * Set explicitly by TransactionService on status change.
     */
    @Column(name = "completed_at")
    private Instant completedAt;

    // --- Business  Methods

    /**
     * Marks transaction as PROCESSING — prevents double execution.
     * Called by TransactionService at the start of processing.
     */
    public void markAsProcessing() {
        this.status = TransactionStatus.PROCESSING;
    }

    /**
     * Marks transaction as COMPLETED — funds have been moved.
     * Sets completedAt timestamp for audit trail.
     */
    public void markAsCompleted() {
        this.status = TransactionStatus.COMPLETED;
        this.completedAt = Instant.now();
    }

    /**
     * Marks transaction as FAILED — funds were NOT moved.
     * Sets completedAt to record when the failure was detected.
     */
    public void markAsFailed() {
        this.status = TransactionStatus.FAILED;
        this.completedAt = Instant.now();
    }

    /**
     * Returns the total cost to the sender: amount + fee.
     * Used by TransactionService to verify sufficient balance
     * before processing WITHDRAWAL or TRANSFER.
     */
    public BigDecimal getTotalDebit() {
        return this.amount.add(this.fee);
    }
}