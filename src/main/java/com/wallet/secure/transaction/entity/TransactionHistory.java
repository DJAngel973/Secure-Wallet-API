package com.wallet.secure.transaction.entity;

import com.wallet.secure.common.enums.TransactionStatus;
import com.wallet.secure.user.entity.User;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

/**
 * Records every status change in a transaction's lifecycle.
 *
 * Maps to: transaction_history table
 *
 * Why this table exists alongside audit_logs:
 *
 * audit_logs          → WHO did WHAT in the system (security events)
 *                       "user X tried to login", "wallet Y was suspended"
 *
 * transaction_history → HOW a transaction moved through states (financial trail)
 *                       "transaction Z went PENDING → PROCESSING → COMPLETED"
 *
 * They serve different purposes:
 * audit_logs      → security forensics, OWASP A09
 * transaction_history → financial compliance, PCI-DSS, dispute resolution
 *
 * REAL EXAMPLE — dispute resolution:
 * Customer: "I never authorized this transfer"
 * Support: queries transaction_history for transaction UUID
 * Response: "Transaction was PENDING at 14:01, PROCESSING at 14:01:02,
 *            COMPLETED at 14:01:03 — initiated from IP 192.168.1.100"
 *
 * DB CONSTRAINTS verified:
 * CHECK (old_status IS DISTINCT FROM new_status) → no redundant entries
 * ON DELETE CASCADE → if transaction deleted, history goes with it
 *
 * OWASP A09: immutable financial trail — never updated, only inserted.
 */
@Entity
@Table(name = "transaction_history")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransactionHistory {

    // ─── Identity

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    // ─── Relationship

    /**
     * The transaction this history entry belongs to.
     * ON DELETE CASCADE — history is meaningless without the transaction.
     * FetchType.LAZY — we rarely need the full transaction when reading history.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "transaction_id", nullable = false)
    private Transaction transaction;

    // ─── State Change

    /**
     * The status BEFORE this change.
     * NULL only for the first entry (PENDING has no previous state).
     * Example: null → PENDING (initial creation)
     *          PENDING → PROCESSING (started execution)
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "old_status")
    private TransactionStatus oldStatus;

    /**
     * The status AFTER this change — always set.
     * DB constraint: NOT NULL
     * DB CHECK: old_status IS DISTINCT FROM new_status (no no-op entries)
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "new_status", nullable = false)
    private TransactionStatus newStatus;

    // ─── Actor

    /**
     * The user who triggered this status change.
     * NULL = system-initiated change (automatic processing).
     * NOT NULL = human-initiated change (admin reversal, user cancellation).
     *
     * ON DELETE SET NULL — keeps the history even if the user is deleted.
     * OWASP A09: we need to know if a human or the system made the change.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "changed_by")
    private User changedBy;

    // ─── Context

    /**
     * Human-readable reason for the change.
     * NULL for automatic transitions (system processing).
     * Required for admin-initiated changes (compliance).
     *
     * Examples:
     * → null                              (automatic: PENDING → PROCESSING)
     * → "Insufficient balance"            (automatic: PROCESSING → FAILED)
     * → "Reversed by admin due to fraud"  (manual: COMPLETED → FAILED)
     * → "Cancelled by user request"       (manual: PENDING → FAILED)
     */
    @Column(name = "reason", columnDefinition = "TEXT")
    private String reason;

    // ─── Timestamp

    /**
     * When this status change occurred.
     * Set by Spring Auditing — never set manually.
     * updatable = false — the moment of change is immutable.
     * OWASP A09: exact timestamp is critical for financial dispute resolution.
     */
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    // ─── Factory Methods

    /**
     * Creates a system-initiated history entry (no human actor, no reason).
     * Used for: PENDING, PROCESSING, COMPLETED, FAILED (automatic transitions).
     *
     * @param transaction the transaction changing state
     * @param oldStatus   previous status (null for initial PENDING)
     * @param newStatus   new status after the change
     */
    public static TransactionHistory system(Transaction transaction,
                                            TransactionStatus oldStatus,
                                            TransactionStatus newStatus) {
        return TransactionHistory.builder()
                .transaction(transaction)
                .oldStatus(oldStatus)
                .newStatus(newStatus)
                .build();
    }

    /**
     * Creates a human-initiated history entry (admin or user action).
     * Used for: manual reversals, cancellations, admin overrides.
     *
     * @param transaction the transaction changing state
     * @param oldStatus   previous status
     * @param newStatus   new status
     * @param changedBy   the user who made the change
     * @param reason      why the change was made (required for manual changes)
     */
    public static TransactionHistory manual(Transaction transaction,
                                            TransactionStatus oldStatus,
                                            TransactionStatus newStatus,
                                            User changedBy,
                                            String reason) {
        return TransactionHistory.builder()
                .transaction(transaction)
                .oldStatus(oldStatus)
                .newStatus(newStatus)
                .changedBy(changedBy)
                .reason(reason)
                .build();
    }
}