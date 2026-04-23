package com.wallet.secure.transaction.dto;

import com.wallet.secure.common.enums.TransactionStatus;
import com.wallet.secure.transaction.entity.TransactionHistory;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.UUID;

/**
 * DTO for transaction history entries.
 *
 * OWASP A01 — what is NOT exposed:
 * → Full Transaction entity     ← too much data, use TransactionResponse for that
 * → Full User entity (changedBy)← only expose the UUID + email snapshot
 * → Internal wallet IDs         ← not relevant for history display
 *
 * WHAT IS exposed and why:
 * → transactionId   ← client can cross-reference with TransactionResponse
 * → oldStatus       ← "came FROM this state"
 * → newStatus       ← "moved TO this state"
 * → changedById     ← null = system, UUID = human actor
 * → changedByEmail  ← human-readable actor identification
 * → reason          ← why it changed (null for automatic transitions)
 * → createdAt       ← exact timestamp of the change
 * → automatic       ← convenience flag: true if system-initiated
 *
 * The combination of oldStatus + newStatus + createdAt + reason
 * gives a complete, human-readable audit trail entry.
 */
@Getter
@Builder
public class TransactionHistoryResponse {

    /** UUID of the history entry itself */
    private final UUID id;

    /** UUID of the transaction this entry belongs to */
    private final UUID transactionId;

    /**
     * Status before this change.
     * NULL for the first entry (initial PENDING creation has no previous state).
     */
    private final TransactionStatus oldStatus;

    /** Status after this change — always set */
    private final TransactionStatus newStatus;

    /**
     * UUID of the user who triggered the change.
     * NULL = system-initiated (automatic processing).
     * NOT NULL = human actor (admin reversal, user cancellation).
     */
    private final UUID changedById;

    /**
     * Email of the user who triggered the change.
     * NULL for system-initiated changes.
     * Snapshot — the user may no longer exist but the record remains.
     */
    private final String changedByEmail;

    /**
     * Why the status changed.
     * NULL for automatic system transitions.
     * Required (and always set) for manual admin changes.
     * Examples: "Insufficient balance", "Reversed by admin due to fraud"
     */
    private final String reason;

    /** Exact moment this status change occurred */
    private final Instant createdAt;

    /**
     * Convenience flag for the frontend.
     * true  = system made this change automatically
     * false = a human (admin or user) made this change
     * Derived from changedById == null.
     */
    private final boolean automatic;

    // ─── Factory Method

    public static TransactionHistoryResponse fromEntity(TransactionHistory history) {
        return TransactionHistoryResponse.builder()
                .id(history.getId())
                .transactionId(history.getTransaction().getId())
                .oldStatus(history.getOldStatus())
                .newStatus(history.getNewStatus())
                .changedById(history.getChangedBy() != null
                        ? history.getChangedBy().getId() : null)
                .changedByEmail(history.getChangedBy() != null
                        ? history.getChangedBy().getEmail() : null)
                .reason(history.getReason())
                .createdAt(history.getCreatedAt())
                .automatic(history.getChangedBy() == null)
                .build();
    }
}