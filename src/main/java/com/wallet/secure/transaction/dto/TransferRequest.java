package com.wallet.secure.transaction.dto;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Digits;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;

import java.math.BigDecimal;
import java.util.UUID;

/**
 * DTO for POST /transactions/transfer
 * Moves funds between two wallets inside the system.
 *
 * WHY sourceWalletId is a UUID here (not currency like Deposit/Withdraw):
 * A user can have multiple wallets in the same currency — wait, actually
 * the DB enforces UNIQUE(user_id, currency), so one per currency.
 * BUT the TARGET wallet belongs to ANOTHER user — we need their walletId
 * because we don't know their currency preference.
 *
 * Design decision:
 * sourceWalletId → UUID (user knows their own wallet IDs from GET /wallets)
 * targetWalletId → UUID (required to identify the recipient's wallet)
 *
 * DB rule: both source AND target must be NOT NULL for TRANSFER.
 * DB rule: source != target (03-tables.sql CHECK source IS DISTINCT FROM target).
 *
 * OWASP A01: TransactionService verifies sourceWallet belongs to the
 * authenticated user — client cannot transfer from someone else's wallet.
 */
@Getter
public class TransferRequest {

    /**
     * Source wallet UUID — must belong to the authenticated user.
     * Verified in TransactionService via findByIdAndUserId().
     * OWASP A01: if wallet exists but belongs to another user → 404.
     */
    @NotNull(message = "Source wallet is required")
    private UUID sourceWalletId;

    /**
     * Target wallet UUID — the recipient's wallet.
     * Can belong to any active user in the system.
     * TransactionService verifies it exists and is ACTIVE.
     *
     * Why UUID and not email:
     * Using email as target would expose whether an email exists in the system.
     * UUID is opaque — recipient shares their walletId out-of-band.
     * OWASP A01: prevents user enumeration via transfer endpoint.
     */
    @NotNull(message = "Target wallet is required")
    private UUID targetWalletId;

    /**
     * Amount to transfer.
     * Must be <= sourceWallet.balance (validated in TransactionService).
     * Both wallets must share the same currency (validated in TransactionService).
     */
    @NotNull(message = "Amount is required")
    @DecimalMin(value = "0.01", message = "Minimum transfer is 0.01")
    @Digits(integer = 15, fraction = 4, message = "Amount format: max 15 digits and 4 decimals")
    private BigDecimal amount;

    @Size(max = 255, message = "Description cannot exceed 255 characters")
    private String description;
}