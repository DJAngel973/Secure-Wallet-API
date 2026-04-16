package com.wallet.secure.transaction.dto;

import com.wallet.secure.common.enums.CurrencyCode;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Digits;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;

import java.math.BigDecimal;

/**
 * DTO for POST /transactions/withdraw
 * Removes funds from the authenticated user's wallet to an external destination.
 *
 * WHY no targetWalletId:
 * WITHDRAWAL = money leaves the system (bank transfer, cash out).
 * There is no target wallet — only a source wallet.
 * DB rule: target_wallet_id IS NULL for WITHDRAWAL
 *
 * OWASP A01: userId from JWT — client cannot withdraw from another user's wallet.
 */
@Getter
public class WithdrawRequest {

    /**
     * Source wallet currency — identifies WHICH wallet funds are taken from.
     * Same reasoning as DepositRequest — currency is more user-friendly than UUID.
     */
    @NotNull(message = "Currency is required")
    private CurrencyCode currency;

    /**
     * Amount to withdraw
     * TransactionService validates: balance >= amount + fee before processing.
     * DB CHECK: amount > 0.
     */
    @NotNull(message = "Amount is required")
    @DecimalMin(value = "0.01", message = "Minimum withdrawal is 0.01")
    @Digits(integer = 15, fraction = 4, message = "Amount format: max 15 digits and 4 decimals")
    private BigDecimal amount;

    @Size(max = 255, message = "Description cannot exceed 255 characters")
    private String description;

    @Size(max = 100, message = "Reference code cannot exceed 100 characters")
    private String referenceCode;
}