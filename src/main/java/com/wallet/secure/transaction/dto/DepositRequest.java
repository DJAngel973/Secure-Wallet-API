package com.wallet.secure.transaction.dto;

import com.wallet.secure.common.enums.CurrencyCode;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Digits;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;

import java.math.BigDecimal;

/**
 * DTO for POST /transactions/deposit
 * Adds external funds into the authenticated user's wallet.
 * Why no sourceWalletId:
 * DEPOSIT = money comes from outside the system (bank, PSE, PayPal)
 * There is no source wallet - only a target wallet.
 * DB rule: source_wallet_id IS NULL for DEPOSIT
 * Why no userId:
 * Comes from JWT - client never controls who receives the deposit.
 * OWASP A01: mass assignment prevention
 */
@Getter
public class DepositRequest {

    /**
     * Target wallet currency - identifies WHICH wallet receives the founds.
     * Why currency and not walletId:
     * More user-friendly - "deposit to my USD wallet" is clearer
     * than requiring the client to know the wallet UUID.
     * WalletService.getMyWalletByCurrency() resolves to the wallet.
     */
    @NotNull(message = "Currency is required")
    private CurrencyCode currency;

    /**
     * Amount to deposit.
     * @DecimalMin("0.01") - minimum deposit is 1 cent. never zero or negative.
     * @Digits - max 15 whole digits + 4 decimal places = DECIMAL(19, 4) in DB.
     */
    @NotNull(message = "Amount is required")
    @DecimalMin(value = "0.01", message = "Minimum deposit is 0.01")
    @Digits(integer = 15, fraction = 4, message = "Amount format: max 15 digits and 4 decimals")
    private BigDecimal amount;

    /**
     * Optional human-readable description.
     * Example: "Salary deposit", "Client payment"
     * Max 255 chars - prevents oversized input (OWASP A03).
     */
    @Size(max = 255, message = "Description cannot exceed 255 characters")
    private String description;

    /**
     * Optional external reference code (PSE, PayPal ID, etc.)
     * Used for reconciliation with payment gateways.
     * DB constraint: UNIQUE - TransactionService checks before saving.
     */
    @Size(max = 255, message = "Description cannot exceed 100 characters")
    private String referenceCode;
}