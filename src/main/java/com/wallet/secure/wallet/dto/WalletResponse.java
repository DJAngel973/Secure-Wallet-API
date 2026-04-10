package com.wallet.secure.wallet.dto;

import com.wallet.secure.common.enums.CurrencyCode;
import com.wallet.secure.common.enums.WalletStatus;
import com.wallet.secure.wallet.entity.Wallet;
import lombok.Builder;
import lombok.Getter;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * DTO returned for all wallet read operations
 * OWASP A01 - Broken Access Control:
 * Why no userId:
 * - Get /wallets/me -> the client already knows these are their wallets
 * (they sent their JWT to get here - userId is redundant)
 * - Exposing userId in every response creates an unnecessary link
 *   between wallet IDs and user IDs - reduces enumeration surface
 * The wallet id (UUID) is exposed because:
 * - The client needs it to reference a specific wallet in future
 *   operations (POST /transactions, GET /wallets/{id})
 * - UUID is not sequential - not guessable (OWASP A01)
 * For ADMIN responses that need ownership context:
 * -> Use WalletAdminResponse (future) which includes ownerEmail
 * -> Never the raw userId UUID
 */
@Getter
@Builder
public class WalletResponse {

    /**
     * Wallet identifier - safe to expose
     * UUID v4 - not sequential, not guessable
     * Client uses this to reference the wallet in transactions
     */
    private final UUID id;

    private final CurrencyCode currency;

    /**
     * Balance - shown to the owner only
     * WalletService.getMyWallets() verifies ownership before returning
     * OWASP A01: service layer ensures you only see your own balance
     */
    private final BigDecimal balance;

    private final WalletStatus status;

    private final Instant createdAt;

    /**
     * Fields intentionally EXCLUDED:
     * userId -> redundant for /me endpoints, unnecessary exposure
     *           for admin use -> WalletAdminResponse with ownerEmail
     * updateAt -> internal audit timestamp, not relevant to client
     * user -> entire User object would espose passwordHash,
     *         refreshToken, failedLoginAttempts (OWASP A02)
     */
    public static WalletResponse fromEntity(Wallet wallet) {
        return WalletResponse.builder()
                .id(wallet.getId())
                .currency(wallet.getCurrency())
                .balance(wallet.getBalance())
                .status(wallet.getStatus())
                .createdAt(wallet.getCreatedAt())
                .build();
    }
}