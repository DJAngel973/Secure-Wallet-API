package com.wallet.secure.wallet.service;

import com.wallet.secure.common.enums.CurrencyCode;
import com.wallet.secure.common.enums.WalletStatus;
import com.wallet.secure.common.exception.ResourceNotFoundException;
import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.common.util.LogSanitizer;
import com.wallet.secure.user.entity.User;
import com.wallet.secure.user.repository.UserRepository;
import com.wallet.secure.wallet.dto.CreateWalletRequest;
import com.wallet.secure.wallet.dto.WalletResponse;
import com.wallet.secure.wallet.entity.Wallet;
import com.wallet.secure.wallet.repository.WalletRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Business logic for wallet management.
 *
 * Responsibilities:
 * - Create wallets (one per currency per user)
 * - Read wallets (own only — OWASP A01)
 * - Suspend / close wallets (admin)
 *
 * What this service does NOT do:
 * - Modify balances directly → that is TransactionService only
 * - Use locking queries → those are for TransactionService only
 *
 * OWASP A01: every method that reads wallet data verifies
 * that the requesting user owns the wallet before returning it.
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class WalletService {

    private final WalletRepository walletRepository;
    private final UserRepository userRepository;

    // --- Create

    /**
     * Creates a new wallet for the authentication user.
     * Business rules:
     * 1. One wallet per currency per user (DB UNIQUE + service check)
     * 2. Initial balance is always 0 - client cannot set it.
     * 3. Initial status is always ACTIVE
     * 4. userId comes from JWT - never from the request body.
     * OWASP A01: userId injected from SecurityContext by the controller -
     * client never controls who the wallet is created for.
     *
     * @param userId  authentication user's ID (from JWT)
     * @param request DTO with desired currency
     * @retun ApiResponse with the created WalletResponse
     */
    @Transactional
    public ApiResponse<WalletResponse> createWallet(UUID userId, CreateWalletRequest request) {

        // Load the user - needed to set the wallet owner
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        // Business rule: one wallet per currency per user
        // Check at service level -> clear error message
        // DB UNIQUE constraint is the final safety net
        if (walletRepository.existsByUserIdAndCurrency(userId, request.getCurrency())) {
            throw new IllegalStateException(String.format("You already have a %s wallet", request.getCurrency()));
        }
        // Built wallet - balance=0 and status=ACTIVE are set by @Builder.Default
        Wallet wallet = Wallet.builder()
                .user(user)
                .currency(request.getCurrency())
                .build();

        Wallet saved = walletRepository.save(wallet);

        log.info("Wallet created: currency={}  userId={}",
                saved.getCurrency(),
                LogSanitizer.sanitize(userId.toString()));

        return ApiResponse.ok("Wallet created successfully", WalletResponse.fromEntity(saved));
    }

    // --- Read

    /**
     * Returns all wallets belonging to the authentication user.
     *
     * OWASP A01: userId comes from the validated JWT - the user can only
     * see their own wallets. No parameter from the client body is trusted.
     * @param userId authentication user's ID (from JWT)
     * @return ApiResponse with list of WalletResponse
     */
    @Transactional(readOnly = true)
    public ApiResponse<List<WalletResponse>> getMyWallets(UUID userId) {

        List<WalletResponse> wallets = walletRepository.findByUserId(userId)
                .stream()
                .map(WalletResponse::fromEntity)
                .toList();
        return ApiResponse.ok("Wallet retrieved", wallets);
    }

    /**
     * Returns a specific wallet - verifies ownership.
     * Why findByIdAndUserId instead of findById:
     * findById(id) -> anyone who knows the UUID can retrieve the wallet
     * findByIdAndUserId(id, userId) -> only the owner cant retrieve it
     *
     * If the wallet exists but belongs to another user:
     * -> returns empty -> throws ResourceNotFoundException -> 404
     * -> same response as "wallet doesn't exist"
     * -> OWASP A01: prevents wallet enumeration by other users
     *    (attacker learns nothing from the response)
     *
     * @param walletId wallet UUID
     * @param userId authentication user's ID (from JWT)
     * @return ApiResponse with WalletResponse
     */
    @Transactional(readOnly = true)
    public ApiResponse<WalletResponse> getMyWallet(UUID walletId, UUID userId) {

        Wallet wallet = walletRepository.findByIdAndUserId(walletId, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Wallet not found"));

        return ApiResponse.ok("Wallet retrieved",  WalletResponse.fromEntity(wallet));
    }

    /**
     * Returns a specific wallet by currency for the authenticated user.
     * Userful when the client knows the currency but not the wallet UUID.
     *
     * @param userId authentication user's ID (from JWT)
     * @param currency desired currency
     * @return ApiResponse with WalletResponse
     */
    @Transactional(readOnly = true)
    public ApiResponse<WalletResponse> getMyWalletByCurrency(UUID userId, CurrencyCode currency) {

        Wallet wallet = walletRepository.findByUserIdAndCurrency(userId, currency)
                .orElseThrow(() -> new ResourceNotFoundException(String.format("You don't have a %s wallet", currency)));

        return ApiResponse.ok("Wallet retrieved", WalletResponse.fromEntity(wallet));
    }

    // --- Admin Operations

    /**
     * Suspends a wallet - ADMIN only
     * ACTIVE -> SUSPENDED
     * No transactions allowed white suspended
     * Why suspension and not direct closure:
     * Suspension is reversible - admin can restore ACTIVE.
     * Closure is permanent - use closeWallet() for that
     * Gives the user a chance to resolve issues before permanent closure.
     * OWASP A01: @PreAuthorize("hasROle('ADMIN')") enforced at controller level.
     *
     * @param walletId wallet to suspend
     * @return ApiResponse with updates WalletResponse
     */
    @Transactional
    public ApiResponse<WalletResponse> suspendWallet(UUID walletId) {

        Wallet wallet = walletRepository.findById(walletId)
                .orElseThrow(() -> new ResourceNotFoundException("Wallet not found"));

        if (!WalletStatus.ACTIVE.equals(wallet.getStatus())) {
            throw new IllegalStateException(String.format("Only ACTIVE wallets can be suspended. Current status: %s", wallet.getStatus()));
        }
        wallet.setStatus(WalletStatus.SUSPENDED);
        Wallet saved = walletRepository.save(wallet);

        log.warn("Wallet suspended: walletId={}", walletId);

        return ApiResponse.ok("Wallet suspended", WalletResponse.fromEntity(saved));
    }

    /**
     * Closes a wallet permanently - ADMIN only.
     * ACTIVE or SUSPENDED -> CLOSED (irreversible)
     * Business rule: cannot close a wallet with remaining balance.
     * The user must withdraw or transfer funds first.
     * Prevents losing money in a closed wallet.
     * OWASP A01: @PreAuthorize("hasRole('ADMIN')") at controller level
     *
     * @param walletId wallet to close permanently
     * @return ApiResponse with updated WalletResponse
     */
    @Transactional
    public ApiResponse<WalletResponse> closeWallet(UUID walletId) {

        Wallet wallet = walletRepository.findById(walletId)
                .orElseThrow(() -> new ResourceNotFoundException("Wallet not found"));

        if (WalletStatus.CLOSED.equals(wallet.getStatus())) {
            throw new IllegalStateException("Wallet is already closed");
        }
        // Business rule: cannot close wallet with remaining balance
        // Client must withdraw/transfer funds first
        if (wallet.getBalance().signum() > 0) {
            throw new IllegalStateException("Cannot close wallet with remaining balance.\nPlease withdraw or transfer funds first.");
        }
        wallet.setStatus(WalletStatus.CLOSED);
        Wallet saved =  walletRepository.save(wallet);

        log.warn("Wallet permanently closed: walletId={}", walletId);

        return ApiResponse.ok("Wallet closed permanently", WalletResponse.fromEntity(saved));
    }

    /**
     * Restores a suspended wallet to ACTIVE - ADMIN only.
     * SUSPENDED -> ACTIVE
     *
     * @param walletId wallet to restore
     * @return ApiResponse with updated WalletResponse
     */
    @Transactional
    public ApiResponse<WalletResponse> restoreWallet(UUID walletId) {

        Wallet wallet =  walletRepository.findById(walletId)
                .orElseThrow(() -> new ResourceNotFoundException("Wallet not found"));

        if (!WalletStatus.SUSPENDED.equals(wallet.getStatus())) {
            throw new IllegalStateException(String.format("Only SUSPENDED wallets can be restored. Current status: %s", wallet.getStatus()));
        }
        wallet.setStatus(WalletStatus.ACTIVE);
        Wallet saved = walletRepository.save(wallet);

        log.warn("Wallet restored to ACTIVE: walletId={}", walletId);

        return ApiResponse.ok("Wallet restored", WalletResponse.fromEntity(saved));
    }

    // --- Internal User - called by TransactionService

    /**
     * Verifies a wallet exists and is operational
     * Called by TransactionService before acquiring locks.
     * Why a separate method and not inline in TransactionService:
     * -> Single place for "is this wallet valid for transactions?" logic
     * -> TransactionService stays focused on the transaction itself
     * -> If the rule changes (ex: add a daily limit check), only this changes
     *
     * @param walletId wallet UUID to validate
     * @param userId owner UUID - verifies ownership
     * @return the wallet entity if valid
     * @throws ResourceNotFoundException if wallet not found or not owned by user
     * @throws IllegalStateException if wallet is not ACTIVE
     */
    @Transactional(readOnly = true)
    public Wallet validateWalletForTransaction(UUID walletId, UUID userId) {

        Wallet wallet = walletRepository.findByIdAndUserId(walletId, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Wallet not found"));

        if (!wallet.isOperational()) {
            throw new IllegalStateException(String.format("Wallet is not available for transaction Status: %s", wallet.getStatus()));
        }
        return wallet;
    }

    /**
     * Resolves UUID from email for controller use.
     * Temporary until CustomUserDetails stores UUID directly in JWT principal.
     */
    @Transactional(readOnly = true)
    public UUID resolveUserId(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found")).getId();
    }
}