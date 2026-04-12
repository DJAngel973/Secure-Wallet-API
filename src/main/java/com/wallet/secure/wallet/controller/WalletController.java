package com.wallet.secure.wallet.controller;

import com.wallet.secure.common.enums.CurrencyCode;
import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.wallet.dto.CreateWalletRequest;
import com.wallet.secure.wallet.dto.WalletResponse;
import com.wallet.secure.wallet.service.WalletService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * REST Controller for wallet management.
 *
 * Base path: /wallets
 * All endpoints require valid JWT — no public endpoints here.
 *
 * Identity rule (OWASP A01):
 * userId ALWAYS comes from @AuthenticationPrincipal (validated JWT).
 * The client NEVER sends their own userId — it cannot be trusted.
 *
 * Endpoint summary:
 * POST   /wallets              → create wallet (authenticated user)
 * GET    /wallets              → list my wallets
 * GET    /wallets/{id}         → get one of my wallets by UUID
 * GET    /wallets/currency/{c} → get my wallet by currency
 * PATCH  /wallets/{id}/suspend → suspend wallet (ADMIN only)
 * PATCH  /wallets/{id}/restore → restore wallet (ADMIN only)
 * PATCH  /wallets/{id}/close   → close wallet permanently (ADMIN only)
 */
@RestController
@RequestMapping("/wallets")
@RequiredArgsConstructor
@Log4j2
public class WalletController {

    private final WalletService walletService;

    // --- User Endpoints

    /**
     * POST /wallets
     * Creates a new wallet for the authentication user.
     * HTTP 201 Created - a new resource was created.
     * userId from JWT - client never controls wallet ownership
     * OWASP A01: mass assignment prevention - only currency in body
     */
    @PostMapping
    public ResponseEntity<ApiResponse<WalletResponse>> createWallet(@AuthenticationPrincipal UserDetails userDetails, @Valid @RequestBody CreateWalletRequest request) {

        UUID userId = resolveUserId(userDetails);
        ApiResponse<WalletResponse> response = walletService.createWallet(userId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * GET /wallets
     * Returns all wallets belonging to the authenticated user.
     * OWASP A01: userId from JWT -> user can only see their own wallets.
     * No way to request wallets of another user via this endpoint
     */
    @GetMapping
    public ResponseEntity<ApiResponse<List<WalletResponse>>> getMyWallets(@AuthenticationPrincipal UserDetails userDetails) {

        UUID userId = resolveUserId(userDetails);
        return ResponseEntity.ok(walletService.getMyWallets(userId));
    }

    /**
     * GET /wallets/{id}
     * Returns a specific wallet by UUID - ownership verified in service.
     * OWASP A01: WalletService.getMyWallet() uses findByIdAndUserId()
     * -> if wallet exists but belongs to another user -> 404
     * -> attacker learns nothing (same response as "not found")
     */
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<WalletResponse>> getMyWallet(@PathVariable UUID id, @AuthenticationPrincipal UserDetails userDetails) {

        UUID userId = resolveUserId(userDetails);
        return ResponseEntity.ok(walletService.getMyWallet(id, userId));
    }

    /**
     * GET /wallets/currency/{currency}
     * Returns the authentication user's wallet for a specific currency.
     * Why this endpoint exists:
     * The client may know "I want my USD wallet" but not its UUID.
     * This avoids loading all wallets just to find one by currency.
     * Example: GET /wallets/currency/USD
     */
    @GetMapping("/currency/{currency}")
    public ResponseEntity<ApiResponse<WalletResponse>> getMyWalletByCurrency(@PathVariable CurrencyCode currency, @AuthenticationPrincipal UserDetails userDetails) {

        UUID userId = resolveUserId(userDetails);
        return ResponseEntity.ok(walletService.getMyWalletByCurrency(userId, currency));
    }

    // --- Admin Endpoints

    /**
     * PATCH /wallets/{id}/suspend
     * Suspends a wallet - ADMIN only
     * Why PATCH and not PUT:
     * PUT replaces the entire resource.
     * PATCH modifies a specific field (status only).
     * REST convention - use PATCH for partial updates.
     * OWASP A01: @PreAuthorize evaluated before method execution.
     * Non-admin -> 403 immediately, method never executes.
     */
    @PatchMapping("/{id}/suspend")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<WalletResponse>> suspendWallet(@PathVariable UUID id) {

        return ResponseEntity.ok(walletService.suspendWallet(id));
    }

    /**
     * PATCH /wallets/{id}/restore
     * Restores a suspended wallet to ACTIVE - ADMIN only.
     * OWASP A01: ADMIN role required.
     */
    @PatchMapping("/{id}/restore")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<WalletResponse>> restoreWallet(@PathVariable UUID id) {

        return ResponseEntity.ok(walletService.restoreWallet(id));
    }

    /**
     * PATCH /wallets/{id}/close
     * Permanently closes a wallet - ADMIN only.
     * Irreversible -wallet cannot be reopened after this.
     * Business rule: wallet must have zero balance (enforced in service).
     * OWASP A01: ADMIN role required.
     */
    @PatchMapping("/{id}/close")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<WalletResponse>> closeWallet(@PathVariable UUID id) {

        return ResponseEntity.ok(walletService.closeWallet(id));
    }

    // --- Private Helper

    /**
     * Resolves the authentication user's UUID their email.
     *
     * UserDetails.getUsername() = email (set by UserDetailsServiceImpl).
     * WalletService.resolverUserId() queries DB to get UUID from email.
     * NOTE: same pattern as UserController - will be refactored
     * when CustomUserDetails stores UUID directly in the JWT principal.
     */
    private UUID resolveUserId(UserDetails userDetails) {

        return walletService.resolveUserId(userDetails.getUsername());
    }
}
