package com.wallet.secure.transaction.controller;

import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.transaction.dto.DepositRequest;
import com.wallet.secure.transaction.dto.TransactionResponse;
import com.wallet.secure.transaction.dto.TransferRequest;
import com.wallet.secure.transaction.dto.WithdrawRequest;
import com.wallet.secure.transaction.service.TransactionService;
import com.wallet.secure.user.repository.UserRepository;
import com.wallet.secure.common.exception.ResourceNotFoundException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * REST Controller for financial transaction endpoints.
 *
 * Base path: /transactions
 * All endpoints require valid JWT — no public endpoints.
 *
 * Endpoint summary:
 * POST /transactions/deposit       → add external funds to wallet
 * POST /transactions/withdraw      → remove funds from wallet
 * POST /transactions/transfer      → move funds between wallets
 * GET  /transactions               → my full transaction history (paginated)
 * GET  /transactions/wallet/{id}   → history for a specific wallet (paginated)
 * GET  /transactions/{id}          → single transaction detail
 *
 * Why POST for all financial operations and not PUT/PATCH:
 * Each operation CREATES a new Transaction record in DB.
 * POST = creates a new resource ← semantically correct.
 * PUT/PATCH = modifies existing resource ← incorrect here.
 *
 * OWASP A01: userId ALWAYS from @AuthenticationPrincipal — never from body.
 */
@RestController
@RequestMapping("/transactions")
@RequiredArgsConstructor
@Log4j2
public class TransactionController {

    private final TransactionService transactionService;
    private final UserRepository userRepository;

    // ─── Financial Operations

    /**
     * POST /transactions/deposit
     * Adds external funds into the authenticated user's wallet.
     *
     * HTTP 201 Created — a new Transaction record was created.
     * @Valid validates: amount > 0.01, currency not null, description max 255.
     * OWASP A01: target wallet resolved from JWT userId + currency,
     *            client cannot deposit into another user's wallet.
     */
    @PostMapping("/deposit")
    public ResponseEntity<ApiResponse<TransactionResponse>> deposit(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody DepositRequest request) {

        UUID userId = resolveUserId(userDetails);
        ApiResponse<TransactionResponse> response = transactionService.deposit(userId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * POST /transactions/withdraw
     * Removes funds from the authenticated user's wallet.
     *
     * HTTP 201 Created — a new Transaction record was created.
     * Business rule validated in service: balance >= amount + fee.
     * OWASP A01: source wallet resolved from JWT userId + currency.
     */
    @PostMapping("/withdraw")
    public ResponseEntity<ApiResponse<TransactionResponse>> withdraw(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody WithdrawRequest request) {

        UUID userId = resolveUserId(userDetails);
        ApiResponse<TransactionResponse> response = transactionService.withdraw(userId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * POST /transactions/transfer
     * Moves funds between two wallets inside the system.
     *
     * HTTP 201 Created — a new Transaction record was created.
     * Business rules validated in service:
     * → source wallet belongs to authenticated user
     * → both wallets are ACTIVE
     * → same currency
     * → sufficient balance
     * → source != target
     *
     * OWASP A01: sourceWallet ownership verified in TransactionService
     *            via validateWalletForTransaction(sourceWalletId, userId).
     */
    @PostMapping("/transfer")
    public ResponseEntity<ApiResponse<TransactionResponse>> transfer(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody TransferRequest request) {

        UUID userId = resolveUserId(userDetails);
        ApiResponse<TransactionResponse> response = transactionService.transfer(userId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ─── History

    /**
     * GET /transactions
     * Returns the authenticated user's full transaction history.
     *
     * Paginated — default page=0, size=20, sorted by createdAt DESC.
     * Client can customize: GET /transactions?page=1&size=10
     *
     * @PageableDefault sets the default pagination when client
     * doesn't specify page/size params.
     *
     * OWASP A01: userId from JWT → only their own transactions.
     */
    @GetMapping
    public ResponseEntity<ApiResponse<Page<TransactionResponse>>> getMyTransactions(
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20) Pageable pageable) {

        UUID userId = resolveUserId(userDetails);
        return ResponseEntity.ok(transactionService.getMyTransactions(userId, pageable));
    }

    /**
     * GET /transactions/wallet/{walletId}
     * Returns paginated transaction history for a specific wallet.
     *
     * WHY this endpoint exists separately from GET /transactions:
     * A user may have 5 wallets. GET /transactions returns ALL transactions
     * across all wallets — useful for a global statement.
     * This endpoint returns only the activity of ONE wallet — useful
     * for a per-wallet statement (e.g., USD wallet movements only).
     *
     * OWASP A01: TransactionService.getWalletTransactions() calls
     * walletService.getMyWallet(walletId, userId) to verify ownership
     * before returning any data.
     */
    @GetMapping("/wallet/{walletId}")
    public ResponseEntity<ApiResponse<Page<TransactionResponse>>> getWalletTransactions(
            @PathVariable UUID walletId,
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 20) Pageable pageable) {

        UUID userId = resolveUserId(userDetails);
        return ResponseEntity.ok(
                transactionService.getWalletTransactions(walletId, userId, pageable));
    }

    /**
     * GET /transactions/{id}
     * Returns a single transaction by UUID.
     *
     * OWASP A01: TransactionService.getTransaction() uses findByIdAndUserId()
     * → if transaction exists but user is not sender/receiver → 404
     * → same response as "not found" — prevents transaction enumeration.
     */
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<TransactionResponse>> getTransaction(
            @PathVariable UUID id,
            @AuthenticationPrincipal UserDetails userDetails) {

        UUID userId = resolveUserId(userDetails);
        return ResponseEntity.ok(transactionService.getTransaction(id, userId));
    }

    // ─── Private Helper

    /**
     * Resolves UUID from email stored in JWT principal.
     * Temporary until CustomUserDetails stores UUID directly.
     * Same pattern as WalletController and UserController.
     */
    private UUID resolveUserId(UserDetails userDetails) {
        return userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"))
                .getId();
    }
}