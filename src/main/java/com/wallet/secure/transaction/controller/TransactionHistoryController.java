package com.wallet.secure.transaction.controller;

import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.transaction.dto.TransactionHistoryResponse;
import com.wallet.secure.transaction.service.TransactionHistoryService;
import com.wallet.secure.user.repository.UserRepository;
import com.wallet.secure.common.exception.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.util.List;
import java.util.UUID;

/**
 * REST Controller for transaction history (state timeline).
 *
 * Base path: /transactions/history
 *
 * WHO can call each endpoint:
 * → Any authenticated user → timeline of their OWN transactions
 * → ADMIN only             → timeline of ANY transaction + wallet audit
 *
 * Endpoint summary:
 * GET /transactions/{transactionId}/history
 *     → User: timeline of one of their own transactions
 *
 * GET /transactions/{transactionId}/history/admin
 *     → ADMIN: timeline of any transaction regardless of owner
 *
 * GET /wallets/{walletId}/history
 *     → ADMIN: all state changes for all transactions through a wallet
 *
 * WHY history endpoints are nested under /transactions/{id}:
 * History belongs to a transaction — it is a sub-resource.
 * REST convention: /transactions/{id}/history reads naturally as
 * "the history of transaction X".
 * This is consistent with how /wallets/{id}/transactions works.
 *
 * OWASP A01: userId always from JWT — users cannot access other users'
 * transaction history by guessing a transaction UUID.
 * Ownership check is enforced in TransactionHistoryService.
 *
 * OWASP A09: every state change is permanently recorded.
 * This controller only READS — history is never modified or deleted.
 */
@RestController
@RequiredArgsConstructor
@Log4j2
@Tag(name = "6. Transaction History", description = "Complete state timeline for each transaction — PENDING → PROCESSING → COMPLETED/FAILED")
public class TransactionHistoryController {

    private final TransactionHistoryService historyService;
    private final UserRepository userRepository;

    // ─── User Endpoints

    /**
     * GET /transactions/{transactionId}/history
     * Returns the complete state timeline for one of the user's transactions.
     *
     * Use case: "Show me everything that happened to this transaction"
     * Example response for a successful deposit:
     * [
     *   { oldStatus: null,       newStatus: "PENDING",    automatic: true },
     *   { oldStatus: "PENDING",  newStatus: "PROCESSING", automatic: true },
     *   { oldStatus: "PROCESSING", newStatus: "COMPLETED", automatic: true }
     * ]
     *
     * Example response for a failed withdrawal:
     * [
     *   { oldStatus: null,       newStatus: "PENDING",    automatic: true },
     *   { oldStatus: "PENDING",  newStatus: "PROCESSING", automatic: true },
     *   { oldStatus: "PROCESSING", newStatus: "FAILED",   reason: "Insufficient balance" }
     * ]
     *
     * OWASP A01: TransactionHistoryService.getTransactionTimeline() verifies
     * the requesting user is the sender or receiver of this transaction.
     * If the transaction exists but belongs to someone else → 404 (not 403).
     * Same error as "not found" — prevents transaction UUID enumeration.
     *
     * @param transactionId UUID of the transaction
     */
    @GetMapping("/transactions/{transactionId}/history")
    public ResponseEntity<ApiResponse<List<TransactionHistoryResponse>>> getMyTransactionHistory(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable UUID transactionId) {

        UUID userId = resolveUserId(userDetails.getUsername());

        return ResponseEntity.ok(
                historyService.getTransactionTimeline(transactionId, userId));
    }

    // ─── Admin Endpoints

    /**
     * GET /transactions/{transactionId}/history/admin
     * Returns the complete state timeline for ANY transaction — ADMIN only.
     *
     * Use case: "Customer disputes this transaction — show me the full trail"
     * Identical response format to the user endpoint but no ownership check.
     *
     * WHY a separate endpoint instead of role-checking in the same method:
     * → Clear URL structure — admin endpoints are visually distinct
     * → @PreAuthorize at method level — authorization is explicit in code
     * → Easier to audit: grep "/admin" shows all privileged endpoints
     *
     * OWASP A01: @PreAuthorize evaluated BEFORE method — non-ADMIN gets 403.
     */
    @GetMapping("/transactions/{transactionId}/history/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<TransactionHistoryResponse>>> getTransactionHistoryAdmin(
            @PathVariable UUID transactionId) {

        return ResponseEntity.ok(
                historyService.getTransactionTimelineAdmin(transactionId));
    }

    /**
     * GET /wallets/{walletId}/history
     * Returns all state changes for all transactions through a wallet — ADMIN only.
     *
     * Use case: "Audit everything that happened through this wallet"
     * Returns history entries for BOTH source and target sides.
     * Example: wallet X sent a transfer AND received a deposit → both appear.
     *
     * WHY this is admin-only:
     * A wallet can receive money from external users.
     * Showing that history to the wallet owner would expose other users'
     * transaction IDs and amounts → privacy violation.
     * ADMIN only sees this for legitimate investigation purposes.
     *
     * OWASP A01: @PreAuthorize — non-ADMIN gets 403 before any DB query.
     * OWASP A09: wallet-level forensic audit for compliance.
     *
     * @param walletId UUID of the wallet to audit
     */
    @GetMapping("/wallets/{walletId}/history")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<TransactionHistoryResponse>>> getWalletHistory(
            @PathVariable UUID walletId) {

        log.info("ADMIN wallet history audit: walletId={}", walletId);

        return ResponseEntity.ok(
                historyService.getWalletHistory(walletId));
    }

    // ─── Private Helper

    /**
     * Resolves user UUID from their email (from JWT).
     * OWASP A01: identity always from the trusted token — never from request.
     */
    private UUID resolveUserId(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"))
                .getId();
    }
}