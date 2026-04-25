package com.wallet.secure.transaction.service;

import com.wallet.secure.common.enums.TransactionStatus;
import com.wallet.secure.common.exception.ResourceNotFoundException;
import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.transaction.dto.TransactionHistoryResponse;
import com.wallet.secure.transaction.entity.Transaction;
import com.wallet.secure.transaction.entity.TransactionHistory;
import com.wallet.secure.transaction.repository.TransactionHistoryRepository;
import com.wallet.secure.transaction.repository.TransactionRepository;
import com.wallet.secure.user.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for TransactionHistoryService.
 *
 * WHAT we test:
 * 1. record()                    — persists a system entry with correct fields
 * 2. recordManual()              — persists a human entry with changedBy + reason
 * 3. getTransactionTimeline()    — ownership check (OWASP A01), not found, returns list
 * 4. getTransactionTimelineAdmin() — no ownership check, not found, returns list
 * 5. getWalletHistory()          — delegates to repository, maps to response list
 *
 * WHAT we do NOT test:
 * → @Transactional behavior — requires Spring context
 * → fromEntity() mapping detail — covered implicitly via response assertions
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("TransactionHistoryService")
class TransactionHistoryServiceTest {

    @Mock private TransactionHistoryRepository historyRepository;
    @Mock private TransactionRepository transactionRepository;

    @InjectMocks
    private TransactionHistoryService historyService;

    // ─── Shared test data

    private UUID userId;
    private UUID transactionId;
    private UUID walletId;
    private Transaction testTransaction;
    private User testUser;

    @BeforeEach
    void setUp() {
        userId        = UUID.randomUUID();
        transactionId = UUID.randomUUID();
        walletId      = UUID.randomUUID();

        testUser = User.builder()
                .id(userId)
                .email("angel@test.com")
                .passwordHash("$2a$12$hash")
                .build();

        testTransaction = Transaction.builder()
                .id(transactionId)
                .build();

        // save() returns what is passed — standard repository stub
        lenient().when(historyRepository.save(any(TransactionHistory.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    // ─── Helper — builds a minimal TransactionHistory entity

    private TransactionHistory buildSystemEntry(TransactionStatus oldStatus,
                                                TransactionStatus newStatus) {
        return TransactionHistory.system(testTransaction, oldStatus, newStatus);
    }

    private TransactionHistory buildManualEntry(TransactionStatus oldStatus,
                                                TransactionStatus newStatus) {
        return TransactionHistory.manual(
                testTransaction, oldStatus, newStatus, testUser, "Reversed by admin");
    }

    // ─── record()

    @Nested
    @DisplayName("record()")
    class RecordTests {

        @Test
        @DisplayName("saves a system entry with correct transaction, oldStatus and newStatus")
        void record_savesSystemEntry() {
            // WHEN
            historyService.record(testTransaction, null, TransactionStatus.PENDING);

            // THEN — capture what was passed to save()
            ArgumentCaptor<TransactionHistory> captor =
                    ArgumentCaptor.forClass(TransactionHistory.class);
            verify(historyRepository).save(captor.capture());

            TransactionHistory saved = captor.getValue();
            assertThat(saved.getTransaction()).isEqualTo(testTransaction);
            assertThat(saved.getOldStatus()).isNull();                           // initial entry
            assertThat(saved.getNewStatus()).isEqualTo(TransactionStatus.PENDING);
            assertThat(saved.getChangedBy()).isNull();                           // system = no actor
            assertThat(saved.getReason()).isNull();                              // system = no reason
        }

        @Test
        @DisplayName("saves each lifecycle step — PENDING→PROCESSING→COMPLETED trail")
        void record_savesEachLifecycleStep() {
            // WHEN — three steps of a normal transaction lifecycle
            historyService.record(testTransaction, null, TransactionStatus.PENDING);
            historyService.record(testTransaction, TransactionStatus.PENDING, TransactionStatus.PROCESSING);
            historyService.record(testTransaction, TransactionStatus.PROCESSING, TransactionStatus.COMPLETED);

            // THEN — one save() call per step
            verify(historyRepository, times(3)).save(any(TransactionHistory.class));
        }

        @Test
        @DisplayName("does not throw when called fire-and-forget — OWASP A09 resilience")
        void record_doesNotThrow() {
            // WHEN / THEN — history recording must never crash the business operation
            assertThatNoException().isThrownBy(() ->
                    historyService.record(testTransaction,
                            TransactionStatus.PENDING, TransactionStatus.FAILED));
        }
    }

    // ─── recordManual()

    @Nested
    @DisplayName("recordManual()")
    class RecordManualTests {

        @Test
        @DisplayName("saves a manual entry with changedBy user and reason")
        void recordManual_savesHumanEntry() {
            // WHEN
            historyService.recordManual(
                    testTransaction,
                    TransactionStatus.COMPLETED,
                    TransactionStatus.FAILED,
                    testUser,
                    "Reversed by admin due to fraud");

            // THEN
            ArgumentCaptor<TransactionHistory> captor =
                    ArgumentCaptor.forClass(TransactionHistory.class);
            verify(historyRepository).save(captor.capture());

            TransactionHistory saved = captor.getValue();
            assertThat(saved.getOldStatus()).isEqualTo(TransactionStatus.COMPLETED);
            assertThat(saved.getNewStatus()).isEqualTo(TransactionStatus.FAILED);
            assertThat(saved.getChangedBy()).isEqualTo(testUser);
            assertThat(saved.getReason()).isEqualTo("Reversed by admin due to fraud");
        }

        @Test
        @DisplayName("system() entry has changedBy=null; manual() entry has changedBy set")
        void record_vs_recordManual_actorDifference() {
            // WHEN
            historyService.record(testTransaction, null, TransactionStatus.PENDING);
            historyService.recordManual(
                    testTransaction,
                    TransactionStatus.PENDING, TransactionStatus.FAILED,
                    testUser, "Cancelled by user request");

            // THEN
            ArgumentCaptor<TransactionHistory> captor =
                    ArgumentCaptor.forClass(TransactionHistory.class);
            verify(historyRepository, times(2)).save(captor.capture());

            List<TransactionHistory> allSaved = captor.getAllValues();
            assertThat(allSaved.get(0).getChangedBy()).isNull();           // system
            assertThat(allSaved.get(1).getChangedBy()).isEqualTo(testUser); // human
        }
    }

    // ─── getTransactionTimeline()

    @Nested
    @DisplayName("getTransactionTimeline()")
    class GetTransactionTimelineTests {

        @Test
        @DisplayName("returns ordered timeline when user owns the transaction — OWASP A01")
        void getTransactionTimeline_owner_returnsTimeline() {
            // GIVEN — ownership check passes
            when(transactionRepository.findByIdAndUserId(transactionId, userId))
                    .thenReturn(Optional.of(testTransaction));

            List<TransactionHistory> entries = List.of(
                    buildSystemEntry(null, TransactionStatus.PENDING),
                    buildSystemEntry(TransactionStatus.PENDING, TransactionStatus.COMPLETED)
            );
            when(historyRepository.findByTransactionIdOrderByCreatedAtAsc(transactionId))
                    .thenReturn(entries);

            // WHEN
            ApiResponse<List<TransactionHistoryResponse>> response =
                    historyService.getTransactionTimeline(transactionId, userId);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData()).hasSize(2);
            assertThat(response.getData().get(0).getNewStatus())
                    .isEqualTo(TransactionStatus.PENDING);
            assertThat(response.getData().get(1).getNewStatus())
                    .isEqualTo(TransactionStatus.COMPLETED);
        }

        @Test
        @DisplayName("throws 404 when transaction does not belong to the requesting user — OWASP A01")
        void getTransactionTimeline_differentUser_throws404() {
            // GIVEN — findByIdAndUserId returns empty → ownership failed
            // Returns 404 (not 403) to prevent resource enumeration
            UUID attackerId = UUID.randomUUID();
            when(transactionRepository.findByIdAndUserId(transactionId, attackerId))
                    .thenReturn(Optional.empty());

            // WHEN / THEN
            // OWASP A01: attacker learns nothing — same response as "not found"
            assertThatThrownBy(() ->
                    historyService.getTransactionTimeline(transactionId, attackerId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Transaction not found");

            // History repository is never queried — ownership failed early
            verify(historyRepository, never()).findByTransactionIdOrderByCreatedAtAsc(any());
        }

        @Test
        @DisplayName("returns empty list when transaction exists but has no history entries yet")
        void getTransactionTimeline_noEntries_returnsEmptyList() {
            // GIVEN — valid owner, but history table is empty for this transaction
            when(transactionRepository.findByIdAndUserId(transactionId, userId))
                    .thenReturn(Optional.of(testTransaction));
            when(historyRepository.findByTransactionIdOrderByCreatedAtAsc(transactionId))
                    .thenReturn(List.of());

            // WHEN
            ApiResponse<List<TransactionHistoryResponse>> response =
                    historyService.getTransactionTimeline(transactionId, userId);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData()).isEmpty();
        }
    }

    // ─── getTransactionTimelineAdmin()

    @Nested
    @DisplayName("getTransactionTimelineAdmin()")
    class GetTransactionTimelineAdminTests {

        @Test
        @DisplayName("returns timeline for any transaction — no ownership check for admin")
        void getTransactionTimelineAdmin_anyTransaction_returnsTimeline() {
            // GIVEN — admin can query any transaction, no userId involved
            when(transactionRepository.findById(transactionId))
                    .thenReturn(Optional.of(testTransaction));

            List<TransactionHistory> entries = List.of(
                    buildSystemEntry(null, TransactionStatus.PENDING),
                    buildManualEntry(TransactionStatus.COMPLETED, TransactionStatus.FAILED)
            );
            when(historyRepository.findByTransactionIdOrderByCreatedAtAsc(transactionId))
                    .thenReturn(entries);

            // WHEN
            ApiResponse<List<TransactionHistoryResponse>> response =
                    historyService.getTransactionTimelineAdmin(transactionId);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData()).hasSize(2);

            // First entry = system (automatic=true), second = manual (automatic=false)
            assertThat(response.getData().get(0).isAutomatic()).isTrue();
            assertThat(response.getData().get(1).isAutomatic()).isFalse();
            assertThat(response.getData().get(1).getChangedById()).isEqualTo(userId);
            assertThat(response.getData().get(1).getChangedByEmail()).isEqualTo("angel@test.com");
        }

        @Test
        @DisplayName("throws 404 when transaction does not exist")
        void getTransactionTimelineAdmin_transactionNotFound_throwsException() {
            // GIVEN
            when(transactionRepository.findById(transactionId)).thenReturn(Optional.empty());

            // WHEN / THEN
            assertThatThrownBy(() ->
                    historyService.getTransactionTimelineAdmin(transactionId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Transaction not found");

            verify(historyRepository, never()).findByTransactionIdOrderByCreatedAtAsc(any());
        }
    }

    // ─── getWalletHistory()

    @Nested
    @DisplayName("getWalletHistory()")
    class GetWalletHistoryTests {

        @Test
        @DisplayName("returns all history entries for a wallet — admin only")
        void getWalletHistory_returnsAllEntries() {
            // GIVEN
            List<TransactionHistory> entries = List.of(
                    buildSystemEntry(null, TransactionStatus.PENDING),
                    buildSystemEntry(TransactionStatus.PENDING, TransactionStatus.COMPLETED),
                    buildSystemEntry(null, TransactionStatus.PENDING),
                    buildSystemEntry(TransactionStatus.PENDING, TransactionStatus.FAILED)
            );
            when(historyRepository.findByWalletId(walletId)).thenReturn(entries);

            // WHEN
            ApiResponse<List<TransactionHistoryResponse>> response =
                    historyService.getWalletHistory(walletId);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData()).hasSize(4);
            verify(historyRepository).findByWalletId(walletId);
        }

        @Test
        @DisplayName("returns empty list when wallet has no transaction history")
        void getWalletHistory_noEntries_returnsEmptyList() {
            // GIVEN
            when(historyRepository.findByWalletId(walletId)).thenReturn(List.of());

            // WHEN
            ApiResponse<List<TransactionHistoryResponse>> response =
                    historyService.getWalletHistory(walletId);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData()).isEmpty();
        }
    }
}
