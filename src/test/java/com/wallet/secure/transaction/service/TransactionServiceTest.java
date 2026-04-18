package com.wallet.secure.transaction.service;

import com.wallet.secure.common.enums.CurrencyCode;
import com.wallet.secure.common.enums.TransactionStatus;
import com.wallet.secure.common.enums.TransactionType;
import com.wallet.secure.common.enums.WalletStatus;
import com.wallet.secure.common.exception.ResourceNotFoundException;
import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.transaction.dto.DepositRequest;
import com.wallet.secure.transaction.dto.TransactionResponse;
import com.wallet.secure.transaction.dto.TransferRequest;
import com.wallet.secure.transaction.dto.WithdrawRequest;
import com.wallet.secure.transaction.entity.Transaction;
import com.wallet.secure.transaction.repository.TransactionRepository;
import com.wallet.secure.user.entity.User;
import com.wallet.secure.wallet.entity.Wallet;
import com.wallet.secure.wallet.repository.WalletRepository;
import com.wallet.secure.wallet.service.WalletService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for TransactionService — the most critical class in the project.
 *
 * Priority test scenarios:
 * 1. DEPOSIT   — funds credited correctly
 * 2. WITHDRAW  — balance check, insufficient funds
 * 3. TRANSFER  — ownership, currency match, balance, source != target
 *
 * What we mock:
 * → TransactionRepository — no real DB
 * → WalletRepository      — no real DB, we control balances
 * → WalletService         — we stub validateWalletForTransaction()
 *
 * WHY mock WalletService and not just WalletRepository:
 * TransactionService calls walletService.validateWalletForTransaction()
 * which internally uses walletRepository. Rather than setting up
 * the entire chain, we mock WalletService directly — cleaner and faster.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("TransactionService")
class TransactionServiceTest {

    @Mock private TransactionRepository transactionRepository;
    @Mock private WalletRepository walletRepository;
    @Mock private WalletService walletService;

    @InjectMocks
    private TransactionService transactionService;

    // ─── Shared test data

    private User owner;
    private UUID ownerId;

    private Wallet sourceWallet;
    private UUID sourceWalletId;

    private Wallet targetWallet;
    private UUID targetWalletId;

    @BeforeEach
    void setUp() {
        ownerId = UUID.randomUUID();
        sourceWalletId = UUID.fromString("00000000-0000-0000-0000-000000000001");
        targetWalletId = UUID.fromString("00000000-0000-0000-0000-000000000002");

        owner = User.builder()
                .id(ownerId)
                .email("albert@test.com")
                .passwordHash("$2a$12$password/hash")
                .build();

        sourceWallet = Wallet.builder()
                .id(sourceWalletId)
                .user(owner)
                .currency(CurrencyCode.USD)
                .balance(BigDecimal.valueOf(500.00))
                .status(WalletStatus.ACTIVE)
                .build();

        User recipient = User.builder()
                .id(UUID.randomUUID())
                .email("recipient@test.com")
                .passwordHash("$2a$12$password/hash2")
                .build();

        targetWallet = Wallet.builder()
                .id(targetWalletId)
                .user(recipient)
                .currency(CurrencyCode.USD)
                .balance(BigDecimal.valueOf(100.00))
                .status(WalletStatus.ACTIVE)
                .build();

        // Default: save() returns the same transaction passed to it
        when(transactionRepository.save(any(Transaction.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    // ─── DEPOSIT

    @Nested
    @DisplayName("deposit()")
    class DepositTests {

        @Test
        @DisplayName("credits wallet balance correctly on successful deposit")
        void deposit_validRequest_creditsBalance() {
            // GIVEN
            DepositRequest request = mock(DepositRequest.class);
            when(request.getCurrency()).thenReturn(CurrencyCode.USD);
            when(request.getAmount()).thenReturn(BigDecimal.valueOf(200.00));
            when(request.getReferenceCode()).thenReturn(null);
            when(request.getDescription()).thenReturn("Test deposit");

            when(transactionRepository.existsByReferenceCode(any())).thenReturn(false);
            when(walletRepository.findByUserIdAndCurrency(ownerId, CurrencyCode.USD))
                    .thenReturn(Optional.of(sourceWallet));
            when(walletService.validateWalletForTransaction(sourceWalletId, ownerId))
                    .thenReturn(sourceWallet);
            when(walletRepository.findByIdWithLock(sourceWalletId))
                    .thenReturn(Optional.of(sourceWallet));
            when(walletRepository.save(any(Wallet.class))).thenReturn(sourceWallet);

            BigDecimal balanceBefore = sourceWallet.getBalance(); // 500.00

            // WHEN
            ApiResponse<TransactionResponse> response =
                    transactionService.deposit(ownerId, request);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData().getTransactionType()).isEqualTo(TransactionType.DEPOSIT);
            assertThat(response.getData().getStatus()).isEqualTo(TransactionStatus.COMPLETED);

            // Balance was credited: 500 + 200 = 700
            assertThat(sourceWallet.getBalance())
                    .isEqualByComparingTo(balanceBefore.add(BigDecimal.valueOf(200.00)));
        }

        @Test
        @DisplayName("throws exception when reference code already exists")
        void deposit_duplicateReferenceCode_throwsException() {
            // GIVEN
            DepositRequest request = mock(DepositRequest.class);
            when(request.getReferenceCode()).thenReturn("PSE-12345");
            when(transactionRepository.existsByReferenceCode("PSE-12345")).thenReturn(true);

            // WHEN / THEN
            assertThatThrownBy(() -> transactionService.deposit(ownerId, request))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("PSE-12345");

            // No transaction was saved — validation failed before any DB write
            verify(transactionRepository, never()).save(any());
        }

        @Test
        @DisplayName("throws ResourceNotFoundException when user has no wallet for currency")
        void deposit_noWalletForCurrency_throwsException() {
            // GIVEN
            DepositRequest request = mock(DepositRequest.class);
            when(request.getCurrency()).thenReturn(CurrencyCode.EUR);
            when(request.getReferenceCode()).thenReturn(null);

            when(walletRepository.findByUserIdAndCurrency(ownerId, CurrencyCode.EUR))
                    .thenReturn(Optional.empty()); // ← user has no EUR wallet

            // WHEN / THEN
            assertThatThrownBy(() -> transactionService.deposit(ownerId, request))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("EUR");
        }
    }

    // ─── WITHDRAWAL

    @Nested
    @DisplayName("withdraw()")
    class WithdrawTests {

        @Test
        @DisplayName("debits wallet balance correctly on successful withdrawal")
        void withdraw_sufficientBalance_debitsBalance() {
            // GIVEN
            WithdrawRequest request = mock(WithdrawRequest.class);
            when(request.getCurrency()).thenReturn(CurrencyCode.USD);
            when(request.getAmount()).thenReturn(BigDecimal.valueOf(100.00));
            when(request.getReferenceCode()).thenReturn(null);
            when(request.getDescription()).thenReturn("ATM withdrawal");

            when(walletRepository.findByUserIdAndCurrency(ownerId, CurrencyCode.USD))
                    .thenReturn(Optional.of(sourceWallet));
            when(walletService.validateWalletForTransaction(sourceWalletId, ownerId))
                    .thenReturn(sourceWallet);
            when(walletRepository.findByIdWithLock(sourceWalletId))
                    .thenReturn(Optional.of(sourceWallet));
            when(walletRepository.save(any(Wallet.class))).thenReturn(sourceWallet);

            BigDecimal balanceBefore = sourceWallet.getBalance(); // 500.00

            // WHEN
            ApiResponse<TransactionResponse> response =
                    transactionService.withdraw(ownerId, request);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData().getTransactionType()).isEqualTo(TransactionType.WITHDRAWAL);
            assertThat(response.getData().getStatus()).isEqualTo(TransactionStatus.COMPLETED);

            // Balance debited: 500 - 100 = 400
            assertThat(sourceWallet.getBalance())
                    .isEqualByComparingTo(balanceBefore.subtract(BigDecimal.valueOf(100.00)));
        }

        @Test
        @DisplayName("throws exception when balance is insufficient — ACID protection")
        void withdraw_insufficientBalance_throwsException() {
            // GIVEN — try to withdraw MORE than available balance
            WithdrawRequest request = mock(WithdrawRequest.class);
            when(request.getCurrency()).thenReturn(CurrencyCode.USD);
            when(request.getAmount()).thenReturn(BigDecimal.valueOf(999.00)); // more than 500
            when(request.getReferenceCode()).thenReturn(null);
            when(request.getDescription()).thenReturn("Over-withdrawal attempt");

            when(walletRepository.findByUserIdAndCurrency(ownerId, CurrencyCode.USD))
                    .thenReturn(Optional.of(sourceWallet));
            when(walletService.validateWalletForTransaction(sourceWalletId, ownerId))
                    .thenReturn(sourceWallet);
            when(walletRepository.findByIdWithLock(sourceWalletId))
                    .thenReturn(Optional.of(sourceWallet));

            BigDecimal balanceBefore = sourceWallet.getBalance(); // 500.00

            // WHEN / THEN
            assertThatThrownBy(() -> transactionService.withdraw(ownerId, request))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Insufficient balance");

            // CRITICAL: balance must NOT have changed after failed withdrawal
            assertThat(sourceWallet.getBalance())
                    .isEqualByComparingTo(balanceBefore);
        }

        @Test
        @DisplayName("does not debit balance when withdrawal fails — ACID atomicity")
        void withdraw_failedTransaction_balanceUnchanged() {
            // GIVEN — wallet is SUSPENDED → validateWalletForTransaction throws
            WithdrawRequest request = mock(WithdrawRequest.class);
            when(request.getCurrency()).thenReturn(CurrencyCode.USD);
            when(request.getReferenceCode()).thenReturn(null);

            when(walletRepository.findByUserIdAndCurrency(ownerId, CurrencyCode.USD))
                    .thenReturn(Optional.of(sourceWallet));
            when(walletService.validateWalletForTransaction(sourceWalletId, ownerId))
                    .thenThrow(new IllegalStateException("Wallet is not available"));

            BigDecimal balanceBefore = sourceWallet.getBalance();

            // WHEN / THEN
            assertThatThrownBy(() -> transactionService.withdraw(ownerId, request))
                    .isInstanceOf(IllegalStateException.class);

            // Balance is completely untouched ← ACID atomicity
            assertThat(sourceWallet.getBalance()).isEqualByComparingTo(balanceBefore);
            verify(walletRepository, never()).save(any(Wallet.class));
        }
    }

    // ─── TRANSFER

    @Nested
    @DisplayName("transfer()")
    class TransferTests {

        @Test
        @DisplayName("moves funds from source to target wallet correctly")
        void transfer_validRequest_movesFunds() {
            // GIVEN
            TransferRequest request = mock(TransferRequest.class);
            when(request.getSourceWalletId()).thenReturn(sourceWalletId);
            when(request.getTargetWalletId()).thenReturn(targetWalletId);
            when(request.getAmount()).thenReturn(BigDecimal.valueOf(150.00));
            when(request.getDescription()).thenReturn("Split bill");

            when(walletService.validateWalletForTransaction(sourceWalletId, ownerId))
                    .thenReturn(sourceWallet);
            when(walletRepository.findById(targetWalletId))
                    .thenReturn(Optional.of(targetWallet));

            // Lock order: sourceWalletId (..001) < targetWalletId (..002)
            when(walletRepository.findByIdWithLock(sourceWalletId))
                    .thenReturn(Optional.of(sourceWallet));
            when(walletRepository.findByIdWithLock(targetWalletId))
                    .thenReturn(Optional.of(targetWallet));
            when(walletRepository.save(any(Wallet.class))).thenReturn(sourceWallet);

            // WHEN
            ApiResponse<TransactionResponse> response =
                    transactionService.transfer(ownerId, request);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData().getTransactionType()).isEqualTo(TransactionType.TRANSFER);
            assertThat(response.getData().getStatus()).isEqualTo(TransactionStatus.COMPLETED);

            // Source debited: 500 - 150 = 350
            assertThat(sourceWallet.getBalance())
                    .isEqualByComparingTo(BigDecimal.valueOf(350.00));

            // Target credited: 100 + 150 = 250
            assertThat(targetWallet.getBalance())
                    .isEqualByComparingTo(BigDecimal.valueOf(250.00));
        }

        @Test
        @DisplayName("throws exception when source and target wallet are the same")
        void transfer_sameWallet_throwsException() {
            // GIVEN
            TransferRequest request = mock(TransferRequest.class);
            when(request.getSourceWalletId()).thenReturn(sourceWalletId);
            when(request.getTargetWalletId()).thenReturn(sourceWalletId); // ← same!

            // WHEN / THEN
            assertThatThrownBy(() -> transactionService.transfer(ownerId, request))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("different");

            verify(transactionRepository, never()).save(any());
        }

        @Test
        @DisplayName("throws exception when currencies don't match — no cross-currency")
        void transfer_currencyMismatch_throwsException() {
            // GIVEN — target wallet is EUR, source is USD
            targetWallet.setCurrency(CurrencyCode.EUR);

            TransferRequest request = mock(TransferRequest.class);
            when(request.getSourceWalletId()).thenReturn(sourceWalletId);
            when(request.getTargetWalletId()).thenReturn(targetWalletId);
            when(request.getAmount()).thenReturn(BigDecimal.valueOf(50.00));

            when(walletService.validateWalletForTransaction(sourceWalletId, ownerId))
                    .thenReturn(sourceWallet);
            when(walletRepository.findById(targetWalletId))
                    .thenReturn(Optional.of(targetWallet));

            // WHEN / THEN
            assertThatThrownBy(() -> transactionService.transfer(ownerId, request))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Currency mismatch");

            verify(transactionRepository, never()).save(any());
        }

        @Test
        @DisplayName("throws exception when source balance is insufficient")
        void transfer_insufficientBalance_throwsException() {
            // GIVEN — try to transfer MORE than available
            TransferRequest request = mock(TransferRequest.class);
            when(request.getSourceWalletId()).thenReturn(sourceWalletId);
            when(request.getTargetWalletId()).thenReturn(targetWalletId);
            when(request.getAmount()).thenReturn(BigDecimal.valueOf(9999.00)); // more than 500

            when(walletService.validateWalletForTransaction(sourceWalletId, ownerId))
                    .thenReturn(sourceWallet);
            when(walletRepository.findById(targetWalletId))
                    .thenReturn(Optional.of(targetWallet));
            when(walletRepository.findByIdWithLock(sourceWalletId))
                    .thenReturn(Optional.of(sourceWallet));
            when(walletRepository.findByIdWithLock(targetWalletId))
                    .thenReturn(Optional.of(targetWallet));

            BigDecimal sourceBalanceBefore = sourceWallet.getBalance();
            BigDecimal targetBalanceBefore = targetWallet.getBalance();

            // WHEN / THEN
            assertThatThrownBy(() -> transactionService.transfer(ownerId, request))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Insufficient balance");

            // CRITICAL — neither balance changed ← ACID atomicity
            assertThat(sourceWallet.getBalance()).isEqualByComparingTo(sourceBalanceBefore);
            assertThat(targetWallet.getBalance()).isEqualByComparingTo(targetBalanceBefore);
        }

        @Test
        @DisplayName("throws 404 when target wallet does not exist — OWASP A01")
        void transfer_targetWalletNotFound_throwsException() {
            // GIVEN
            TransferRequest request = mock(TransferRequest.class);
            when(request.getSourceWalletId()).thenReturn(sourceWalletId);
            when(request.getTargetWalletId()).thenReturn(targetWalletId);
            when(request.getAmount()).thenReturn(BigDecimal.valueOf(50.00));

            when(walletService.validateWalletForTransaction(sourceWalletId, ownerId))
                    .thenReturn(sourceWallet);
            when(walletRepository.findById(targetWalletId))
                    .thenReturn(Optional.empty()); // ← doesn't exist

            // WHEN / THEN
            assertThatThrownBy(() -> transactionService.transfer(ownerId, request))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Target wallet not found");
        }

        @Test
        @DisplayName("throws exception when target wallet is SUSPENDED")
        void transfer_suspendedTargetWallet_throwsException() {
            // GIVEN
            targetWallet.setStatus(WalletStatus.SUSPENDED);

            TransferRequest request = mock(TransferRequest.class);
            when(request.getSourceWalletId()).thenReturn(sourceWalletId);
            when(request.getTargetWalletId()).thenReturn(targetWalletId);
            when(request.getAmount()).thenReturn(BigDecimal.valueOf(50.00));

            when(walletService.validateWalletForTransaction(sourceWalletId, ownerId))
                    .thenReturn(sourceWallet);
            when(walletRepository.findById(targetWalletId))
                    .thenReturn(Optional.of(targetWallet));

            // WHEN / THEN
            assertThatThrownBy(() -> transactionService.transfer(ownerId, request))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("not available");
        }
    }
}