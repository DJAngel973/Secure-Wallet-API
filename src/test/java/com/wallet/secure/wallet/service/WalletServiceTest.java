package com.wallet.secure.wallet.service;

import com.wallet.secure.audit.service.AuditService;
import com.wallet.secure.common.enums.CurrencyCode;
import com.wallet.secure.common.enums.WalletStatus;
import com.wallet.secure.common.exception.ResourceNotFoundException;
import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.user.entity.User;
import com.wallet.secure.user.repository.UserRepository;
import com.wallet.secure.wallet.dto.CreateWalletRequest;
import com.wallet.secure.wallet.dto.WalletResponse;
import com.wallet.secure.wallet.entity.Wallet;
import com.wallet.secure.wallet.repository.WalletRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.BiFunction;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for WalletService.
 *
 * Why @ExtendWith(MockitoExtension.class) and not @SpringBootTest:
 * @SpringBootTest loads the entire Spring context — slow (2-5 seconds).
 * MockitoExtension loads ONLY the class under test with mocked dependencies.
 * Fast (milliseconds) — ideal for unit tests that test ONE class in isolation.
 *
 * What we mock:
 * → WalletRepository — we don't want real DB calls
 * → UserRepository   — same reason
 *
 * What we test:
 * → Business logic in WalletService methods
 * → OWASP A01: ownership verification works correctly
 * → Status transition rules
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("WalletService")
public class WalletServiceTest {

    @Mock
    private WalletRepository walletRepository;

    @Mock private UserRepository userRepository;
    @Mock private AuditService auditService;

    @InjectMocks
    private WalletService walletService;

    // --- Shared test data

    private User testUser;
    private UUID userId;
    private Wallet activeWallet;
    private UUID walletId;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        walletId = UUID.randomUUID();

        testUser = User.builder()
                .id(userId)
                .email("jhon@test.com")
                .passwordHash("$3927$93.password")
                .build();

        activeWallet = Wallet.builder()
                .id(walletId)
                .user(testUser)
                .currency(CurrencyCode.USD)
                .balance(BigDecimal.valueOf(100.00))
                .status(WalletStatus.ACTIVE)
                .build();
    }

    // --- createWallet

    @Nested
    @DisplayName("createWallet()")
    class CreateWalletTests {

        @Test
        @DisplayName("creates wallet successfully when no duplicate exists")
        void createWallet_success() {
            // GIVEN
            CreateWalletRequest request = mock(CreateWalletRequest.class);
            when(request.getCurrency()).thenReturn(CurrencyCode.USD);

            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            when(walletRepository.existsByUserIdAndCurrency(userId, CurrencyCode.USD))
                    .thenReturn(false);
            when(walletRepository.save(any(Wallet.class))).thenReturn(activeWallet);

            // WHEN
            ApiResponse<WalletResponse> response = walletService.createWallet(userId, request);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData().getCurrency()).isEqualTo(CurrencyCode.USD);
            verify(walletRepository, times(1)).save(any(Wallet.class));
        }

        @Test
        @DisplayName("throws IllegalStateException when wallet for currency already exists")
        void createWallet_duplicateCurrency_throwsException() {
            // GIVEN
            CreateWalletRequest request = mock(CreateWalletRequest.class);
            when(request.getCurrency()).thenReturn(CurrencyCode.USD);

            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            when(walletRepository.existsByUserIdAndCurrency(userId, CurrencyCode.USD))
                    .thenReturn(true); // ← already has USD wallet

            // WHEN / THEN
            assertThatThrownBy(() -> walletService.createWallet(userId, request))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("USD");

            verify(walletRepository, never()).save(any()); // ← never saves
        }

        @Test
        @DisplayName("throws ResourceNotFoundException when user does not exist")
        void createWallet_userNotFound_throwsException() {
            // GIVEN
            CreateWalletRequest request = mock(CreateWalletRequest.class);
            when(userRepository.findById(userId)).thenReturn(Optional.empty());

            // WHEN / THEN
            assertThatThrownBy(() -> walletService.createWallet(userId, request))
                    .isInstanceOf(ResourceNotFoundException.class);

            verify(walletRepository, never()).save(any());
        }
    }

    // ─── getMyWallet — OWASP A01

    @Nested
    @DisplayName("getMyWallet() — OWASP A01 ownership")
    class GetMyWalletTests {

        @Test
        @DisplayName("returns wallet when it belongs to the requesting user")
        void getMyWallet_ownerRequests_returnsWallet() {
            // GIVEN
            when(walletRepository.findByIdAndUserId(walletId, userId))
                    .thenReturn(Optional.of(activeWallet));

            // WHEN
            ApiResponse<WalletResponse> response = walletService.getMyWallet(walletId, userId);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData().getId()).isEqualTo(walletId);
        }

        @Test
        @DisplayName("throws 404 when wallet belongs to another user — OWASP A01")
        void getMyWallet_differentUser_throws404() {
            // GIVEN — wallet exists but for a different user
            UUID otherUserId = UUID.randomUUID();
            when(walletRepository.findByIdAndUserId(walletId, otherUserId))
                    .thenReturn(Optional.empty()); // ← same as "not found"

            // WHEN / THEN
            // OWASP A01: attacker gets 404 — same as if wallet didn't exist
            // They learn nothing about whether the wallet exists
            assertThatThrownBy(() -> walletService.getMyWallet(walletId, otherUserId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Wallet not found");
        }
    }

    // ─── suspendWallet

    @Nested
    @DisplayName("suspendWallet()")
    class SuspendWalletTests {

        @Test
        @DisplayName("suspends ACTIVE wallet successfully")
        void suspendWallet_activeWallet_success() {
            // GIVEN
            when(walletRepository.findById(walletId)).thenReturn(Optional.of(activeWallet));
            when(walletRepository.save(any(Wallet.class))).thenReturn(activeWallet);

            // WHEN
            ApiResponse<WalletResponse> response = walletService.suspendWallet(walletId);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(activeWallet.getStatus()).isEqualTo(WalletStatus.SUSPENDED);
        }

        @Test
        @DisplayName("throws exception when trying to suspend an already SUSPENDED wallet")
        void suspendWallet_alreadySuspended_throwsException() {
            // GIVEN
            activeWallet.setStatus(WalletStatus.SUSPENDED);
            when(walletRepository.findById(walletId)).thenReturn(Optional.of(activeWallet));

            // WHEN / THEN
            assertThatThrownBy(() -> walletService.suspendWallet(walletId))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("ACTIVE");
        }

        @Test
        @DisplayName("throws exception when trying to suspend a CLOSED wallet")
        void suspendWallet_closedWallet_throwsException() {
            // GIVEN
            activeWallet.setStatus(WalletStatus.CLOSED);
            when(walletRepository.findById(walletId)).thenReturn(Optional.of(activeWallet));

            // WHEN / THEN
            assertThatThrownBy(() -> walletService.suspendWallet(walletId))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    // ─── closeWallet

    @Nested
    @DisplayName("closeWallet()")
    class CloseWalletTests {

        @Test
        @DisplayName("closes wallet with zero balance successfully")
        void closeWallet_zeroBalance_success() {
            // GIVEN — balance = 0
            activeWallet.setBalance(BigDecimal.ZERO);
            when(walletRepository.findById(walletId)).thenReturn(Optional.of(activeWallet));
            when(walletRepository.save(any(Wallet.class))).thenReturn(activeWallet);

            // WHEN
            ApiResponse<WalletResponse> response = walletService.closeWallet(walletId);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(activeWallet.getStatus()).isEqualTo(WalletStatus.CLOSED);
        }

        @Test
        @DisplayName("throws exception when closing wallet with remaining balance")
        void closeWallet_withBalance_throwsException() {
            // GIVEN — wallet still has money
            activeWallet.setBalance(BigDecimal.valueOf(150.00));
            when(walletRepository.findById(walletId)).thenReturn(Optional.of(activeWallet));

            // WHEN / THEN
            // Business rule: cannot close wallet with remaining balance
            assertThatThrownBy(() -> walletService.closeWallet(walletId))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("balance");
        }

        @Test
        @DisplayName("throws exception when wallet is already CLOSED")
        void closeWallet_alreadyClosed_throwsException() {
            // GIVEN
            activeWallet.setStatus(WalletStatus.CLOSED);
            activeWallet.setBalance(BigDecimal.ZERO);
            when(walletRepository.findById(walletId)).thenReturn(Optional.of(activeWallet));

            // WHEN / THEN
            assertThatThrownBy(() -> walletService.closeWallet(walletId))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("already closed");
        }
    }

    // ─── getMyWallets

    @Nested
    @DisplayName("getMyWallets()")
    class GetMyWalletsTests {

        @Test
        @DisplayName("returns all wallets for the authenticated user")
        void getMyWallets_returnsOwnedWallets() {
            // GIVEN
            Wallet copWallet = Wallet.builder()
                    .id(UUID.randomUUID())
                    .user(testUser)
                    .currency(CurrencyCode.COP)
                    .balance(BigDecimal.valueOf(500000))
                    .status(WalletStatus.ACTIVE)
                    .build();

            when(walletRepository.findByUserId(userId))
                    .thenReturn(List.of(activeWallet, copWallet));

            // WHEN
            ApiResponse<List<WalletResponse>> response = walletService.getMyWallets(userId);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData()).hasSize(2);
            assertThat(response.getData())
                    .extracting(WalletResponse::getCurrency)
                    .containsExactlyInAnyOrder(CurrencyCode.USD, CurrencyCode.COP);
        }

        @Test
        @DisplayName("returns empty list when user has no wallets")
        void getMyWallets_noWallets_returnsEmptyList() {
            // GIVEN
            when(walletRepository.findByUserId(userId)).thenReturn(List.of());

            // WHEN
            ApiResponse<List<WalletResponse>> response = walletService.getMyWallets(userId);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData()).isEmpty();
        }
    }
}