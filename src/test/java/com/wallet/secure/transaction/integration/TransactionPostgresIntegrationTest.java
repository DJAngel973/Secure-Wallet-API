package com.wallet.secure.transaction.integration;

import com.wallet.secure.audit.repository.AuditLogRepository;
import com.wallet.secure.common.enums.AuditAction;
import com.wallet.secure.common.enums.CurrencyCode;
import com.wallet.secure.common.enums.TransactionStatus;
import com.wallet.secure.common.enums.TransactionType;
import com.wallet.secure.common.enums.UserRole;
import com.wallet.secure.common.exception.InsufficientFundsException;
import com.wallet.secure.transaction.dto.WithdrawRequest;
import com.wallet.secure.transaction.dto.TransferRequest;
import com.wallet.secure.transaction.repository.TransactionHistoryRepository;
import com.wallet.secure.transaction.repository.TransactionRepository;
import com.wallet.secure.transaction.service.TransactionService;
import com.wallet.secure.user.entity.User;
import com.wallet.secure.user.repository.UserRepository;
import com.wallet.secure.wallet.entity.Wallet;
import com.wallet.secure.wallet.repository.WalletRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.BindMode;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.math.BigDecimal;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TX-001 integration evidence. The container receives the tracked SQL schema
 * and is destroyed after the class; no local/developer database is ever read or changed.
 */
@Testcontainers
@SpringBootTest
class TransactionPostgresIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("wallet_test")
            .withUsername("wallet_test")
            .withPassword("wallet_test")
            .withFileSystemBind("database", "/docker-entrypoint-initdb.d", BindMode.READ_ONLY);

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
        registry.add("spring.jpa.properties.hibernate.type.preferred_inet_jdbc_type", () -> "VARCHAR");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("jwt.secret", () -> "test-only-secret-that-is-long-enough-for-hs256-signing-key");
    }

    @Autowired private TransactionService transactionService;
    @Autowired private UserRepository userRepository;
    @Autowired private WalletRepository walletRepository;
    @Autowired private TransactionRepository transactionRepository;
    @Autowired private TransactionHistoryRepository historyRepository;
    @Autowired private AuditLogRepository auditLogRepository;
    @Autowired private JdbcTemplate jdbcTemplate;

    private UUID userId;
    private UUID walletId;

    @BeforeEach
    void setUp() {
        User user = userRepository.saveAndFlush(User.builder()
                .email("tx-" + UUID.randomUUID() + "@example.test")
                .passwordHash("$2a$12$integration-test-password-hash")
                .role(UserRole.USER).isActive(true).emailVerified(true).build());
        Wallet wallet = walletRepository.saveAndFlush(Wallet.builder()
                .user(user).currency(CurrencyCode.USD).balance(new BigDecimal("100.0000")).build());
        userId = user.getId();
        walletId = wallet.getId();
    }

    @Test
    @DisplayName("concurrent withdrawals serialize balance and preserve success/failure evidence")
    void withdraw_concurrentRequests_serializesBalanceAndPreservesEvidence() throws Exception {
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            CompletableFuture<Boolean> first = CompletableFuture.supplyAsync(() -> attemptWithdrawal(start, "80.0000"), executor);
            CompletableFuture<Boolean> second = CompletableFuture.supplyAsync(() -> attemptWithdrawal(start, "80.0000"), executor);
            start.countDown();

            boolean firstSucceeded = first.get(20, TimeUnit.SECONDS);
            boolean secondSucceeded = second.get(20, TimeUnit.SECONDS);
            assertThat(firstSucceeded ^ secondSucceeded).isTrue();
        } finally {
            executor.shutdownNow();
        }

        Wallet reloaded = walletRepository.findById(walletId).orElseThrow();
        assertThat(reloaded.getBalance()).isEqualByComparingTo("20.0000");
        assertThat(transactionRepository.findAll().stream()
                .filter(t -> t.getTransactionType() == TransactionType.WITHDRAWAL)
                .filter(t -> t.getStatus() == TransactionStatus.COMPLETED)).hasSize(1);
        assertThat(historyCount(TransactionStatus.COMPLETED)).isEqualTo(2);
        assertThat(historyCount(TransactionStatus.FAILED)).isZero();
        assertThat(auditLogRepository.findAll().stream()
                .filter(a -> userId.equals(a.getUserId()))
                .filter(a -> a.getAction() == AuditAction.TRANSACTION_COMPLETE)).hasSize(1);
        assertThat(auditLogRepository.findAll().stream()
                .filter(a -> userId.equals(a.getUserId()))
                .filter(a -> a.getAction() == AuditAction.TRANSACTION_FAIL)).hasSize(1);
    }

    @Test
    @DisplayName("concurrent transfers allow only one debit and roll back the rejected transfer")
    void transfer_concurrentRequests_preservesBothBalancesAndAudit() throws Exception {
        User recipient = userRepository.saveAndFlush(User.builder()
                .email("recipient-" + UUID.randomUUID() + "@example.test")
                .passwordHash("$2a$12$integration-test-password-hash").build());
        UUID recipientWalletId = walletRepository.saveAndFlush(Wallet.builder()
                .user(recipient).currency(CurrencyCode.USD).balance(new BigDecimal("10.0000")).build()).getId();

        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            CompletableFuture<Boolean> first = CompletableFuture.supplyAsync(() -> attemptTransfer(start, recipientWalletId), executor);
            CompletableFuture<Boolean> second = CompletableFuture.supplyAsync(() -> attemptTransfer(start, recipientWalletId), executor);
            start.countDown();
            assertThat(first.get(20, TimeUnit.SECONDS) ^ second.get(20, TimeUnit.SECONDS)).isTrue();
        } finally {
            executor.shutdownNow();
        }

        assertThat(walletRepository.findById(walletId).orElseThrow().getBalance()).isEqualByComparingTo("20.0000");
        assertThat(walletRepository.findById(recipientWalletId).orElseThrow().getBalance()).isEqualByComparingTo("90.0000");
        assertThat(transactionRepository.findAll().stream()
                .filter(t -> t.getTransactionType() == TransactionType.TRANSFER)).hasSize(1)
                .allMatch(t -> t.getStatus() == TransactionStatus.COMPLETED);
        assertThat(historyCount(TransactionStatus.COMPLETED)).isEqualTo(2);
        assertThat(historyCount(TransactionStatus.FAILED)).isZero();
        assertThat(auditLogRepository.findAll().stream()
                .filter(a -> userId.equals(a.getUserId()))
                .filter(a -> a.getAction() == AuditAction.TRANSACTION_COMPLETE)).hasSize(1);
        assertThat(auditLogRepository.findAll().stream()
                .filter(a -> userId.equals(a.getUserId()))
                .filter(a -> a.getAction() == AuditAction.TRANSACTION_FAIL)).hasSize(1);
    }

    private boolean attemptTransfer(CountDownLatch start, UUID recipientWalletId) {
        try {
            if (!start.await(10, TimeUnit.SECONDS)) throw new AssertionError("Concurrent workers did not start");
            TransferRequest request = new TransferRequest();
            setField(request, "sourceWalletId", walletId);
            setField(request, "targetWalletId", recipientWalletId);
            setField(request, "amount", new BigDecimal("80.0000"));
            transactionService.transfer(userId, request);
            return true;
        } catch (InsufficientFundsException expected) {
            return false;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new AssertionError(interrupted);
        }
    }

    private int historyCount(TransactionStatus status) {
        return jdbcTemplate.queryForObject("""
                SELECT count(*) FROM transaction_history h JOIN transactions t ON t.id = h.transaction_id
                WHERE t.source_wallet_id = ? AND h.new_status = ?::transaction_status
                """, Integer.class, walletId, status.name());
    }

    private void setField(Object target, String name, Object value) {
        try {
            var field = target.getClass().getDeclaredField(name);
            field.setAccessible(true);
            field.set(target, value);
        } catch (ReflectiveOperationException exception) {
            throw new AssertionError(exception);
        }
    }

    private boolean attemptWithdrawal(CountDownLatch start, String amount) {
        try {
            if (!start.await(10, TimeUnit.SECONDS)) throw new AssertionError("Concurrent workers did not start");
            transactionService.withdraw(userId, withdraw(amount));
            return true;
        } catch (InsufficientFundsException expected) {
            return false;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new AssertionError(interrupted);
        }
    }

    private WithdrawRequest withdraw(String amount) {
        WithdrawRequest request = new WithdrawRequest();
        try {
            var currency = WithdrawRequest.class.getDeclaredField("currency");
            var value = WithdrawRequest.class.getDeclaredField("amount");
            currency.setAccessible(true); value.setAccessible(true);
            currency.set(request, CurrencyCode.USD); value.set(request, new BigDecimal(amount));
        } catch (ReflectiveOperationException exception) {
            throw new AssertionError(exception);
        }
        return request;
    }
}
