package com.wallet.secure.wallet.entity;

import com.wallet.secure.common.enums.CurrencyCode;
import com.wallet.secure.common.enums.WalletStatus;
import com.wallet.secure.user.entity.User;
import jakarta.persistence.*;
import lombok.*;
import org.apache.tomcat.util.bcel.classfile.EnumElementValue;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * Represents a digital wallet - one per user per currency
 * DB constraints already enforced at DB level:
 * - balance >= 0  (CHECK constraint)
 * - UNIQUE (user_id, currency) - one wallet per currency per user
 * - ON DELETE CASCADE - if user is deleted, wallets are deleted
 *
 * Financial precision:
 * DECIMAL(19,4) - up to 15 whole digits + 4 decimal places.
 * Why BigDecimal and not double:
 * double has floating-point precision errors.
 * 0.1 + 0.2 = 0.30000000000000004 in double.
 * BigDecimal is exact - mandatory for financial systems
 * NEVER use float or double for money
 */
@Entity
@Table(name = "wallets")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Wallet {

    // --- Identity

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    // --- Ownership

    /**
     * The user who owns this wallet
     * ManyToOne - one user can have multiple wallets (one per currency)
     * FetchType.LAZY - user is NOT loaded unless explicitly accessed
     * Why LAZY: loading the full User on every wallet query is wasteful
     * We only need user_id for most operations
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // --- Financial Data

    /**
     * Current balance - DECIMAL(19,4) in DB
     * BigDecimal in Java - exact arithmetic, no floating-point errors
     * OWASP: balance is NEVER modified directly here - only via
     * TransactionService which uses DB-level locking (FOR UPDATE)
     * Default 0 matches DB DEFAULT 0
     */
    @Column(name = "balance", nullable = false, precision = 19, scale = 4)
    @Builder.Default
    private BigDecimal balance = BigDecimal.ZERO;

    /**
     * Currency of this wallet - maps to PostgreSQL ENUM currency_code
     * USD, EUR, COP, MXN, ARS
     * A user can have one wallet per currency - enforced by DB UNIQUE constraint
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "currency", nullable = false, length = 10)
    private CurrencyCode currency;

    // --- Status

    /**
     * Wallet operation status
     * ACTIVE  - normal operation, can send/receive funds
     * SUSPENDED - temporarily blocked, no transactions allowed
     * CLOSED - permanently closed, no transactions allowed
     * Status transitions:
     * ACTIVE -> SUSPENDED (admin action or fraud detection)
     * SUSPENDED -> ACTIVE (admin restores)
     * ACTIVE/SUSPENDED -> CLOSED (user request or admin - irreversible)
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    @Builder.Default
    private WalletStatus status = WalletStatus.ACTIVE;

    // --- Audit Timestamps

    @CreatedDate
    @Column(name = "created_at",nullable = false, updatable = false)
    private Instant createAt;

    @LastModifiedDate
    @Column(name = "update_at", nullable = false)
    private Instant updateAt;

    // --- Business Methods

    /**
     * Returns true if this wallet can participate in transactions
     * Used by TransactionService before processing any operation
     */
    public boolean isOperational() {
        return WalletStatus.ACTIVE.equals(this.status);
    }

    /**
     * Returns true if the wallet has enough balance for the given amount
     * Used by TransactionService for WITHDRAWAL and TRANSFER validation
     * BigDecimal.compareTo() - correct comparison for financial values
     * Never use .equals() for BigDecimal (0.10 != 0.1 with equals)
     */
    public boolean hasSufficientBalance(BigDecimal amount) {
        return this.balance.compareTo(amount) >= 0;
    }
}