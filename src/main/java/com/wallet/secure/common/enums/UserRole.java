package com.wallet.secure.common.enums;

/**
 * Maps to PostgreSQL type: user_role
 * DB definition: ENUM ('USER', 'ADMIN', 'MANAGER')
 *
 * OWASP A01 - Broken Access Control:
 * Role-based access control. Every endpoint is restricted by role.
 *
 * USER    → standard customer, accesses only their own wallet
 * MANAGER → operational support, can view reports and manage users
 * ADMIN   → full system access including audit logs
 *
 * NOTE: No "ROLE_" prefix here — the prefix is added by Spring Security
 * automatically when reading from the database via UserDetails.
 * In @PreAuthorize use hasRole('ADMIN'), not hasRole('ROLE_ADMIN').
 */
public enum UserRole {
    USER,
    MANAGER,
    ADMIN
}