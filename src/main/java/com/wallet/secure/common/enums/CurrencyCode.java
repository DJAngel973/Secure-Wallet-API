package com.wallet.secure.common.enums;

/**
 * Maps to PostgreSQL type: currency_code
 * DB definition: ENUM ('USD', 'EUR', 'COP', 'MXN', 'ARS')
 * Standard: ISO 4217
 *
 * WHY an enum and not a String:
 * Prevents invalid currency codes at compile time and DB level.
 * If a new currency is needed, it must be added here AND in the DB migration.
 * This forces a conscious, auditable decision — important for a financial app.
 */
public enum CurrencyCode {
    USD,  // US Dollar
    EUR,  // Euro
    COP,  // Colombian Peso
    MXN,  // Mexican Peso
    ARS   // Argentine Peso
}