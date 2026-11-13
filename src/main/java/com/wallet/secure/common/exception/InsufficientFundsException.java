package com.wallet.secure.common.exception;

/** Safe business error for a debit rejected because the available balance is insufficient. */
public class InsufficientFundsException extends RuntimeException {
    public InsufficientFundsException() {
        super("Insufficient balance");
    }
}
