package com.wallet.secure.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Thrown when a login is attempted on a locked account.
 *
 * OWASP A07: account lockout after MAX_FAILED_ATTEMPTS (3).
 * HTTP 423 Locked — communicates clearly to the client.
 */
@ResponseStatus(HttpStatus.LOCKED)
public class AccountLockedException extends RuntimeException {
    public AccountLockedException(String message) {
        super(message);
    }
}