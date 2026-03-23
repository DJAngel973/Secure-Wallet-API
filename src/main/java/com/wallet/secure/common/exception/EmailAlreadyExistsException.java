package com.wallet.secure.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Thrown when a registration or email change is attempted
 * with an email that already exists in the system.
 *
 * OWASP A07: message is intentionally vague to avoid email enumeration.
 * HTTP 409 Conflict — the resource already exists.
 */
@ResponseStatus(HttpStatus.CONFLICT)
public class EmailAlreadyExistsException extends RuntimeException {
    public EmailAlreadyExistsException(String message) {
        super(message);
    }
}
