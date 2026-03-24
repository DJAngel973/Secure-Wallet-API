package com.wallet.secure.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Thrown when an authenticated user tries to perform an action
 * they are not authorized for (e.g., modifying another user's profile).
 *
 * OWASP A01: Broken Access Control prevention.
 * HTTP 403 Forbidden — authenticated but not authorized.
 */
@ResponseStatus(HttpStatus.FORBIDDEN)
public class UnauthorizedOperationException extends RuntimeException {
    public UnauthorizedOperationException(String message) {
        super(message);
    }
}