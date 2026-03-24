package com.wallet.secure.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Thrown when credentials (password, token) are invalid.
 *
 * OWASP A07: always use the same message regardless of whether
 * the user doesn't exist or the password is wrong.
 * Prevents user enumeration attacks.
 * HTTP 401 Unauthorized.
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException(String message) {
        super(message);
    }
}