package com.wallet.secure.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Thrown when any resource (wallet, transaction, etc.) is not found.
 * Why a generic ResourceNotFoundException instead of one per domain:
 * UserNotFoundException, WalletNotFoundException, TransactionNotFoundException...
 * -> Too many classes for the same behavior (404)
 * -> ResourceNotFoundException covers all domains with a single class
 * for compatibility with existing code in UserService.
 * The new domains (wallet,transaction) use ResourceNotFoundException.
 * OWASP A01: The message never reveals whether the resource doesn't exist
 * or whether it simply doesn't belong to the user asking the question.
 * HTTP 404 Not Found.
 */
@ResponseStatus(HttpStatus.NOT_FOUND)
public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String message) {
        super(message);
    }
}