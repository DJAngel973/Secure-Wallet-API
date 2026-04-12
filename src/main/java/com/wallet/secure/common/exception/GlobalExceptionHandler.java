package com.wallet.secure.common.exception;

import com.wallet.secure.common.response.ApiResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

/**
 * Global exception handler — catches ALL exceptions thrown anywhere in the app
 * and converts them into consistent ApiResponse format.
 *
 * WHY this exists:
 * Without this, Spring returns its own error format:
 * { "timestamp": "...", "status": 500, "error": "Internal Server Error", "path": "/users" }
 * That format is inconsistent with ApiResponse and may expose internal details.
 *
 * With this handler ALL errors follow the same contract:
 * { "success": false, "message": "...", "data": null, "timestamp": "..." }
 *
 * @RestControllerAdvice = @ControllerAdvice + @ResponseBody
 * Intercepts exceptions from ALL @RestController classes.
 * OWASP A05: never expose stack traces or internal error details to the client.
 */
@RestControllerAdvice
@Log4j2
public class GlobalExceptionHandler {

    // ─── Custom Business Exceptions ───────────────────────────────────────────

    /**
     * 404 — User not found.
     * Triggered by: UserService.findUserById() when user doesn't exist.
     */
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleUserNotFound(
            UserNotFoundException ex) {
        log.warn("UserNotFoundException: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.error(ex.getMessage()));
    }

    /**
     * 404 - Any resource not found (wallet, transaction, etc.)
     * Triggered by: WalletService, TransactionService when resource doesn't exist
     * or doesn't belong to the requesting user.
     * OWASP A01: same 404 response whether the resource doesn't exist
     * or belongs to another user - prevents enumeration
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleResourceNotFound(
            ResourceNotFoundException ex) {
        log.warn("ResourceNotFoundException: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.error(ex.getMessage()));
    }

    /**
     * 409 Conflict - Business rule violation.
     * Triggered by: WalletService when trying to create duplicate wallet,
     * suspend a non-ACTIVE wallet, close a wallet with balance, etc.
     */
    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ApiResponse<Void>> handleIlegalState(
            IllegalStateException ex) {
        log.warn("IlegalStateException: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(ApiResponse.error(ex.getMessage()));
    }

    /**
     * 409 — Email already registered.
     * Triggered by: UserService.register() and UserService.updateProfile().
     */
    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ApiResponse<Void>> handleEmailAlreadyExists(
            EmailAlreadyExistsException ex) {
        log.warn("EmailAlreadyExistsException: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(ApiResponse.error(ex.getMessage()));
    }

    /**
     * 401 — Invalid credentials (wrong password, invalid token).
     * Triggered by: UserService.updateProfile() on wrong currentPassword.
     * OWASP A07: same message regardless of whether user exists or password is wrong.
     */
    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiResponse<Void>> handleInvalidCredentials(
            InvalidCredentialsException ex) {
        log.warn("InvalidCredentialsException: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error(ex.getMessage()));
    }

    /**
     * 423 — Account locked after too many failed attempts.
     * Triggered by: AuthService (future) when failedLoginAttempts >= 3.
     * OWASP A07: brute force protection.
     */
    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccountLocked(
            AccountLockedException ex) {
        log.warn("AccountLockedException: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.LOCKED)
                .body(ApiResponse.error(ex.getMessage()));
    }

    /**
     * 403 — Authenticated but not authorized.
     * Triggered by: UserService when a user tries to modify another user's data.
     * OWASP A01: Broken Access Control prevention.
     */
    @ExceptionHandler(UnauthorizedOperationException.class)
    public ResponseEntity<ApiResponse<Void>> handleUnauthorizedOperation(
            UnauthorizedOperationException ex) {
        log.warn("UnauthorizedOperationException: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(ApiResponse.error(ex.getMessage()));
    }

    /**
     * 423 — Account locked by Spring Security (LockedException).
     * Thrown by Spring Security when UserDetails.isAccountLocked() = true.
     * OWASP A07: brute force protection.
     */
    @ExceptionHandler(org.springframework.security.authentication.LockedException.class)
    public ResponseEntity<ApiResponse<Void>> handleLocked(
            org.springframework.security.authentication.LockedException ex) {
        log.warn("Login attempt on locked account");
        return ResponseEntity
                .status(HttpStatus.LOCKED)
                .body(ApiResponse.error("Account temporarily locked. Try again later."));
    }

    /**
     * 401 — Bad credentials (wrong password or user not found).
     * Thrown by Spring Security AuthenticationManager.
     * OWASP A07: same message for "user not found" and "wrong password"
     *            to prevent user enumeration attacks.
     */
    @ExceptionHandler(org.springframework.security.authentication.BadCredentialsException.class)
    public ResponseEntity<ApiResponse<Void>> handleBadCredentials(
            org.springframework.security.authentication.BadCredentialsException ex) {
        log.warn("Failed login attempt — bad credentials");
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error("Invalid credentials"));
    }

    // ─── Validation Exceptions ────────────────────────────────────────────────

    /**
     * 400 — Bean Validation failed (@Valid on DTO fields).
     * Triggered by: @NotBlank, @Email, @Size, @Pattern violations in DTOs.
     *
     * Returns a map of field → error message so the frontend knows
     * exactly which field failed and why.
     *
     * Example response:
     * {
     *   "success": false,
     *   "message": "Validation failed",
     *   "data": {
     *     "email": "Email format is invalid",
     *     "password": "Password must contain uppercase..."
     *   }
     * }
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationErrors(
            MethodArgumentNotValidException ex) {

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult()
                .getAllErrors()
                .forEach(error -> {
                    String field = ((FieldError) error).getField();
                    String message = error.getDefaultMessage();
                    errors.put(field, message);
                });

        log.warn("Validation failed: {}", errors);
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error("Validation failed", errors));
    }

    // ─── Generic Fallback ─────────────────────────────────────────────────────

    /**
     * 500 — Unexpected exception not handled by any other handler.
     *
     * OWASP A05: NEVER expose the real exception message to the client.
     * The internal message is logged for debugging — client gets a generic message.
     *
     * This is the safety net — if a new exception is thrown and we forgot
     * to add a specific handler, this catches it.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGenericException(Exception ex) {
        // Full stack trace logged internally for debugging
        log.error("Unexpected error: {}", ex.getMessage(), ex);
        // Generic message to client — NEVER ex.getMessage() here
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error("An unexpected error occurred. Please try again later."));
    }
}
