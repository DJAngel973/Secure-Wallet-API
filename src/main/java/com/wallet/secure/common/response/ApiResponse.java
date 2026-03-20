package com.wallet.secure.common.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import java.time.Instant;

/**
 * Standard API response wrapper for all endpoints.
 * WHY: Consistent response structure across the entire API.
 * Clients always know what to expect: success flag, message, data, timestamp.
 * OWASP A05: Never expose internal error details — message is controlled here.
 */
@Getter
@JsonInclude(JsonInclude.Include.NON_NULL) // Don't serialize null fields
public class ApiResponse<T> {

    private final boolean success;
    private final String message;
    private final T data;
    private final Instant timestamp;

    // Private constructor — use static factory methods
    private ApiResponse(boolean success, String message, T data) {
        this.success = success;
        this.message = message;
        this.data = data;
        this.timestamp = Instant.now();
    }

    /** Successful response with data */
    public static <T> ApiResponse<T> ok(String message, T data) {
        return new ApiResponse<>(true, message, data);
    }

    /** Successful response without data (e.g., logout, delete) */
    public static <T> ApiResponse<T> ok(String message) {
        return new ApiResponse<>(true, message, null);
    }

    /** Error response — data is null intentionally */
    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<>(false, message, null);
    }
}