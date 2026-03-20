package com.wallet.secure.common.response;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for ApiResponse wrapper.
 * Verifies the standard response structure used across all endpoints.
 */
@DisplayName("ApiResponse")
class ApiResponseTest {

    @Test
    @DisplayName("ok() with data sets success=true and contains data")
    void ok_withData_setsSuccessAndData() {
        ApiResponse<String> response = ApiResponse.ok("Created", "test-data");

        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).isEqualTo("Created");
        assertThat(response.getData()).isEqualTo("test-data");
        assertThat(response.getTimestamp()).isNotNull();
    }

    @Test
    @DisplayName("ok() without data has null data field")
    void ok_withoutData_hasNullData() {
        ApiResponse<Void> response = ApiResponse.ok("Logged out");

        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getData()).isNull();
    }

    @Test
    @DisplayName("error() sets success=false and null data")
    void error_setsFailureAndNullData() {
        ApiResponse<Void> response = ApiResponse.error("Invalid credentials");

        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).isEqualTo("Invalid credentials");
        // OWASP A05: error responses must never carry data
        assertThat(response.getData()).isNull();
    }
}