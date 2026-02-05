package io.darkstrata.credentialcheck;

import io.darkstrata.credentialcheck.exception.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Exception Tests")
class ExceptionTest {

    @Test
    @DisplayName("DarkStrataException has correct properties")
    void darkStrataExceptionHasCorrectProperties() {
        DarkStrataException ex = new DarkStrataException(
                "Test error",
                ErrorCode.API_ERROR,
                500,
                true
        );

        assertEquals("Test error", ex.getMessage());
        assertEquals(ErrorCode.API_ERROR, ex.getCode());
        assertEquals(500, ex.getStatusCode());
        assertTrue(ex.isRetryable());
    }

    @Test
    @DisplayName("AuthenticationException is not retryable")
    void authenticationExceptionIsNotRetryable() {
        AuthenticationException ex = new AuthenticationException();

        assertEquals(ErrorCode.AUTHENTICATION_ERROR, ex.getCode());
        assertEquals(401, ex.getStatusCode());
        assertFalse(ex.isRetryable());
    }

    @Test
    @DisplayName("ValidationException has field information")
    void validationExceptionHasFieldInformation() {
        ValidationException ex = new ValidationException("Invalid email", "email");

        assertEquals(ErrorCode.VALIDATION_ERROR, ex.getCode());
        assertEquals("email", ex.getField());
        assertFalse(ex.isRetryable());
        assertNull(ex.getStatusCode());
    }

    @Test
    @DisplayName("ApiException determines retryability by status code")
    void apiExceptionDeterminesRetryabilityByStatusCode() {
        ApiException retryable = new ApiException("Server error", 503);
        ApiException notRetryable = new ApiException("Bad request", 400);

        assertTrue(retryable.isRetryable());
        assertFalse(notRetryable.isRetryable());
    }

    @Test
    @DisplayName("ApiException includes response body")
    void apiExceptionIncludesResponseBody() {
        ApiException ex = new ApiException("Error", 500, "{\"error\": \"internal\"}");

        assertEquals("{\"error\": \"internal\"}", ex.getResponseBody());
    }

    @Test
    @DisplayName("TimeoutException is retryable")
    void timeoutExceptionIsRetryable() {
        TimeoutException ex = new TimeoutException(30000);

        assertEquals(ErrorCode.TIMEOUT_ERROR, ex.getCode());
        assertEquals(30000, ex.getTimeoutMs());
        assertTrue(ex.isRetryable());
    }

    @Test
    @DisplayName("NetworkException is retryable")
    void networkExceptionIsRetryable() {
        NetworkException ex = new NetworkException("Connection refused");

        assertEquals(ErrorCode.NETWORK_ERROR, ex.getCode());
        assertTrue(ex.isRetryable());
    }

    @Test
    @DisplayName("RateLimitException includes retry-after")
    void rateLimitExceptionIncludesRetryAfter() {
        RateLimitException ex = new RateLimitException(60);

        assertEquals(ErrorCode.RATE_LIMIT_ERROR, ex.getCode());
        assertEquals(429, ex.getStatusCode());
        assertEquals(60, ex.getRetryAfter());
        assertTrue(ex.isRetryable());
    }

    @Test
    @DisplayName("isDarkStrataException identifies correct types")
    void isDarkStrataExceptionIdentifiesCorrectTypes() {
        assertTrue(DarkStrataException.isDarkStrataException(new AuthenticationException()));
        assertTrue(DarkStrataException.isDarkStrataException(new ValidationException("test")));
        assertFalse(DarkStrataException.isDarkStrataException(new RuntimeException()));
        assertFalse(DarkStrataException.isDarkStrataException(null));
    }

    @Test
    @DisplayName("isRetryableError checks retryability")
    void isRetryableErrorChecksRetryability() {
        assertTrue(DarkStrataException.isRetryableError(new TimeoutException(1000)));
        assertTrue(DarkStrataException.isRetryableError(new NetworkException("error")));
        assertTrue(DarkStrataException.isRetryableError(new RateLimitException()));
        assertFalse(DarkStrataException.isRetryableError(new AuthenticationException()));
        assertFalse(DarkStrataException.isRetryableError(new ValidationException("test")));
        assertFalse(DarkStrataException.isRetryableError(new RuntimeException()));
    }
}
