package io.darkstrata.credentialcheck.exception;

/**
 * Exception thrown when rate limited by the API (429).
 */
public class RateLimitException extends DarkStrataException {

    private final Integer retryAfter;

    public RateLimitException() {
        this(null);
    }

    public RateLimitException(Integer retryAfter) {
        super(
            retryAfter != null
                ? "Rate limited. Retry after " + retryAfter + " seconds"
                : "Rate limited",
            ErrorCode.RATE_LIMIT_ERROR,
            429,
            true
        );
        this.retryAfter = retryAfter;
    }

    /**
     * Get the number of seconds to wait before retrying, if provided by the API.
     */
    public Integer getRetryAfter() {
        return retryAfter;
    }
}
