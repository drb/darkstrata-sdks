package io.darkstrata.credentialcheck.exception;

/**
 * Exception thrown when a request times out.
 */
public class TimeoutException extends DarkStrataException {

    private final long timeoutMs;

    public TimeoutException(long timeoutMs) {
        this(timeoutMs, null);
    }

    public TimeoutException(long timeoutMs, Throwable cause) {
        super("Request timed out after " + timeoutMs + "ms", ErrorCode.TIMEOUT_ERROR, null, true, cause);
        this.timeoutMs = timeoutMs;
    }

    /**
     * Get the timeout duration in milliseconds.
     */
    public long getTimeoutMs() {
        return timeoutMs;
    }
}
