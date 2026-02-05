package io.darkstrata.credentialcheck.exception;

/**
 * Base exception for all DarkStrata SDK errors.
 */
public class DarkStrataException extends Exception {

    private final ErrorCode code;
    private final Integer statusCode;
    private final boolean retryable;

    public DarkStrataException(String message, ErrorCode code) {
        this(message, code, null, false, null);
    }

    public DarkStrataException(String message, ErrorCode code, Integer statusCode, boolean retryable) {
        this(message, code, statusCode, retryable, null);
    }

    public DarkStrataException(String message, ErrorCode code, Integer statusCode, boolean retryable, Throwable cause) {
        super(message, cause);
        this.code = code;
        this.statusCode = statusCode;
        this.retryable = retryable;
    }

    /**
     * Get the error code for this exception.
     */
    public ErrorCode getCode() {
        return code;
    }

    /**
     * Get the HTTP status code, if applicable.
     */
    public Integer getStatusCode() {
        return statusCode;
    }

    /**
     * Check if the operation that caused this exception can be retried.
     */
    public boolean isRetryable() {
        return retryable;
    }

    /**
     * Check if an exception is a DarkStrata exception.
     */
    public static boolean isDarkStrataException(Throwable error) {
        return error instanceof DarkStrataException;
    }

    /**
     * Check if an exception is retryable.
     */
    public static boolean isRetryableError(Throwable error) {
        if (error instanceof DarkStrataException) {
            return ((DarkStrataException) error).isRetryable();
        }
        return false;
    }
}
