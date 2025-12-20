package io.darkstrata.credentialcheck.exception;

/**
 * Exception thrown when the API returns an error response.
 */
public class ApiException extends DarkStrataException {

    private static final int[] RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504};

    private final String responseBody;

    public ApiException(String message, int statusCode) {
        this(message, statusCode, null, null);
    }

    public ApiException(String message, int statusCode, String responseBody) {
        this(message, statusCode, responseBody, null);
    }

    public ApiException(String message, int statusCode, String responseBody, Throwable cause) {
        super(message, ErrorCode.API_ERROR, statusCode, isRetryableStatusCode(statusCode), cause);
        this.responseBody = responseBody;
    }

    /**
     * Get the response body from the API, if available.
     */
    public String getResponseBody() {
        return responseBody;
    }

    private static boolean isRetryableStatusCode(int statusCode) {
        for (int retryable : RETRYABLE_STATUS_CODES) {
            if (statusCode == retryable) {
                return true;
            }
        }
        return false;
    }
}
