package io.darkstrata.credentialcheck;

/**
 * SDK constants and default configuration values.
 */
public final class Constants {

    private Constants() {
        // Utility class
    }

    // API Configuration
    public static final String DEFAULT_BASE_URL = "https://api.darkstrata.io/v1/";
    public static final String CREDENTIAL_CHECK_ENDPOINT = "credential-check/query";
    public static final String API_KEY_HEADER = "X-Api-Key";

    // SDK Info
    public static final String SDK_VERSION = "1.0.0";
    public static final String SDK_NAME = "darkstrata-credential-check-java";

    // Default Configuration
    public static final long DEFAULT_TIMEOUT = 30000; // 30 seconds
    public static final int DEFAULT_RETRIES = 3;
    public static final long DEFAULT_CACHE_TTL = 3600000; // 1 hour

    // Hash Configuration
    public static final int PREFIX_LENGTH = 5;
    public static final long TIME_WINDOW_SECONDS = 3600; // 1 hour

    // Retry Configuration
    public static final long RETRY_INITIAL_DELAY = 1000; // 1 second
    public static final long RETRY_MAX_DELAY = 10000; // 10 seconds
    public static final double RETRY_BACKOFF_MULTIPLIER = 2.0;

    // Retryable HTTP Status Codes
    public static final int[] RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504};

    // Response Headers
    public static final String HEADER_PREFIX = "X-Prefix";
    public static final String HEADER_HMAC_KEY = "X-HMAC-Key";
    public static final String HEADER_HMAC_SOURCE = "X-HMAC-Source";
    public static final String HEADER_TIME_WINDOW = "X-Time-Window";
    public static final String HEADER_TOTAL_RESULTS = "X-Total-Results";
    public static final String HEADER_FILTER_SINCE = "X-Filter-Since";
    public static final String HEADER_RETRY_AFTER = "Retry-After";
}
