/**
 * Default base URL for the DarkStrata API.
 */
export const DEFAULT_BASE_URL = 'https://api.darkstrata.io/v1/';

/**
 * Default request timeout in milliseconds (30 seconds).
 */
export const DEFAULT_TIMEOUT = 30000;

/**
 * Default number of retry attempts.
 */
export const DEFAULT_RETRIES = 3;

/**
 * Default cache TTL in milliseconds (1 hour).
 * Aligned with server HMAC time window.
 */
export const DEFAULT_CACHE_TTL = 3600000;

/**
 * Length of the hash prefix for k-anonymity queries.
 */
export const PREFIX_LENGTH = 5;

/**
 * Server time window duration in seconds (1 hour).
 * Used for HMAC key rotation.
 */
export const TIME_WINDOW_SECONDS = 3600;

/**
 * API endpoint path for credential checks.
 */
export const CREDENTIAL_CHECK_ENDPOINT = 'credential-check/query';

/**
 * HTTP header name for API key authentication.
 */
export const API_KEY_HEADER = 'X-Api-Key';

/**
 * Response header names from the API.
 */
export const RESPONSE_HEADERS = {
  PREFIX: 'X-Prefix',
  HMAC_KEY: 'X-HMAC-Key',
  HMAC_SOURCE: 'X-HMAC-Source',
  TIME_WINDOW: 'X-Time-Window',
  TOTAL_RESULTS: 'X-Total-Results',
  FILTER_SINCE: 'X-Filter-Since',
} as const;

/**
 * Retry configuration defaults.
 */
export const RETRY_DEFAULTS = {
  INITIAL_DELAY: 1000,
  MAX_DELAY: 10000,
  BACKOFF_MULTIPLIER: 2,
} as const;

/**
 * HTTP status codes that should trigger a retry.
 */
export const RETRYABLE_STATUS_CODES = [408, 429, 500, 502, 503, 504] as const;

/**
 * SDK version for user-agent headers.
 */
export const SDK_VERSION = '0.1.0';

/**
 * SDK name for user-agent headers.
 */
export const SDK_NAME = '@darkstrata/credential-check';
