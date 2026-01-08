/**
 * Configuration options for the DarkStrata credential check client.
 */
export interface ClientOptions {
  /**
   * Your DarkStrata API key (JWT token).
   * Obtain this from your DarkStrata dashboard.
   */
  apiKey: string;

  /**
   * Base URL for the DarkStrata API.
   * @default 'https://api.darkstrata.io/v1/'
   */
  baseUrl?: string;

  /**
   * Request timeout in milliseconds.
   * @default 30000
   */
  timeout?: number;

  /**
   * Number of retry attempts for failed requests.
   * @default 3
   */
  retries?: number;

  /**
   * Enable in-memory caching of API responses.
   * Cache is automatically invalidated when the server time window changes.
   * @default true
   */
  enableCaching?: boolean;

  /**
   * Cache time-to-live in milliseconds.
   * Should align with server time window (1 hour).
   * @default 3600000
   */
  cacheTTL?: number;
}

/**
 * A credential pair to check.
 */
export interface Credential {
  /**
   * The email address or username.
   */
  email: string;

  /**
   * The password to check.
   */
  password: string;
}

/**
 * Options for individual credential check requests.
 */
export interface CheckOptions {
  /**
   * Client-provided HMAC key for deterministic results.
   *
   * When provided, results are consistent across requests (not time-windowed).
   * Must be a cryptographically strong hex string of at least 64 characters (256 bits).
   *
   * Use this when you need:
   * - Consistent results across multiple requests
   * - To avoid server-side HMAC key rotation
   * - Custom key management
   *
   * @example
   * ```typescript
   * // Generate a secure key (do this once and store securely)
   * const hmacKey = crypto.randomBytes(32).toString('hex');
   *
   * const result = await client.check(email, password, { clientHmac: hmacKey });
   * ```
   */
  clientHmac?: string;

  /**
   * Filter results to only include breaches from this date onwards.
   *
   * Accepts either:
   * - **Epoch day**: Days since 1 January 1970 (e.g., 19724 = 1 January 2024)
   * - **Unix timestamp**: Seconds since 1 January 1970 (auto-detected if > 100000)
   * - **Date object**: Will be converted to epoch day
   *
   * @example
   * ```typescript
   * // Only check breaches from 2024 onwards
   * const result = await client.check(email, password, {
   *   since: new Date('2024-01-01'),
   * });
   *
   * // Or using epoch day directly
   * const result = await client.check(email, password, { since: 19724 });
   * ```
   */
  since?: number | Date;
}

/**
 * Result of a credential check.
 */
export interface CheckResult {
  /**
   * Whether the credential was found in a data breach.
   * `true` means the credential has been compromised.
   */
  found: boolean;

  /**
   * Information about the credential that was checked.
   */
  credential: {
    /**
     * The email address that was checked.
     */
    email: string;

    /**
     * Always `true` - the password is never included in results.
     */
    masked: true;
  };

  /**
   * Additional metadata about the check.
   */
  metadata: CheckMetadata;
}

/**
 * Metadata returned with check results.
 */
export interface CheckMetadata {
  /**
   * The 5-character hash prefix used for the k-anonymity lookup.
   */
  prefix: string;

  /**
   * Total number of matching hashes returned by the API.
   */
  totalResults: number;

  /**
   * Source of the HMAC key used for this request.
   * - `'server'`: Server-generated key (rotates hourly)
   * - `'client'`: Client-provided key (deterministic)
   */
  hmacSource: 'server' | 'client';

  /**
   * Server time window (hour-based) for HMAC key rotation.
   * Only present when using server-generated HMAC.
   */
  timeWindow?: number | undefined;

  /**
   * The epoch day used for filtering (if `since` was provided).
   * Epoch day = days since 1 January 1970.
   */
  filterSince?: number | undefined;

  /**
   * Whether this result was served from cache.
   */
  cachedResult: boolean;

  /**
   * Timestamp when the check was performed.
   */
  checkedAt: Date;
}

/**
 * Raw API response from the k-anonymity endpoint.
 * @internal
 */
export interface ApiResponse {
  /**
   * Array of HMAC'd hash suffixes.
   */
  hashes: string[];

  /**
   * Response headers from the API.
   */
  headers: ApiResponseHeaders;
}

/**
 * Response headers from the k-anonymity API.
 * @internal
 */
export interface ApiResponseHeaders {
  /**
   * The normalised prefix that was queried.
   */
  prefix: string;

  /**
   * The HMAC key used to encode the results.
   */
  hmacKey: string;

  /**
   * Source of the HMAC key ('server' or 'client').
   */
  hmacSource: 'server' | 'client';

  /**
   * Server time window (only present for server-generated HMAC).
   */
  timeWindow?: number | undefined;

  /**
   * Total number of results.
   */
  totalResults: number;

  /**
   * Filter epoch day (if since parameter was used).
   */
  filterSince?: number | undefined;
}

/**
 * Retry policy configuration.
 */
export interface RetryPolicy {
  /**
   * Maximum number of retry attempts.
   * @default 3
   */
  maxRetries: number;

  /**
   * Initial delay between retries in milliseconds.
   * @default 1000
   */
  initialDelay: number;

  /**
   * Maximum delay between retries in milliseconds.
   * @default 10000
   */
  maxDelay: number;

  /**
   * Multiplier for exponential backoff.
   * @default 2
   */
  backoffMultiplier: number;
}

/**
 * Cache entry structure.
 * @internal
 */
export interface CacheEntry {
  /**
   * Cached API response.
   */
  response: ApiResponse;

  /**
   * Time window when this entry was cached.
   */
  timeWindow: number;

  /**
   * Timestamp when this entry was created.
   */
  createdAt: number;
}

/**
 * Internal resolved configuration with all defaults applied.
 * @internal
 */
export interface ResolvedConfig {
  apiKey: string;
  baseUrl: string;
  timeout: number;
  retries: number;
  enableCaching: boolean;
  cacheTTL: number;
}
