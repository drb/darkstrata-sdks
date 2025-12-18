import {
  API_KEY_HEADER,
  CREDENTIAL_CHECK_ENDPOINT,
  DEFAULT_BASE_URL,
  DEFAULT_CACHE_TTL,
  DEFAULT_RETRIES,
  DEFAULT_TIMEOUT,
  RESPONSE_HEADERS,
  RETRYABLE_STATUS_CODES,
  RETRY_DEFAULTS,
  SDK_NAME,
  SDK_VERSION,
  TIME_WINDOW_SECONDS,
} from './constants.js';
import {
  hashCredential,
  extractPrefix,
  isHashInSet,
  isValidHash,
  isValidPrefix,
  groupByPrefix,
} from './crypto.js';
import {
  ApiError,
  AuthenticationError,
  DarkStrataError,
  NetworkError,
  RateLimitError,
  TimeoutError,
  ValidationError,
  isRetryableError,
} from './errors.js';
import type {
  ApiResponse,
  ApiResponseHeaders,
  CacheEntry,
  CheckMetadata,
  CheckResult,
  ClientOptions,
  Credential,
  ResolvedConfig,
} from './types.js';

/**
 * DarkStrata credential check client.
 *
 * This client allows you to check if credentials have been exposed in
 * data breaches using k-anonymity to protect the credentials being checked.
 *
 * @example
 * ```typescript
 * import { DarkStrataCredentialCheck } from '@darkstrata/credential-check';
 *
 * const client = new DarkStrataCredentialCheck({
 *   apiKey: 'your-api-key',
 * });
 *
 * const result = await client.check('user@example.com', 'password123');
 * if (result.found) {
 *   console.log('Credential found in breach database!');
 * }
 * ```
 */
export class DarkStrataCredentialCheck {
  private readonly config: ResolvedConfig;
  private readonly cache: Map<string, CacheEntry>;

  /**
   * Create a new DarkStrata credential check client.
   *
   * @param options - Client configuration options
   * @throws {ValidationError} If the API key is missing or invalid
   *
   * @example
   * ```typescript
   * const client = new DarkStrataCredentialCheck({
   *   apiKey: 'your-api-key',
   *   timeout: 60000, // 60 seconds
   *   enableCaching: true,
   * });
   * ```
   */
  constructor(options: ClientOptions) {
    this.validateOptions(options);

    this.config = {
      apiKey: options.apiKey,
      baseUrl: this.normaliseBaseUrl(options.baseUrl ?? DEFAULT_BASE_URL),
      timeout: options.timeout ?? DEFAULT_TIMEOUT,
      retries: options.retries ?? DEFAULT_RETRIES,
      enableCaching: options.enableCaching ?? true,
      cacheTTL: options.cacheTTL ?? DEFAULT_CACHE_TTL,
    };

    this.cache = new Map();
  }

  /**
   * Check if a credential has been exposed in a data breach.
   *
   * This method uses k-anonymity to protect the credential being checked.
   * Only the first 5 characters of the hash are sent to the server.
   *
   * @param email - The email address or username
   * @param password - The password to check
   * @returns A promise that resolves with the check result
   * @throws {ValidationError} If the email or password is empty
   * @throws {AuthenticationError} If the API key is invalid
   * @throws {ApiError} If the API request fails
   *
   * @example
   * ```typescript
   * const result = await client.check('user@example.com', 'password123');
   *
   * if (result.found) {
   *   console.log('This credential was found in a data breach!');
   *   console.log(`Checked at: ${result.metadata.checkedAt}`);
   * } else {
   *   console.log('Credential not found in known breaches.');
   * }
   * ```
   */
  async check(email: string, password: string): Promise<CheckResult> {
    this.validateCredential(email, password);

    const hash = hashCredential(email, password);
    return this.checkHashInternal(hash, email);
  }

  /**
   * Check if a pre-computed hash has been exposed in a data breach.
   *
   * Use this method if you've already computed the SHA-256 hash of
   * the credential (`email:password`).
   *
   * @param hash - The SHA-256 hash of `email:password` (64 hex characters)
   * @returns A promise that resolves with the check result
   * @throws {ValidationError} If the hash is invalid
   *
   * @example
   * ```typescript
   * // If you've already computed the hash
   * const hash = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8...';
   * const result = await client.checkHash(hash);
   * ```
   */
  async checkHash(hash: string): Promise<CheckResult> {
    const normalisedHash = hash.toUpperCase();

    if (!isValidHash(normalisedHash)) {
      throw new ValidationError(
        'Invalid hash format. Expected 64 hexadecimal characters.',
        'hash'
      );
    }

    return this.checkHashInternal(normalisedHash);
  }

  /**
   * Check multiple credentials in a single batch.
   *
   * Credentials are grouped by their hash prefix to minimise API calls.
   *
   * @param credentials - Array of credential objects to check
   * @returns A promise that resolves with an array of check results
   * @throws {ValidationError} If any credential is invalid
   *
   * @example
   * ```typescript
   * const results = await client.checkBatch([
   *   { email: 'user1@example.com', password: 'pass1' },
   *   { email: 'user2@example.com', password: 'pass2' },
   * ]);
   *
   * for (const result of results) {
   *   if (result.found) {
   *     console.log(`${result.credential.email} was compromised!`);
   *   }
   * }
   * ```
   */
  async checkBatch(credentials: Credential[]): Promise<CheckResult[]> {
    if (credentials.length === 0) {
      return [];
    }

    // Validate all credentials first
    for (const credential of credentials) {
      this.validateCredential(credential.email, credential.password);
    }

    // Hash all credentials and group by prefix
    const hashedCredentials = credentials.map((cred) => ({
      ...cred,
      hash: hashCredential(cred.email, cred.password),
    }));

    const groupedByPrefix = groupByPrefix(hashedCredentials);

    // Fetch data for each unique prefix
    const prefixResponses = new Map<string, ApiResponse>();
    const prefixPromises: Promise<void>[] = [];

    for (const prefix of groupedByPrefix.keys()) {
      prefixPromises.push(
        this.fetchPrefixData(prefix).then((response) => {
          prefixResponses.set(prefix, response);
        })
      );
    }

    await Promise.all(prefixPromises);

    // Check each credential against its prefix's response
    const results: CheckResult[] = [];

    for (const credential of hashedCredentials) {
      const prefix = extractPrefix(credential.hash);
      const response = prefixResponses.get(prefix);

      if (!response) {
        // This shouldn't happen, but handle gracefully
        results.push(
          this.createCheckResult(
            false,
            credential.email,
            {
              prefix,
              totalResults: 0,
              cachedResult: false,
              checkedAt: new Date(),
            }
          )
        );
        continue;
      }

      const found = isHashInSet(
        credential.hash,
        response.headers.hmacKey,
        response.hashes
      );

      results.push(
        this.createCheckResult(found, credential.email, {
          prefix,
          totalResults: response.headers.totalResults,
          timeWindow: response.headers.timeWindow,
          cachedResult: false, // Batch doesn't use caching for individual results
          checkedAt: new Date(),
        })
      );
    }

    return results;
  }

  /**
   * Clear the internal cache.
   *
   * @example
   * ```typescript
   * client.clearCache();
   * ```
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get the current cache size.
   *
   * @returns The number of entries in the cache
   */
  getCacheSize(): number {
    return this.cache.size;
  }

  // ============================================================
  // Private methods
  // ============================================================

  private async checkHashInternal(
    hash: string,
    email?: string
  ): Promise<CheckResult> {
    const prefix = extractPrefix(hash);
    const response = await this.fetchPrefixData(prefix);

    const found = isHashInSet(hash, response.headers.hmacKey, response.hashes);

    return this.createCheckResult(found, email, {
      prefix,
      totalResults: response.headers.totalResults,
      timeWindow: response.headers.timeWindow,
      cachedResult: false, // TODO: Track this properly
      checkedAt: new Date(),
    });
  }

  private async fetchPrefixData(prefix: string): Promise<ApiResponse> {
    // Check cache first
    if (this.config.enableCaching) {
      const cached = this.getCachedResponse(prefix);
      if (cached) {
        return cached;
      }
    }

    // Fetch from API
    const response = await this.fetchWithRetry(prefix);

    // Cache the response
    if (this.config.enableCaching && response.headers.timeWindow) {
      this.cacheResponse(prefix, response, response.headers.timeWindow);
    }

    return response;
  }

  private async fetchWithRetry(prefix: string): Promise<ApiResponse> {
    let lastError: Error | undefined;
    let delay: number = RETRY_DEFAULTS.INITIAL_DELAY;

    for (let attempt = 0; attempt <= this.config.retries; attempt++) {
      try {
        return await this.fetch(prefix);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        if (!isRetryableError(error) || attempt === this.config.retries) {
          throw error;
        }

        // Wait before retrying
        await this.sleep(delay);
        delay = Math.min(
          delay * RETRY_DEFAULTS.BACKOFF_MULTIPLIER,
          RETRY_DEFAULTS.MAX_DELAY
        );
      }
    }

    throw lastError ?? new Error('Unknown error during fetch');
  }

  private async fetch(prefix: string): Promise<ApiResponse> {
    if (!isValidPrefix(prefix)) {
      throw new ValidationError(`Invalid prefix: ${prefix}`, 'prefix');
    }

    const url = new URL(CREDENTIAL_CHECK_ENDPOINT, this.config.baseUrl);
    url.searchParams.set('prefix', prefix);

    const controller = new AbortController();
    const timeoutId = setTimeout(
      () => controller.abort(),
      this.config.timeout
    );

    try {
      const response = await fetch(url.toString(), {
        method: 'GET',
        headers: {
          [API_KEY_HEADER]: this.config.apiKey,
          'User-Agent': `${SDK_NAME}/${SDK_VERSION}`,
          Accept: 'application/json',
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      return await this.handleResponse(response);
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof DarkStrataError) {
        throw error;
      }

      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          throw new TimeoutError(this.config.timeout, error);
        }
        throw new NetworkError(error.message, error);
      }

      throw new NetworkError('Unknown network error', error);
    }
  }

  private async handleResponse(response: Response): Promise<ApiResponse> {
    if (response.status === 401) {
      throw new AuthenticationError();
    }

    if (response.status === 429) {
      const retryAfter = response.headers.get('Retry-After');
      throw new RateLimitError(
        retryAfter ? parseInt(retryAfter, 10) : undefined
      );
    }

    if (!response.ok) {
      const isRetryable = RETRYABLE_STATUS_CODES.includes(
        response.status as (typeof RETRYABLE_STATUS_CODES)[number]
      );

      let responseBody: unknown;
      try {
        responseBody = await response.json();
      } catch {
        responseBody = await response.text().catch(() => undefined);
      }

      throw new ApiError(
        `API request failed with status ${response.status}`,
        response.status,
        { responseBody, retryable: isRetryable }
      );
    }

    // Parse response headers
    const headers = this.parseResponseHeaders(response);

    // Parse response body
    const hashes = (await response.json()) as string[];

    return { hashes, headers };
  }

  private parseResponseHeaders(response: Response): ApiResponseHeaders {
    const prefix = response.headers.get(RESPONSE_HEADERS.PREFIX) ?? '';
    const hmacKey = response.headers.get(RESPONSE_HEADERS.HMAC_KEY) ?? '';
    const hmacSourceRaw = response.headers.get(RESPONSE_HEADERS.HMAC_SOURCE);
    const hmacSource: 'server' | 'client' =
      hmacSourceRaw === 'client' ? 'client' : 'server';
    const timeWindowRaw = response.headers.get(RESPONSE_HEADERS.TIME_WINDOW);
    const totalResultsRaw = response.headers.get(
      RESPONSE_HEADERS.TOTAL_RESULTS
    );
    const filterSinceRaw = response.headers.get(RESPONSE_HEADERS.FILTER_SINCE);

    return {
      prefix,
      hmacKey,
      hmacSource,
      timeWindow: timeWindowRaw ? parseInt(timeWindowRaw, 10) : undefined,
      totalResults: totalResultsRaw ? parseInt(totalResultsRaw, 10) : 0,
      filterSince: filterSinceRaw ? parseInt(filterSinceRaw, 10) : undefined,
    };
  }

  private getCachedResponse(prefix: string): ApiResponse | undefined {
    const currentTimeWindow = this.getCurrentTimeWindow();
    const cacheKey = `${prefix}:${currentTimeWindow}`;
    const entry = this.cache.get(cacheKey);

    if (!entry) {
      return undefined;
    }

    // Check if cache entry is still valid
    const now = Date.now();
    if (now - entry.createdAt > this.config.cacheTTL) {
      this.cache.delete(cacheKey);
      return undefined;
    }

    // Check if time window has changed
    if (entry.timeWindow !== currentTimeWindow) {
      this.cache.delete(cacheKey);
      return undefined;
    }

    return entry.response;
  }

  private cacheResponse(
    prefix: string,
    response: ApiResponse,
    timeWindow: number
  ): void {
    const cacheKey = `${prefix}:${timeWindow}`;
    this.cache.set(cacheKey, {
      response,
      timeWindow,
      createdAt: Date.now(),
    });

    // Clean up old cache entries
    this.pruneCache();
  }

  private pruneCache(): void {
    const currentTimeWindow = this.getCurrentTimeWindow();
    const now = Date.now();

    for (const [key, entry] of this.cache.entries()) {
      // Remove entries from old time windows
      if (entry.timeWindow !== currentTimeWindow) {
        this.cache.delete(key);
        continue;
      }

      // Remove expired entries
      if (now - entry.createdAt > this.config.cacheTTL) {
        this.cache.delete(key);
      }
    }
  }

  private getCurrentTimeWindow(): number {
    return Math.floor(Date.now() / 1000 / TIME_WINDOW_SECONDS);
  }

  private createCheckResult(
    found: boolean,
    email: string | undefined,
    metadata: CheckMetadata
  ): CheckResult {
    return {
      found,
      credential: {
        email: email ?? '[hash-only]',
        masked: true as const,
      },
      metadata,
    };
  }

  private validateOptions(options: ClientOptions): void {
    if (!options.apiKey || typeof options.apiKey !== 'string') {
      throw new ValidationError('API key is required', 'apiKey');
    }

    if (options.apiKey.trim().length === 0) {
      throw new ValidationError('API key cannot be empty', 'apiKey');
    }

    if (options.timeout !== undefined && options.timeout <= 0) {
      throw new ValidationError('Timeout must be a positive number', 'timeout');
    }

    if (options.retries !== undefined && options.retries < 0) {
      throw new ValidationError(
        'Retries must be a non-negative number',
        'retries'
      );
    }

    if (options.cacheTTL !== undefined && options.cacheTTL <= 0) {
      throw new ValidationError(
        'Cache TTL must be a positive number',
        'cacheTTL'
      );
    }
  }

  private validateCredential(email: string, password: string): void {
    if (!email || typeof email !== 'string' || email.trim().length === 0) {
      throw new ValidationError('Email is required', 'email');
    }

    if (
      !password ||
      typeof password !== 'string' ||
      password.length === 0
    ) {
      throw new ValidationError('Password is required', 'password');
    }
  }

  private normaliseBaseUrl(url: string): string {
    // Ensure URL ends with a slash
    return url.endsWith('/') ? url : `${url}/`;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
