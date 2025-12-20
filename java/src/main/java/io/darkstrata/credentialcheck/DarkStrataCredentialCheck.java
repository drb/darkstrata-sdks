package io.darkstrata.credentialcheck;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.darkstrata.credentialcheck.exception.*;
import io.darkstrata.credentialcheck.internal.ApiResponse;
import io.darkstrata.credentialcheck.internal.ApiResponseHeaders;
import io.darkstrata.credentialcheck.internal.CacheEntry;
import okhttp3.*;

import java.io.Closeable;
import java.io.IOException;
import java.lang.reflect.Type;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/**
 * Client for checking credentials against the DarkStrata breach database.
 *
 * <p>This client uses k-anonymity to check credentials without exposing them.
 * Only the first 5 characters of a SHA-256 hash are sent to the API.</p>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * DarkStrataCredentialCheck client = new DarkStrataCredentialCheck(
 *     ClientOptions.builder("your-api-key").build()
 * );
 *
 * CheckResult result = client.check("user@example.com", "password123");
 * if (result.isFound()) {
 *     System.out.println("Credential found in breach database!");
 * }
 *
 * client.close();
 * }</pre>
 */
public class DarkStrataCredentialCheck implements Closeable {

    private final ClientOptions config;
    private final OkHttpClient httpClient;
    private final Gson gson;
    private final Map<String, CacheEntry> cache;
    private final ExecutorService executor;

    /**
     * Create a new DarkStrata client with the given options.
     *
     * @param options client configuration options
     * @throws ValidationException if the options are invalid
     */
    public DarkStrataCredentialCheck(ClientOptions options) throws ValidationException {
        validateOptions(options);
        this.config = options;
        this.gson = new Gson();
        this.cache = new ConcurrentHashMap<>();
        this.executor = Executors.newCachedThreadPool();

        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(options.getTimeout(), TimeUnit.MILLISECONDS)
                .readTimeout(options.getTimeout(), TimeUnit.MILLISECONDS)
                .writeTimeout(options.getTimeout(), TimeUnit.MILLISECONDS)
                .build();
    }

    /**
     * Check a single credential for exposure in data breaches.
     *
     * @param email    the email address
     * @param password the password
     * @return the check result
     * @throws DarkStrataException if an error occurs
     */
    public CheckResult check(String email, String password) throws DarkStrataException {
        return check(email, password, null);
    }

    /**
     * Check a single credential for exposure in data breaches.
     *
     * @param email    the email address
     * @param password the password
     * @param options  optional check options
     * @return the check result
     * @throws DarkStrataException if an error occurs
     */
    public CheckResult check(String email, String password, CheckOptions options) throws DarkStrataException {
        validateCredential(email, password);

        String hash = CryptoUtils.hashCredential(email, password);
        String prefix = CryptoUtils.extractPrefix(hash);

        ApiResponse response = fetchWithRetry(prefix, options);
        boolean found = CryptoUtils.isHashInSet(hash, response.getHeaders().getHmacKey(), response.getHashes());

        return buildResult(found, email, prefix, response, false);
    }

    /**
     * Check a pre-computed SHA-256 hash for exposure.
     *
     * @param hash the SHA-256 hash (64 hex characters)
     * @return the check result
     * @throws DarkStrataException if an error occurs
     */
    public CheckResult checkHash(String hash) throws DarkStrataException {
        return checkHash(hash, null);
    }

    /**
     * Check a pre-computed SHA-256 hash for exposure.
     *
     * @param hash    the SHA-256 hash (64 hex characters)
     * @param options optional check options
     * @return the check result
     * @throws DarkStrataException if an error occurs
     */
    public CheckResult checkHash(String hash, CheckOptions options) throws DarkStrataException {
        validateHash(hash);

        String normalizedHash = hash.toUpperCase(Locale.ROOT);
        String prefix = CryptoUtils.extractPrefix(normalizedHash);

        ApiResponse response = fetchWithRetry(prefix, options);
        boolean found = CryptoUtils.isHashInSet(normalizedHash, response.getHeaders().getHmacKey(), response.getHashes());

        return buildResult(found, "[hash-only]", prefix, response, false);
    }

    /**
     * Check multiple credentials efficiently using batch processing.
     *
     * @param credentials list of credentials to check
     * @return list of check results in the same order as input
     * @throws DarkStrataException if an error occurs
     */
    public List<CheckResult> checkBatch(List<Credential> credentials) throws DarkStrataException {
        return checkBatch(credentials, null);
    }

    /**
     * Check multiple credentials efficiently using batch processing.
     *
     * @param credentials list of credentials to check
     * @param options     optional check options
     * @return list of check results in the same order as input
     * @throws DarkStrataException if an error occurs
     */
    public List<CheckResult> checkBatch(List<Credential> credentials, CheckOptions options) throws DarkStrataException {
        if (credentials == null || credentials.isEmpty()) {
            return Collections.emptyList();
        }

        // Validate all credentials first
        for (Credential cred : credentials) {
            validateCredential(cred.getEmail(), cred.getPassword());
        }

        // Hash all credentials and group by prefix
        List<HashedCredential> hashedCredentials = new ArrayList<>();
        for (int i = 0; i < credentials.size(); i++) {
            Credential cred = credentials.get(i);
            String hash = CryptoUtils.hashCredential(cred.getEmail(), cred.getPassword());
            hashedCredentials.add(new HashedCredential(i, cred.getEmail(), hash));
        }

        Map<String, List<HashedCredential>> grouped = CryptoUtils.groupByPrefix(
                hashedCredentials,
                HashedCredential::getHash
        );

        // Fetch all prefixes in parallel
        Map<String, ApiResponse> responses = new ConcurrentHashMap<>();
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        for (String prefix : grouped.keySet()) {
            CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                try {
                    ApiResponse response = fetchWithRetry(prefix, options);
                    responses.put(prefix, response);
                } catch (DarkStrataException e) {
                    throw new CompletionException(e);
                }
            }, executor);
            futures.add(future);
        }

        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        } catch (CompletionException e) {
            if (e.getCause() instanceof DarkStrataException) {
                throw (DarkStrataException) e.getCause();
            }
            throw new NetworkException("Batch check failed", e.getCause());
        }

        // Build results in original order
        CheckResult[] results = new CheckResult[credentials.size()];
        for (HashedCredential hc : hashedCredentials) {
            String prefix = CryptoUtils.extractPrefix(hc.getHash());
            ApiResponse response = responses.get(prefix);
            boolean found = CryptoUtils.isHashInSet(hc.getHash(), response.getHeaders().getHmacKey(), response.getHashes());
            results[hc.getIndex()] = buildResult(found, hc.getEmail(), prefix, response, false);
        }

        return Arrays.asList(results);
    }

    /**
     * Check a single credential asynchronously.
     *
     * @param email    the email address
     * @param password the password
     * @return a future with the check result
     */
    public CompletableFuture<CheckResult> checkAsync(String email, String password) {
        return checkAsync(email, password, null);
    }

    /**
     * Check a single credential asynchronously.
     *
     * @param email    the email address
     * @param password the password
     * @param options  optional check options
     * @return a future with the check result
     */
    public CompletableFuture<CheckResult> checkAsync(String email, String password, CheckOptions options) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return check(email, password, options);
            } catch (DarkStrataException e) {
                throw new CompletionException(e);
            }
        }, executor);
    }

    /**
     * Clear the internal cache.
     */
    public void clearCache() {
        cache.clear();
    }

    /**
     * Get the current number of entries in the cache.
     */
    public int getCacheSize() {
        return cache.size();
    }

    /**
     * Close the client and release resources.
     */
    @Override
    public void close() {
        executor.shutdown();
        httpClient.dispatcher().executorService().shutdown();
        httpClient.connectionPool().evictAll();
    }

    // Private helper methods

    private void validateOptions(ClientOptions options) throws ValidationException {
        if (options == null) {
            throw new ValidationException("Options cannot be null");
        }
        if (options.getApiKey() == null || options.getApiKey().trim().isEmpty()) {
            throw new ValidationException("API key is required", "apiKey");
        }
        if (options.getTimeout() <= 0) {
            throw new ValidationException("Timeout must be positive", "timeout");
        }
        if (options.getRetries() < 0) {
            throw new ValidationException("Retries must be non-negative", "retries");
        }
        if (options.getCacheTTL() <= 0) {
            throw new ValidationException("Cache TTL must be positive", "cacheTTL");
        }
    }

    private void validateCredential(String email, String password) throws ValidationException {
        if (email == null || email.isEmpty()) {
            throw new ValidationException("Email is required", "email");
        }
        if (password == null || password.isEmpty()) {
            throw new ValidationException("Password is required", "password");
        }
    }

    private void validateHash(String hash) throws ValidationException {
        if (hash == null || hash.isEmpty()) {
            throw new ValidationException("Hash is required", "hash");
        }
        if (!CryptoUtils.isValidHash(hash)) {
            throw new ValidationException("Hash must be 64 hexadecimal characters", "hash");
        }
    }

    private ApiResponse fetchWithRetry(String prefix, CheckOptions options) throws DarkStrataException {
        // Check cache first
        if (config.isEnableCaching() && (options == null || (options.getClientHmac() == null && options.getSince() == null))) {
            long currentTimeWindow = getCurrentTimeWindow();
            String cacheKey = prefix + ":" + currentTimeWindow;
            CacheEntry cached = cache.get(cacheKey);

            if (cached != null && !cached.isExpired(currentTimeWindow, config.getCacheTTL())) {
                // Return cached response with cachedResult flag
                return cached.getResponse();
            }
        }

        // Retry logic with exponential backoff
        long delay = Constants.RETRY_INITIAL_DELAY;
        DarkStrataException lastError = null;

        for (int attempt = 0; attempt <= config.getRetries(); attempt++) {
            try {
                ApiResponse response = doFetch(prefix, options);

                // Cache the response if appropriate
                if (config.isEnableCaching() && (options == null || (options.getClientHmac() == null && options.getSince() == null))) {
                    Long timeWindow = response.getHeaders().getTimeWindow();
                    if (timeWindow != null) {
                        String cacheKey = prefix + ":" + timeWindow;
                        cache.put(cacheKey, new CacheEntry(response, timeWindow));
                        pruneCache();
                    }
                }

                return response;
            } catch (DarkStrataException e) {
                lastError = e;

                if (!e.isRetryable() || attempt == config.getRetries()) {
                    throw e;
                }

                try {
                    Thread.sleep(delay);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new NetworkException("Request interrupted", ie);
                }

                delay = Math.min((long) (delay * Constants.RETRY_BACKOFF_MULTIPLIER), Constants.RETRY_MAX_DELAY);
            }
        }

        throw lastError != null ? lastError : new NetworkException("Request failed after retries");
    }

    private ApiResponse doFetch(String prefix, CheckOptions options) throws DarkStrataException {
        HttpUrl.Builder urlBuilder = HttpUrl.parse(config.getBaseUrl() + Constants.CREDENTIAL_CHECK_ENDPOINT)
                .newBuilder()
                .addQueryParameter("prefix", prefix);

        if (options != null) {
            if (options.getClientHmac() != null) {
                urlBuilder.addQueryParameter("clientHmac", options.getClientHmac());
            }
            if (options.getSince() != null) {
                urlBuilder.addQueryParameter("since", options.getSince().toString());
            }
        }

        Request request = new Request.Builder()
                .url(urlBuilder.build())
                .header(Constants.API_KEY_HEADER, config.getApiKey())
                .header("User-Agent", Constants.SDK_NAME + "/" + Constants.SDK_VERSION)
                .header("Accept", "application/json")
                .get()
                .build();

        try {
            Response response = httpClient.newCall(request).execute();

            try (ResponseBody body = response.body()) {
                int statusCode = response.code();

                if (statusCode == 401) {
                    throw new AuthenticationException();
                }

                if (statusCode == 429) {
                    String retryAfterHeader = response.header(Constants.HEADER_RETRY_AFTER);
                    Integer retryAfter = null;
                    if (retryAfterHeader != null) {
                        try {
                            retryAfter = Integer.parseInt(retryAfterHeader);
                        } catch (NumberFormatException ignored) {
                        }
                    }
                    throw new RateLimitException(retryAfter);
                }

                if (statusCode >= 400) {
                    String responseBody = body != null ? body.string() : null;
                    throw new ApiException("API error: " + statusCode, statusCode, responseBody);
                }

                // Parse response
                String responseText = body != null ? body.string() : "[]";
                Type listType = new TypeToken<List<String>>() {}.getType();
                List<String> hashes = gson.fromJson(responseText, listType);

                // Parse headers
                ApiResponseHeaders headers = parseHeaders(response);

                return new ApiResponse(hashes != null ? hashes : Collections.emptyList(), headers);
            }
        } catch (java.net.SocketTimeoutException e) {
            throw new TimeoutException(config.getTimeout(), e);
        } catch (IOException e) {
            throw new NetworkException("Network error: " + e.getMessage(), e);
        }
    }

    private ApiResponseHeaders parseHeaders(Response response) {
        String prefix = response.header(Constants.HEADER_PREFIX, "");
        String hmacKey = response.header(Constants.HEADER_HMAC_KEY, "");

        String hmacSourceStr = response.header(Constants.HEADER_HMAC_SOURCE, "server");
        HmacSource hmacSource = "client".equalsIgnoreCase(hmacSourceStr) ? HmacSource.CLIENT : HmacSource.SERVER;

        Long timeWindow = null;
        String timeWindowStr = response.header(Constants.HEADER_TIME_WINDOW);
        if (timeWindowStr != null) {
            try {
                timeWindow = Long.parseLong(timeWindowStr);
            } catch (NumberFormatException ignored) {
            }
        }

        int totalResults = 0;
        String totalResultsStr = response.header(Constants.HEADER_TOTAL_RESULTS);
        if (totalResultsStr != null) {
            try {
                totalResults = Integer.parseInt(totalResultsStr);
            } catch (NumberFormatException ignored) {
            }
        }

        Long filterSince = null;
        String filterSinceStr = response.header(Constants.HEADER_FILTER_SINCE);
        if (filterSinceStr != null) {
            try {
                filterSince = Long.parseLong(filterSinceStr);
            } catch (NumberFormatException ignored) {
            }
        }

        return new ApiResponseHeaders(prefix, hmacKey, hmacSource, timeWindow, totalResults, filterSince);
    }

    private CheckResult buildResult(boolean found, String email, String prefix, ApiResponse response, boolean cached) {
        ApiResponseHeaders headers = response.getHeaders();

        CheckMetadata metadata = CheckMetadata.builder()
                .prefix(prefix)
                .totalResults(headers.getTotalResults())
                .hmacSource(headers.getHmacSource())
                .timeWindow(headers.getTimeWindow())
                .filterSince(headers.getFilterSince())
                .cachedResult(cached)
                .checkedAt(Instant.now())
                .build();

        return CheckResult.builder()
                .found(found)
                .credential(new CredentialInfo(email))
                .metadata(metadata)
                .build();
    }

    private long getCurrentTimeWindow() {
        return System.currentTimeMillis() / 1000 / Constants.TIME_WINDOW_SECONDS;
    }

    private void pruneCache() {
        long currentTimeWindow = getCurrentTimeWindow();
        cache.entrySet().removeIf(entry ->
                entry.getValue().isExpired(currentTimeWindow, config.getCacheTTL())
        );
    }

    /**
     * Internal class to track hashed credentials with their original index.
     */
    private static class HashedCredential {
        private final int index;
        private final String email;
        private final String hash;

        HashedCredential(int index, String email, String hash) {
            this.index = index;
            this.email = email;
            this.hash = hash;
        }

        int getIndex() {
            return index;
        }

        String getEmail() {
            return email;
        }

        String getHash() {
            return hash;
        }
    }
}
