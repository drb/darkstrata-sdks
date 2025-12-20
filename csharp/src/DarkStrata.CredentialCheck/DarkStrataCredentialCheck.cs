using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DarkStrata.CredentialCheck;

/// <summary>
/// DarkStrata credential check client.
///
/// This client allows you to check if credentials have been exposed in
/// data breaches using k-anonymity to protect the credentials being checked.
/// </summary>
/// <example>
/// <code>
/// using var client = new DarkStrataCredentialCheck(new ClientOptions
/// {
///     ApiKey = "your-api-key"
/// });
///
/// var result = await client.CheckAsync("user@example.com", "password123");
/// if (result.Found)
/// {
///     Console.WriteLine("Credential found in breach database!");
/// }
/// </code>
/// </example>
public sealed partial class DarkStrataCredentialCheck : IDisposable
{
    private readonly ResolvedConfig _config;
    private readonly HttpClient _httpClient;
    private readonly Dictionary<string, CacheEntry> _cache = new();
    private readonly object _cacheLock = new();
    private bool _disposed;

    /// <summary>
    /// Create a new DarkStrata credential check client.
    /// </summary>
    /// <param name="options">Client configuration options.</param>
    /// <exception cref="ValidationException">If the API key is missing or invalid.</exception>
    public DarkStrataCredentialCheck(ClientOptions options)
    {
        ValidateOptions(options);

        _config = new ResolvedConfig
        {
            ApiKey = options.ApiKey,
            BaseUrl = NormalizeBaseUrl(options.BaseUrl ?? Constants.DefaultBaseUrl),
            Timeout = options.Timeout ?? Constants.DefaultTimeout,
            Retries = options.Retries ?? Constants.DefaultRetries,
            EnableCaching = options.EnableCaching ?? true,
            CacheTtl = options.CacheTtl ?? Constants.DefaultCacheTtl
        };

        _httpClient = new HttpClient
        {
            BaseAddress = new Uri(_config.BaseUrl),
            Timeout = _config.Timeout
        };

        _httpClient.DefaultRequestHeaders.Add(Constants.ApiKeyHeader, _config.ApiKey);
        _httpClient.DefaultRequestHeaders.UserAgent.Add(
            new ProductInfoHeaderValue(Constants.SdkName, Constants.SdkVersion));
        _httpClient.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
    }

    /// <summary>
    /// Check if a credential has been exposed in a data breach.
    ///
    /// This method uses k-anonymity to protect the credential being checked.
    /// Only the first 5 characters of the hash are sent to the server.
    /// </summary>
    /// <param name="email">The email address or username.</param>
    /// <param name="password">The password to check.</param>
    /// <param name="options">Optional check options (client HMAC, date filter).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The check result.</returns>
    /// <exception cref="ValidationException">If the email or password is empty.</exception>
    /// <exception cref="AuthenticationException">If the API key is invalid.</exception>
    /// <exception cref="ApiException">If the API request fails.</exception>
    public async Task<CheckResult> CheckAsync(
        string email,
        string password,
        CheckOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ValidateCredential(email, password);
        ValidateCheckOptions(options);

        var hash = CryptoUtils.HashCredential(email, password);
        return await CheckHashInternalAsync(hash, email, options, cancellationToken);
    }

    /// <summary>
    /// Check if a pre-computed hash has been exposed in a data breach.
    ///
    /// Use this method if you've already computed the SHA-256 hash of
    /// the credential ("email:password").
    /// </summary>
    /// <param name="hash">The SHA-256 hash of "email:password" (64 hex characters).</param>
    /// <param name="options">Optional check options (client HMAC, date filter).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The check result.</returns>
    /// <exception cref="ValidationException">If the hash is invalid.</exception>
    public async Task<CheckResult> CheckHashAsync(
        string hash,
        CheckOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var normalizedHash = hash.ToUpperInvariant();

        if (!CryptoUtils.IsValidHash(normalizedHash))
        {
            throw new ValidationException(
                "Invalid hash format. Expected 64 hexadecimal characters.",
                "hash");
        }

        ValidateCheckOptions(options);

        return await CheckHashInternalAsync(normalizedHash, null, options, cancellationToken);
    }

    /// <summary>
    /// Check multiple credentials in a single batch.
    ///
    /// Credentials are grouped by their hash prefix to minimize API calls.
    /// </summary>
    /// <param name="credentials">Collection of credential objects to check.</param>
    /// <param name="options">Optional check options applied to all credentials.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of check results in the same order as input.</returns>
    /// <exception cref="ValidationException">If any credential is invalid.</exception>
    public async Task<IReadOnlyList<CheckResult>> CheckBatchAsync(
        IEnumerable<Credential> credentials,
        CheckOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var credentialList = credentials.ToList();
        if (credentialList.Count == 0)
        {
            return [];
        }

        // Validate all credentials first
        foreach (var credential in credentialList)
        {
            ValidateCredential(credential.Email, credential.Password);
        }
        ValidateCheckOptions(options);

        // Hash all credentials and group by prefix
        var hashedCredentials = credentialList
            .Select(c => new HashedCredential(c.Email, c.Password, CryptoUtils.HashCredential(c.Email, c.Password)))
            .ToList();

        var groupedByPrefix = CryptoUtils.GroupByPrefix(hashedCredentials, hc => hc.Hash);

        // Fetch data for each unique prefix in parallel
        var prefixResponses = new Dictionary<string, ApiResponse>();
        var fetchTasks = groupedByPrefix.Keys
            .Select(async prefix =>
            {
                var response = await FetchPrefixDataAsync(prefix, options, cancellationToken);
                lock (prefixResponses)
                {
                    prefixResponses[prefix] = response;
                }
            });

        await Task.WhenAll(fetchTasks);

        // Check each credential against its prefix's response
        var results = new List<CheckResult>();

        foreach (var credential in hashedCredentials)
        {
            var prefix = CryptoUtils.ExtractPrefix(credential.Hash);

            if (!prefixResponses.TryGetValue(prefix, out var response))
            {
                // This shouldn't happen, but handle gracefully
                results.Add(CreateCheckResult(
                    found: false,
                    email: credential.Email,
                    metadata: new CheckMetadata
                    {
                        Prefix = prefix,
                        TotalResults = 0,
                        HmacSource = HmacSource.Server,
                        CachedResult = false,
                        CheckedAt = DateTimeOffset.UtcNow
                    }));
                continue;
            }

            var found = CryptoUtils.IsHashInSet(
                credential.Hash,
                response.Headers.HmacKey,
                response.Hashes);

            results.Add(CreateCheckResult(
                found,
                credential.Email,
                new CheckMetadata
                {
                    Prefix = prefix,
                    TotalResults = response.Headers.TotalResults,
                    HmacSource = response.Headers.HmacSource,
                    TimeWindow = response.Headers.TimeWindow,
                    FilterSince = response.Headers.FilterSince,
                    CachedResult = false,
                    CheckedAt = DateTimeOffset.UtcNow
                }));
        }

        return results;
    }

    /// <summary>
    /// Clear the internal cache.
    /// </summary>
    public void ClearCache()
    {
        lock (_cacheLock)
        {
            _cache.Clear();
        }
    }

    /// <summary>
    /// Get the current cache size.
    /// </summary>
    /// <returns>The number of entries in the cache.</returns>
    public int GetCacheSize()
    {
        lock (_cacheLock)
        {
            return _cache.Count;
        }
    }

    /// <summary>
    /// Dispose of the client and release resources.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _httpClient.Dispose();
            _disposed = true;
        }
    }

    // ============================================================
    // Private methods
    // ============================================================

    private async Task<CheckResult> CheckHashInternalAsync(
        string hash,
        string? email,
        CheckOptions? options,
        CancellationToken cancellationToken)
    {
        var prefix = CryptoUtils.ExtractPrefix(hash);
        var response = await FetchPrefixDataAsync(prefix, options, cancellationToken);

        var found = CryptoUtils.IsHashInSet(hash, response.Headers.HmacKey, response.Hashes);

        return CreateCheckResult(found, email, new CheckMetadata
        {
            Prefix = prefix,
            TotalResults = response.Headers.TotalResults,
            HmacSource = response.Headers.HmacSource,
            TimeWindow = response.Headers.TimeWindow,
            FilterSince = response.Headers.FilterSince,
            CachedResult = false,
            CheckedAt = DateTimeOffset.UtcNow
        });
    }

    private async Task<ApiResponse> FetchPrefixDataAsync(
        string prefix,
        CheckOptions? options,
        CancellationToken cancellationToken)
    {
        // Don't use cache when client provides custom options
        var useCache = _config.EnableCaching &&
                       string.IsNullOrEmpty(options?.ClientHmac) &&
                       options?.Since is null &&
                       options?.SinceEpochDay is null;

        // Check cache first
        if (useCache)
        {
            var cached = GetCachedResponse(prefix);
            if (cached is not null)
            {
                return cached;
            }
        }

        // Fetch from API
        var response = await FetchWithRetryAsync(prefix, options, cancellationToken);

        // Cache the response (only if no custom options and server HMAC)
        if (useCache && response.Headers.TimeWindow.HasValue)
        {
            CacheResponse(prefix, response, response.Headers.TimeWindow.Value);
        }

        return response;
    }

    private async Task<ApiResponse> FetchWithRetryAsync(
        string prefix,
        CheckOptions? options,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;
        var delay = Constants.RetryDefaults.InitialDelay;

        for (var attempt = 0; attempt <= _config.Retries; attempt++)
        {
            try
            {
                return await FetchAsync(prefix, options, cancellationToken);
            }
            catch (Exception ex) when (ex is DarkStrataException dse && dse.IsRetryable)
            {
                lastError = ex;

                if (attempt == _config.Retries)
                {
                    throw;
                }

                // Wait before retrying
                await Task.Delay(delay, cancellationToken);
                delay = TimeSpan.FromMilliseconds(
                    Math.Min(delay.TotalMilliseconds * Constants.RetryDefaults.BackoffMultiplier,
                             Constants.RetryDefaults.MaxDelay.TotalMilliseconds));
            }
            catch (Exception ex) when (ex is not DarkStrataException)
            {
                lastError = ex;

                if (attempt == _config.Retries)
                {
                    throw;
                }

                // For non-DarkStrata exceptions, only retry network errors
                if (ex is HttpRequestException or TaskCanceledException)
                {
                    await Task.Delay(delay, cancellationToken);
                    delay = TimeSpan.FromMilliseconds(
                        Math.Min(delay.TotalMilliseconds * Constants.RetryDefaults.BackoffMultiplier,
                                 Constants.RetryDefaults.MaxDelay.TotalMilliseconds));
                }
                else
                {
                    throw;
                }
            }
        }

        throw lastError ?? new InvalidOperationException("Unknown error during fetch");
    }

    private async Task<ApiResponse> FetchAsync(
        string prefix,
        CheckOptions? options,
        CancellationToken cancellationToken)
    {
        if (!CryptoUtils.IsValidPrefix(prefix))
        {
            throw new ValidationException($"Invalid prefix: {prefix}", "prefix");
        }

        var queryParams = new List<string> { $"prefix={prefix}" };

        // Add optional parameters
        if (!string.IsNullOrEmpty(options?.ClientHmac))
        {
            queryParams.Add($"clientHmac={options.ClientHmac}");
        }

        if (options?.SinceEpochDay.HasValue == true)
        {
            queryParams.Add($"since={options.SinceEpochDay.Value}");
        }
        else if (options?.Since.HasValue == true)
        {
            var epochDay = ConvertToEpochDay(options.Since.Value);
            queryParams.Add($"since={epochDay}");
        }

        var requestUri = $"{Constants.CredentialCheckEndpoint}?{string.Join("&", queryParams)}";

        try
        {
            using var response = await _httpClient.GetAsync(requestUri, cancellationToken);
            return await HandleResponseAsync(response);
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new DarkStrataTimeoutException((int)_config.Timeout.TotalMilliseconds, ex);
        }
        catch (HttpRequestException ex)
        {
            throw new NetworkException(ex.Message, ex);
        }
    }

    private async Task<ApiResponse> HandleResponseAsync(HttpResponseMessage response)
    {
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new AuthenticationException();
        }

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            int? retryAfter = null;
            if (response.Headers.TryGetValues("Retry-After", out var retryAfterValues))
            {
                if (int.TryParse(retryAfterValues.FirstOrDefault(), out var retryAfterValue))
                {
                    retryAfter = retryAfterValue;
                }
            }
            throw new RateLimitException(retryAfter);
        }

        if (!response.IsSuccessStatusCode)
        {
            var isRetryable = Constants.RetryableStatusCodes.Contains((int)response.StatusCode);
            string? responseBody = null;

            try
            {
                responseBody = await response.Content.ReadAsStringAsync();
            }
            catch
            {
                // Ignore
            }

            throw new ApiException(
                $"API request failed with status {(int)response.StatusCode}",
                (int)response.StatusCode,
                responseBody,
                isRetryable);
        }

        // Parse response headers
        var headers = ParseResponseHeaders(response);

        // Parse response body
        var content = await response.Content.ReadAsStringAsync();
        var hashes = JsonSerializer.Deserialize<string[]>(content) ?? [];

        return new ApiResponse(hashes, headers);
    }

    private static ApiResponseHeaders ParseResponseHeaders(HttpResponseMessage response)
    {
        var prefix = GetHeaderValue(response, Constants.ResponseHeaders.Prefix) ?? "";
        var hmacKey = GetHeaderValue(response, Constants.ResponseHeaders.HmacKey) ?? "";
        var hmacSourceRaw = GetHeaderValue(response, Constants.ResponseHeaders.HmacSource);
        var hmacSource = hmacSourceRaw == "client" ? HmacSource.Client : HmacSource.Server;
        var timeWindowRaw = GetHeaderValue(response, Constants.ResponseHeaders.TimeWindow);
        var totalResultsRaw = GetHeaderValue(response, Constants.ResponseHeaders.TotalResults);
        var filterSinceRaw = GetHeaderValue(response, Constants.ResponseHeaders.FilterSince);

        return new ApiResponseHeaders
        {
            Prefix = prefix,
            HmacKey = hmacKey,
            HmacSource = hmacSource,
            TimeWindow = timeWindowRaw is not null ? int.Parse(timeWindowRaw) : null,
            TotalResults = totalResultsRaw is not null ? int.Parse(totalResultsRaw) : 0,
            FilterSince = filterSinceRaw is not null ? int.Parse(filterSinceRaw) : null
        };
    }

    private static string? GetHeaderValue(HttpResponseMessage response, string headerName)
    {
        if (response.Headers.TryGetValues(headerName, out var values))
        {
            return values.FirstOrDefault();
        }
        return null;
    }

    private ApiResponse? GetCachedResponse(string prefix)
    {
        var currentTimeWindow = GetCurrentTimeWindow();
        var cacheKey = $"{prefix}:{currentTimeWindow}";

        lock (_cacheLock)
        {
            if (!_cache.TryGetValue(cacheKey, out var entry))
            {
                return null;
            }

            // Check if cache entry is still valid
            var now = DateTimeOffset.UtcNow;
            if (now - entry.CreatedAt > _config.CacheTtl)
            {
                _cache.Remove(cacheKey);
                return null;
            }

            // Check if time window has changed
            if (entry.TimeWindow != currentTimeWindow)
            {
                _cache.Remove(cacheKey);
                return null;
            }

            return entry.Response;
        }
    }

    private void CacheResponse(string prefix, ApiResponse response, int timeWindow)
    {
        var cacheKey = $"{prefix}:{timeWindow}";

        lock (_cacheLock)
        {
            _cache[cacheKey] = new CacheEntry(response, timeWindow, DateTimeOffset.UtcNow);

            // Clean up old cache entries
            PruneCache();
        }
    }

    private void PruneCache()
    {
        var currentTimeWindow = GetCurrentTimeWindow();
        var now = DateTimeOffset.UtcNow;
        var keysToRemove = new List<string>();

        foreach (var (key, entry) in _cache)
        {
            // Remove entries from old time windows
            if (entry.TimeWindow != currentTimeWindow)
            {
                keysToRemove.Add(key);
                continue;
            }

            // Remove expired entries
            if (now - entry.CreatedAt > _config.CacheTtl)
            {
                keysToRemove.Add(key);
            }
        }

        foreach (var key in keysToRemove)
        {
            _cache.Remove(key);
        }
    }

    private static int GetCurrentTimeWindow()
    {
        return (int)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / Constants.TimeWindowSeconds);
    }

    private static CheckResult CreateCheckResult(bool found, string? email, CheckMetadata metadata)
    {
        return new CheckResult
        {
            Found = found,
            Email = email ?? "[hash-only]",
            Metadata = metadata
        };
    }

    private static void ValidateOptions(ClientOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.ApiKey))
        {
            throw new ValidationException("API key is required", "apiKey");
        }

        if (options.Timeout.HasValue && options.Timeout.Value <= TimeSpan.Zero)
        {
            throw new ValidationException("Timeout must be a positive duration", "timeout");
        }

        if (options.Retries.HasValue && options.Retries.Value < 0)
        {
            throw new ValidationException("Retries must be a non-negative number", "retries");
        }

        if (options.CacheTtl.HasValue && options.CacheTtl.Value <= TimeSpan.Zero)
        {
            throw new ValidationException("Cache TTL must be a positive duration", "cacheTtl");
        }
    }

    private static void ValidateCredential(string email, string password)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            throw new ValidationException("Email is required", "email");
        }

        if (string.IsNullOrEmpty(password))
        {
            throw new ValidationException("Password is required", "password");
        }
    }

    private static void ValidateCheckOptions(CheckOptions? options)
    {
        if (options is null)
        {
            return;
        }

        // Validate clientHmac if provided
        if (options.ClientHmac is not null)
        {
            if (options.ClientHmac.Length < Constants.MinClientHmacLength)
            {
                throw new ValidationException(
                    $"Client HMAC must be at least {Constants.MinClientHmacLength} hexadecimal characters (256 bits)",
                    "clientHmac");
            }

            if (!HexPattern().IsMatch(options.ClientHmac))
            {
                throw new ValidationException(
                    "Client HMAC must be a hexadecimal string",
                    "clientHmac");
            }
        }

        // Validate sinceEpochDay if provided
        if (options.SinceEpochDay.HasValue && options.SinceEpochDay.Value < 0)
        {
            throw new ValidationException(
                "Since epoch day must be a non-negative integer",
                "sinceEpochDay");
        }
    }

    private static int ConvertToEpochDay(DateTimeOffset date)
    {
        // Convert DateTimeOffset to epoch day (days since 1 January 1970)
        return (int)(date.ToUnixTimeSeconds() / 86400);
    }

    private static string NormalizeBaseUrl(string url)
    {
        // Ensure URL ends with a slash
        return url.EndsWith('/') ? url : $"{url}/";
    }

    [GeneratedRegex("^[A-Fa-f0-9]+$")]
    private static partial Regex HexPattern();

    // ============================================================
    // Internal types
    // ============================================================

    private sealed record ResolvedConfig
    {
        public required string ApiKey { get; init; }
        public required string BaseUrl { get; init; }
        public required TimeSpan Timeout { get; init; }
        public required int Retries { get; init; }
        public required bool EnableCaching { get; init; }
        public required TimeSpan CacheTtl { get; init; }
    }

    private sealed record ApiResponse(string[] Hashes, ApiResponseHeaders Headers);

    private sealed record ApiResponseHeaders
    {
        public required string Prefix { get; init; }
        public required string HmacKey { get; init; }
        public required HmacSource HmacSource { get; init; }
        public int? TimeWindow { get; init; }
        public required int TotalResults { get; init; }
        public int? FilterSince { get; init; }
    }

    private sealed record CacheEntry(ApiResponse Response, int TimeWindow, DateTimeOffset CreatedAt);

    private sealed record HashedCredential(string Email, string Password, string Hash);
}
