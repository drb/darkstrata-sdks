namespace DarkStrata.CredentialCheck;

/// <summary>
/// SDK constants and default values.
/// </summary>
internal static class Constants
{
    /// <summary>
    /// SDK name for User-Agent header.
    /// </summary>
    public const string SdkName = "DarkStrata.CredentialCheck";

    /// <summary>
    /// SDK version.
    /// </summary>
    public const string SdkVersion = "1.0.2";

    /// <summary>
    /// Default base URL for the DarkStrata API.
    /// </summary>
    public const string DefaultBaseUrl = "https://api.darkstrata.io/v1/";

    /// <summary>
    /// Default request timeout.
    /// </summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Default number of retry attempts.
    /// </summary>
    public const int DefaultRetries = 3;

    /// <summary>
    /// Default cache time-to-live.
    /// </summary>
    public static readonly TimeSpan DefaultCacheTtl = TimeSpan.FromHours(1);

    /// <summary>
    /// Length of the k-anonymity prefix.
    /// </summary>
    public const int PrefixLength = 5;

    /// <summary>
    /// Time window duration in seconds (for HMAC key rotation).
    /// </summary>
    public const int TimeWindowSeconds = 3600;

    /// <summary>
    /// Credential check API endpoint.
    /// </summary>
    public const string CredentialCheckEndpoint = "credential-check/query";

    /// <summary>
    /// API key header name.
    /// </summary>
    public const string ApiKeyHeader = "X-Api-Key";

    /// <summary>
    /// Minimum length for client-provided HMAC key (256 bits = 64 hex chars).
    /// </summary>
    public const int MinClientHmacLength = 64;

    /// <summary>
    /// HTTP status codes that indicate retryable errors.
    /// </summary>
    public static readonly int[] RetryableStatusCodes = [408, 429, 500, 502, 503, 504];

    /// <summary>
    /// Response header names.
    /// </summary>
    public static class ResponseHeaders
    {
        public const string Prefix = "X-Prefix";
        public const string HmacKey = "X-HMAC-Key";
        public const string HmacSource = "X-HMAC-Source";
        public const string TimeWindow = "X-Time-Window";
        public const string TotalResults = "X-Total-Results";
        public const string FilterSince = "X-Filter-Since";
    }

    /// <summary>
    /// Retry configuration defaults.
    /// </summary>
    public static class RetryDefaults
    {
        /// <summary>
        /// Initial delay between retries.
        /// </summary>
        public static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(1);

        /// <summary>
        /// Maximum delay between retries.
        /// </summary>
        public static readonly TimeSpan MaxDelay = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Backoff multiplier for exponential retry.
        /// </summary>
        public const double BackoffMultiplier = 2.0;
    }
}
