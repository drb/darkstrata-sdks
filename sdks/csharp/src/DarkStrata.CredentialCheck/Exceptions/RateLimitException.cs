namespace DarkStrata.CredentialCheck;

/// <summary>
/// Exception thrown when rate limit is exceeded.
/// </summary>
public sealed class RateLimitException : DarkStrataException
{
    /// <summary>
    /// Seconds until rate limit resets (if available).
    /// </summary>
    public int? RetryAfter { get; }

    /// <summary>
    /// Creates a new RateLimitException.
    /// </summary>
    /// <param name="retryAfter">Seconds until rate limit resets (if available).</param>
    public RateLimitException(int? retryAfter = null)
        : base(
            retryAfter.HasValue
                ? $"Rate limit exceeded. Retry after {retryAfter} seconds."
                : "Rate limit exceeded.",
            ErrorCode.RateLimitError,
            statusCode: 429,
            isRetryable: true)
    {
        RetryAfter = retryAfter;
    }
}
