namespace DarkStrata.CredentialCheck;

/// <summary>
/// Configuration options for the DarkStrata credential check client.
/// </summary>
public sealed class ClientOptions
{
    /// <summary>
    /// Your DarkStrata API key (JWT token).
    /// Obtain this from your DarkStrata dashboard.
    /// </summary>
    public required string ApiKey { get; init; }

    /// <summary>
    /// Base URL for the DarkStrata API.
    /// </summary>
    /// <remarks>Default: https://api.darkstrata.io/v1/</remarks>
    public string? BaseUrl { get; init; }

    /// <summary>
    /// Request timeout.
    /// </summary>
    /// <remarks>Default: 30 seconds</remarks>
    public TimeSpan? Timeout { get; init; }

    /// <summary>
    /// Number of retry attempts for failed requests.
    /// </summary>
    /// <remarks>Default: 3</remarks>
    public int? Retries { get; init; }

    /// <summary>
    /// Enable in-memory caching of API responses.
    /// Cache is automatically invalidated when the server time window changes.
    /// </summary>
    /// <remarks>Default: true</remarks>
    public bool? EnableCaching { get; init; }

    /// <summary>
    /// Cache time-to-live.
    /// Should align with server time window (1 hour).
    /// </summary>
    /// <remarks>Default: 1 hour</remarks>
    public TimeSpan? CacheTtl { get; init; }
}
