namespace DarkStrata.CredentialCheck;

/// <summary>
/// Metadata returned with check results.
/// </summary>
public sealed class CheckMetadata
{
    /// <summary>
    /// The 5-character hash prefix used for the k-anonymity lookup.
    /// </summary>
    public required string Prefix { get; init; }

    /// <summary>
    /// Total number of matching hashes returned by the API.
    /// </summary>
    public required int TotalResults { get; init; }

    /// <summary>
    /// Source of the HMAC key used for this request.
    /// </summary>
    public required HmacSource HmacSource { get; init; }

    /// <summary>
    /// Server time window (hour-based) for HMAC key rotation.
    /// Only present when using server-generated HMAC.
    /// </summary>
    public int? TimeWindow { get; init; }

    /// <summary>
    /// The epoch day used for filtering (if since was provided).
    /// Epoch day = days since 1 January 1970.
    /// </summary>
    public int? FilterSince { get; init; }

    /// <summary>
    /// Whether this result was served from cache.
    /// </summary>
    public required bool CachedResult { get; init; }

    /// <summary>
    /// Timestamp when the check was performed.
    /// </summary>
    public required DateTimeOffset CheckedAt { get; init; }
}
