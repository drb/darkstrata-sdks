using System;

namespace DarkStrata.CredentialCheck;

/// <summary>
/// Options for individual credential check requests.
/// </summary>
public sealed class CheckOptions
{
    /// <summary>
    /// Client-provided HMAC key for deterministic results.
    /// </summary>
    /// <remarks>
    /// When provided, results are consistent across requests (not time-windowed).
    /// Must be a cryptographically strong hex string of at least 64 characters (256 bits).
    ///
    /// Use this when you need:
    /// - Consistent results across multiple requests
    /// - To avoid server-side HMAC key rotation
    /// - Custom key management
    /// </remarks>
    public string? ClientHmac { get; init; }

    /// <summary>
    /// Filter results to only include breaches from this date onwards.
    /// </summary>
    /// <remarks>
    /// Accepts either:
    /// - A DateTimeOffset which will be converted to epoch day
    /// - An integer epoch day (days since 1 January 1970)
    /// </remarks>
    public DateTimeOffset? Since { get; init; }

    /// <summary>
    /// Filter results to only include breaches from this epoch day onwards.
    /// </summary>
    /// <remarks>
    /// Epoch day = days since 1 January 1970 (e.g., 19724 = 1 January 2024).
    /// If both Since and SinceEpochDay are set, SinceEpochDay takes precedence.
    /// </remarks>
    public int? SinceEpochDay { get; init; }
}
