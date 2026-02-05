using System;

namespace DarkStrata.CredentialCheck;

/// <summary>
/// Exception thrown when a request times out.
/// </summary>
public sealed class DarkStrataTimeoutException : DarkStrataException
{
    /// <summary>
    /// The timeout duration in milliseconds.
    /// </summary>
    public int TimeoutMs { get; }

    /// <summary>
    /// Creates a new DarkStrataTimeoutException.
    /// </summary>
    /// <param name="timeoutMs">The timeout duration in milliseconds.</param>
    /// <param name="innerException">The inner exception (if any).</param>
    public DarkStrataTimeoutException(int timeoutMs, Exception? innerException = null)
        : base($"Request timed out after {timeoutMs}ms", ErrorCode.TimeoutError, isRetryable: true, innerException: innerException)
    {
        TimeoutMs = timeoutMs;
    }
}
