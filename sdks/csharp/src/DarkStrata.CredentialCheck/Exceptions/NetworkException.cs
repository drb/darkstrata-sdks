using System;

namespace DarkStrata.CredentialCheck;

/// <summary>
/// Exception thrown when a network error occurs.
/// </summary>
public sealed class NetworkException : DarkStrataException
{
    /// <summary>
    /// Creates a new NetworkException.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception (if any).</param>
    public NetworkException(string message, Exception? innerException = null)
        : base(message, ErrorCode.NetworkError, isRetryable: true, innerException: innerException)
    {
    }
}
