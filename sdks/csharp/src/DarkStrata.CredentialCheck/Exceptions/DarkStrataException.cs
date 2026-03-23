using System;

namespace DarkStrata.CredentialCheck;

/// <summary>
/// Base exception class for all DarkStrata SDK exceptions.
/// </summary>
public class DarkStrataException : Exception
{
    /// <summary>
    /// Error code for programmatic error handling.
    /// </summary>
    public ErrorCode Code { get; }

    /// <summary>
    /// HTTP status code (if applicable).
    /// </summary>
    public int? StatusCode { get; }

    /// <summary>
    /// Whether this error is retryable.
    /// </summary>
    public bool IsRetryable { get; }

    /// <summary>
    /// Creates a new DarkStrataException.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="code">The error code.</param>
    /// <param name="statusCode">The HTTP status code (if applicable).</param>
    /// <param name="isRetryable">Whether this error is retryable.</param>
    /// <param name="innerException">The inner exception (if any).</param>
    public DarkStrataException(
        string message,
        ErrorCode code,
        int? statusCode = null,
        bool isRetryable = false,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
        StatusCode = statusCode;
        IsRetryable = isRetryable;
    }
}
