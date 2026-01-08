using System;

namespace DarkStrata.CredentialCheck;

/// <summary>
/// Exception thrown when an API request fails.
/// </summary>
public sealed class ApiException : DarkStrataException
{
    /// <summary>
    /// Response body from the API (if available).
    /// </summary>
    public string? ResponseBody { get; }

    /// <summary>
    /// Creates a new ApiException.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="statusCode">The HTTP status code.</param>
    /// <param name="responseBody">The response body (if available).</param>
    /// <param name="isRetryable">Whether this error is retryable.</param>
    /// <param name="innerException">The inner exception (if any).</param>
    public ApiException(
        string message,
        int statusCode,
        string? responseBody = null,
        bool isRetryable = false,
        Exception? innerException = null)
        : base(message, ErrorCode.ApiError, statusCode, isRetryable, innerException)
    {
        ResponseBody = responseBody;
    }
}
