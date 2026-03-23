namespace DarkStrata.CredentialCheck;

/// <summary>
/// Error codes for DarkStrata SDK exceptions.
/// </summary>
public enum ErrorCode
{
    /// <summary>
    /// Invalid or missing API key.
    /// </summary>
    AuthenticationError,

    /// <summary>
    /// Invalid input parameters.
    /// </summary>
    ValidationError,

    /// <summary>
    /// API request failed.
    /// </summary>
    ApiError,

    /// <summary>
    /// Request timed out.
    /// </summary>
    TimeoutError,

    /// <summary>
    /// Network error.
    /// </summary>
    NetworkError,

    /// <summary>
    /// Rate limit exceeded.
    /// </summary>
    RateLimitError
}
