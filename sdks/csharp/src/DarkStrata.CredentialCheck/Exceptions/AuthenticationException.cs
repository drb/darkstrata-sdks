namespace DarkStrata.CredentialCheck;

/// <summary>
/// Exception thrown when API key authentication fails.
/// </summary>
public sealed class AuthenticationException : DarkStrataException
{
    /// <summary>
    /// Creates a new AuthenticationException.
    /// </summary>
    /// <param name="message">The error message.</param>
    public AuthenticationException(string message = "Invalid or missing API key")
        : base(message, ErrorCode.AuthenticationError, statusCode: 401, isRetryable: false)
    {
    }
}
