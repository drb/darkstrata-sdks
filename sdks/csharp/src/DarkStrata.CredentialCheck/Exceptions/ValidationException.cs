namespace DarkStrata.CredentialCheck;

/// <summary>
/// Exception thrown when input validation fails.
/// </summary>
public sealed class ValidationException : DarkStrataException
{
    /// <summary>
    /// The field that failed validation.
    /// </summary>
    public string? Field { get; }

    /// <summary>
    /// Creates a new ValidationException.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="field">The field that failed validation.</param>
    public ValidationException(string message, string? field = null)
        : base(message, ErrorCode.ValidationError, isRetryable: false)
    {
        Field = field;
    }
}
