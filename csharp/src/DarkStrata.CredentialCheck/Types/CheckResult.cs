namespace DarkStrata.CredentialCheck;

/// <summary>
/// Result of a credential check.
/// </summary>
public sealed class CheckResult
{
    /// <summary>
    /// Whether the credential was found in a data breach.
    /// True means the credential has been compromised.
    /// </summary>
    public required bool Found { get; init; }

    /// <summary>
    /// The email address that was checked.
    /// </summary>
    public required string Email { get; init; }

    /// <summary>
    /// Always true - the password is never included in results.
    /// </summary>
    public bool Masked => true;

    /// <summary>
    /// Additional metadata about the check.
    /// </summary>
    public required CheckMetadata Metadata { get; init; }
}
