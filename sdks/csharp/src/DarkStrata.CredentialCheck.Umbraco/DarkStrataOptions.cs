namespace DarkStrata.CredentialCheck.Umbraco;

/// <summary>
/// Package settings, bound from the <c>DarkStrata:CredentialCheck</c> configuration section.
/// </summary>
public sealed class DarkStrataOptions
{
    public const string SectionName = "DarkStrata:CredentialCheck";

    /// <summary>ASP.NET Identity error code returned when a password is rejected.</summary>
    public const string IdentityErrorCode = "DarkStrataCompromised";

    /// <summary>DarkStrata API key with the <c>credential_check:read</c> scope.</summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>Override the API base URL (defaults to the SDK default).</summary>
    public string? BaseUrl { get; set; }

    /// <summary>Reject compromised passwords when members or backoffice users set or change them.</summary>
    public bool ValidatePasswords { get; set; } = true;

    /// <summary>Check member and backoffice logins against the breach corpus.</summary>
    public bool CheckLogins { get; set; } = true;

    /// <summary>What to do when a login uses a compromised password.</summary>
    public LoginAction LoginAction { get; set; } = LoginAction.Deny;

    /// <summary>When the DarkStrata API is unreachable, allow the operation (true) or reject it (false).</summary>
    public bool FailOpen { get; set; } = true;
}

public enum LoginAction
{
    /// <summary>Reject the login as invalid credentials, counting towards Umbraco's lockout threshold.</summary>
    Deny,

    /// <summary>Allow the login but log a warning and publish <see cref="CompromisedCredentialDetectedNotification"/>.</summary>
    Warn,
}
