namespace DarkStrata.CredentialCheck;

/// <summary>
/// Source of the HMAC key used for credential checking.
/// </summary>
public enum HmacSource
{
    /// <summary>
    /// Server-generated HMAC key (rotates hourly).
    /// </summary>
    Server,

    /// <summary>
    /// Client-provided HMAC key (deterministic results).
    /// </summary>
    Client
}
