namespace DarkStrata.CredentialCheck;

/// <summary>
/// Represents a credential pair to check.
/// </summary>
/// <param name="Email">The email address or username.</param>
/// <param name="Password">The password to check.</param>
public sealed record Credential(string Email, string Password);
