using Microsoft.AspNetCore.Identity;

namespace DarkStrata.CredentialCheck.Umbraco;

/// <summary>
/// Returned by <see cref="DarkStrataMemberSignInManager"/> when a member login is refused because the
/// email and password were found together in DarkStrata's stolen-credential data and <see cref="LoginAction"/> is
/// <see cref="LoginAction.Deny"/>.
/// </summary>
/// <remarks>
/// It is an ordinary failed <see cref="SignInResult"/>, so existing login code keeps working unchanged.
/// A custom surface controller can test for this type to tell the member the pair is compromised and
/// send them to password reset, instead of the generic "invalid username or password". Umbraco's own
/// <c>UmbLoginController</c> cannot do this: its failure message is hard-coded.
/// </remarks>
public sealed class CompromisedCredentialSignInResult : SignInResult
{
    /// <summary>The single instance; the result carries no per-login state.</summary>
    public static readonly CompromisedCredentialSignInResult Instance = new();

    private CompromisedCredentialSignInResult()
    {
    }

    public override string ToString() => "CompromisedCredential";
}
