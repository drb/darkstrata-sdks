using Umbraco.Cms.Core.Notifications;

namespace DarkStrata.CredentialCheck.Umbraco;

public enum CompromisedCredentialSource
{
    MemberPassword,
    BackOfficePassword,
    MemberLogin,
    BackOfficeLogin,
}

/// <summary>
/// Published whenever a checked email/password pair is found in the DarkStrata breach corpus.
/// Handle it with an INotificationAsyncHandler to trigger your own workflow.
/// </summary>
public sealed class CompromisedCredentialDetectedNotification : INotification
{
    public CompromisedCredentialDetectedNotification(CompromisedCredentialSource source, string email, string? userId)
    {
        Source = source;
        Email = email;
        UserId = userId;
    }

    public CompromisedCredentialSource Source { get; }

    public string Email { get; }

    /// <summary>Identity user id (member or backoffice user) when known.</summary>
    public string? UserId { get; }
}
