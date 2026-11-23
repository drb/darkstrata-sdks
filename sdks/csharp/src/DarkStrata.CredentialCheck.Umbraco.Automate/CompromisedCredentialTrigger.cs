using Umbraco.Automate.Core.Settings;
using Umbraco.Automate.Core.Triggers;

namespace DarkStrata.CredentialCheck.Umbraco.Automate;

public sealed class CompromisedCredentialTriggerSettings
{
    [Field(Label = "Sources", Description = "Comma-separated: MemberPassword, BackOfficePassword, MemberLogin, BackOfficeLogin. Leave empty for all.")]
    public string? Sources { get; set; }
}

/// <summary>Trigger output. Every field is stored in Automate's run history.</summary>
public sealed class CompromisedCredentialTriggerOutput
{
    public string Source { get; init; } = string.Empty;

    public string Email { get; init; } = string.Empty;

    public string? UserId { get; init; }

    public DateTime DetectedAt { get; init; }
}

/// <summary>
/// Starts an automation when <see cref="CompromisedCredentialDetectedNotification"/> is published.
/// Automate discovers it by attribute; no registration needed.
/// </summary>
[Trigger(TriggerAlias, "Compromised Credential Detected",
    Description = "A login or password change used an email and password pair DarkStrata found in infostealer logs.",
    Group = "DarkStrata",
    Icon = "icon-alert")]
public sealed class CompromisedCredentialTrigger(TriggerInfrastructure infrastructure)
    : NotificationTriggerBase<CompromisedCredentialTriggerSettings, CompromisedCredentialTriggerOutput, CompromisedCredentialDetectedNotification>(infrastructure)
{
    public const string TriggerAlias = "darkStrata.compromisedCredentialDetected";

    /// <summary>
    /// Hits for the same user and source in the same clock window share an idempotency key, so a
    /// burst of denied logins starts at most one run per window instead of one per attempt.
    /// </summary>
    internal static readonly TimeSpan DedupeWindow = TimeSpan.FromMinutes(5);

    public override IEnumerable<TriggerEvent> MapEvent(CompromisedCredentialDetectedNotification notification)
    {
        var detectedAt = DateTime.UtcNow;
        yield return new TriggerEvent<CompromisedCredentialTriggerOutput>
        {
            TriggerAlias = Alias,
            InitiatorType = TriggerInitiatorType.System,
            IdempotencyKey = IdempotencyKey(notification, detectedAt),
            Output = new CompromisedCredentialTriggerOutput
            {
                Source = notification.Source.ToString(),
                Email = notification.Email,
                UserId = notification.UserId,
                DetectedAt = detectedAt,
            },
        };
    }

    protected override bool CanHandle(CompromisedCredentialTriggerOutput output, CompromisedCredentialTriggerSettings? settings) =>
        MatchesSources(output.Source, settings?.Sources);

    // ponytail: fixed buckets, so a burst straddling a boundary starts two runs; a sliding window needs run-history lookups.
    internal static string IdempotencyKey(CompromisedCredentialDetectedNotification notification, DateTime at)
    {
        var who = (notification.UserId ?? notification.Email).Trim().ToLowerInvariant();
        return $"{TriggerAlias}:{notification.Source}:{who}:w{at.Ticks / DedupeWindow.Ticks}";
    }

    internal static bool MatchesSources(string source, string? sources) =>
        string.IsNullOrWhiteSpace(sources)
        || sources.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Contains(source, StringComparer.OrdinalIgnoreCase);
}
