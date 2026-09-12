using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Umbraco.Cms.Core.Events;

namespace DarkStrata.CredentialCheck.Umbraco;

/// <summary>
/// Single gate every hook goes through: config guard, SDK call, fail-open handling, notification.
/// </summary>
public sealed class CompromisedCredentialService
{
    private readonly IDarkStrataCredentialCheck _client;
    private readonly IEventAggregator _events;
    private readonly IOptionsMonitor<DarkStrataOptions> _options;
    private readonly ILogger<CompromisedCredentialService> _logger;

    public CompromisedCredentialService(
        IDarkStrataCredentialCheck client,
        IEventAggregator events,
        IOptionsMonitor<DarkStrataOptions> options,
        ILogger<CompromisedCredentialService> logger)
    {
        _client = client;
        _events = events;
        _options = options;
        _logger = logger;
    }

    /// <summary>
    /// Returns true when the pair is in the breach corpus. Returns false when the check is
    /// unconfigured or fails and <see cref="DarkStrataOptions.FailOpen"/> is set; throws otherwise.
    /// </summary>
    public async Task<bool> IsCompromisedAsync(
        CompromisedCredentialSource source,
        string? email,
        string? password,
        string? userId,
        CancellationToken cancellationToken = default)
    {
        var options = _options.CurrentValue;
        if (string.IsNullOrWhiteSpace(options.ApiKey) || string.IsNullOrWhiteSpace(email) || string.IsNullOrEmpty(password))
        {
            return false;
        }

        bool found;
        try
        {
            found = (await _client.CheckAsync(email, password, null, cancellationToken)).Found;
        }
        catch (DarkStrataException ex) when (options.FailOpen)
        {
            _logger.LogWarning(ex, "DarkStrata credential check failed ({Code}); allowing because FailOpen is enabled", ex.Code);
            return false;
        }

        if (found)
        {
            _logger.LogWarning("Compromised credential detected for {Email} via {Source}", email, source);
            await _events.PublishAsync(new CompromisedCredentialDetectedNotification(source, email, userId), cancellationToken);
        }

        return found;
    }
}
