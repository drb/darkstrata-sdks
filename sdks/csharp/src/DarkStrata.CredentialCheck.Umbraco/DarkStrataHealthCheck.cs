using Microsoft.Extensions.Options;
using Umbraco.Cms.Core.HealthChecks;

namespace DarkStrata.CredentialCheck.Umbraco;

/// <summary>
/// Backoffice health check: API key configured and the DarkStrata API reachable.
/// </summary>
[HealthCheck(
    "7f2b8a3e-5c4d-4e1f-9a6b-2d8c1e0f3a47",
    "DarkStrata Credential Check",
    Description = "Verifies the DarkStrata API key is configured and the credential check API is reachable.",
    Group = "Security")]
public sealed class DarkStrataHealthCheck : HealthCheck
{
    // Any well-formed SHA-256 hex string works; the API only sees its 5-char prefix.
    private const string SentinelHash = "0000000000000000000000000000000000000000000000000000000000000000";

    private readonly IDarkStrataCredentialCheck _client;
    private readonly IOptionsMonitor<DarkStrataOptions> _options;

    public DarkStrataHealthCheck(IDarkStrataCredentialCheck client, IOptionsMonitor<DarkStrataOptions> options)
    {
        _client = client;
        _options = options;
    }

    public override async Task<IEnumerable<HealthCheckStatus>> GetStatus()
    {
        if (string.IsNullOrWhiteSpace(_options.CurrentValue.ApiKey))
        {
            return [new HealthCheckStatus($"No API key configured at {DarkStrataOptions.SectionName}:ApiKey.") { ResultType = StatusResultType.Error }];
        }

        try
        {
            await _client.CheckHashAsync(SentinelHash);
            return [new HealthCheckStatus("DarkStrata API reachable and API key accepted.") { ResultType = StatusResultType.Success }];
        }
        catch (DarkStrataException ex)
        {
            return [new HealthCheckStatus($"DarkStrata API check failed: {ex.Message}") { ResultType = StatusResultType.Error }];
        }
    }

    public override HealthCheckStatus ExecuteAction(HealthCheckAction action) =>
        throw new InvalidOperationException("This health check has no actions.");
}
