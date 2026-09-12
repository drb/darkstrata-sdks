namespace DarkStrata.CredentialCheck.Umbraco;

/// <summary>
/// Stand-in registered when no API key is configured so DI never throws; the service gate short-circuits before calling it.
/// </summary>
internal sealed class DisabledCredentialCheck : IDarkStrataCredentialCheck
{
    private const string Message = "DarkStrata API key is not configured.";

    public Task<CheckResult> CheckAsync(string email, string password, CheckOptions? options = null, CancellationToken cancellationToken = default) =>
        throw new ValidationException(Message);

    public Task<CheckResult> CheckHashAsync(string hash, CheckOptions? options = null, CancellationToken cancellationToken = default) =>
        throw new ValidationException(Message);

    public Task<IReadOnlyList<CheckResult>> CheckBatchAsync(IEnumerable<Credential> credentials, CheckOptions? options = null, CancellationToken cancellationToken = default) =>
        throw new ValidationException(Message);

    public Task<IReadOnlyList<CheckResult>> CheckHashBatchAsync(IEnumerable<string> hashes, CheckOptions? options = null, CancellationToken cancellationToken = default) =>
        throw new ValidationException(Message);

    public void ClearCache()
    {
    }

    public int GetCacheSize() => 0;
}
