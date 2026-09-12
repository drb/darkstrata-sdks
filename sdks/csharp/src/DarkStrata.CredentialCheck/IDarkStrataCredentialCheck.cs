using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DarkStrata.CredentialCheck;

/// <summary>
/// Abstraction over <see cref="DarkStrataCredentialCheck"/> so consumers can inject and mock the client.
/// </summary>
public interface IDarkStrataCredentialCheck
{
    /// <inheritdoc cref="DarkStrataCredentialCheck.CheckAsync"/>
    Task<CheckResult> CheckAsync(string email, string password, CheckOptions? options = null, CancellationToken cancellationToken = default);

    /// <inheritdoc cref="DarkStrataCredentialCheck.CheckHashAsync"/>
    Task<CheckResult> CheckHashAsync(string hash, CheckOptions? options = null, CancellationToken cancellationToken = default);

    /// <inheritdoc cref="DarkStrataCredentialCheck.CheckBatchAsync"/>
    Task<IReadOnlyList<CheckResult>> CheckBatchAsync(IEnumerable<Credential> credentials, CheckOptions? options = null, CancellationToken cancellationToken = default);

    /// <inheritdoc cref="DarkStrataCredentialCheck.CheckHashBatchAsync"/>
    Task<IReadOnlyList<CheckResult>> CheckHashBatchAsync(IEnumerable<string> hashes, CheckOptions? options = null, CancellationToken cancellationToken = default);

    /// <inheritdoc cref="DarkStrataCredentialCheck.ClearCache"/>
    void ClearCache();

    /// <inheritdoc cref="DarkStrataCredentialCheck.GetCacheSize"/>
    int GetCacheSize();
}
