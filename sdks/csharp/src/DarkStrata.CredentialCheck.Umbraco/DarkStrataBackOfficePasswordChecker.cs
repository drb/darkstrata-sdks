using Microsoft.Extensions.Options;
using Umbraco.Cms.Core.Security;

namespace DarkStrata.CredentialCheck.Umbraco;

/// <summary>
/// Checks backoffice logins against the breach corpus. Never validates the password itself;
/// always falls back to Umbraco's default checker unless the pair is compromised and the action is Deny.
/// </summary>
public sealed class DarkStrataBackOfficePasswordChecker : IBackOfficeUserPasswordChecker
{
    private readonly CompromisedCredentialService _service;
    private readonly IOptionsMonitor<DarkStrataOptions> _options;

    public DarkStrataBackOfficePasswordChecker(CompromisedCredentialService service, IOptionsMonitor<DarkStrataOptions> options)
    {
        _service = service;
        _options = options;
    }

    public async Task<BackOfficeUserPasswordCheckerResult> CheckPasswordAsync(BackOfficeIdentityUser user, string password)
    {
        var options = _options.CurrentValue;
        if (!options.CheckLogins)
        {
            return BackOfficeUserPasswordCheckerResult.FallbackToDefaultChecker;
        }

        var compromised = await _service.IsCompromisedAsync(CompromisedCredentialSource.BackOfficeLogin, user.Email, password, user.Id);

        return compromised && options.LoginAction == LoginAction.Deny
            ? BackOfficeUserPasswordCheckerResult.InvalidCredentials
            : BackOfficeUserPasswordCheckerResult.FallbackToDefaultChecker;
    }
}
