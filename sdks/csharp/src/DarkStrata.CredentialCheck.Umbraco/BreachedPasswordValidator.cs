using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Umbraco.Cms.Core.Security;

namespace DarkStrata.CredentialCheck.Umbraco;

/// <summary>
/// Rejects passwords found in the DarkStrata breach corpus when a member or backoffice user sets or changes them.
/// </summary>
public sealed class BreachedPasswordValidator<TUser> : IPasswordValidator<TUser>
    where TUser : UmbracoIdentityUser
{
    private readonly CompromisedCredentialService _service;
    private readonly IOptionsMonitor<DarkStrataOptions> _options;

    public BreachedPasswordValidator(CompromisedCredentialService service, IOptionsMonitor<DarkStrataOptions> options)
    {
        _service = service;
        _options = options;
    }

    public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string? password)
    {
        if (!_options.CurrentValue.ValidatePasswords)
        {
            return IdentityResult.Success;
        }

        var source = user is MemberIdentityUser
            ? CompromisedCredentialSource.MemberPassword
            : CompromisedCredentialSource.BackOfficePassword;

        var compromised = await _service.IsCompromisedAsync(source, user.Email, password, user.Id);

        return compromised
            ? IdentityResult.Failed(new IdentityError
            {
                Code = DarkStrataOptions.IdentityErrorCode,
                Description = "This password has appeared in a data breach. Please choose a different password.",
            })
            : IdentityResult.Success;
    }
}
