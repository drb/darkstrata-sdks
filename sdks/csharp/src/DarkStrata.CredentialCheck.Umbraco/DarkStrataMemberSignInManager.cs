using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Umbraco.Cms.Core.Cache;
using Umbraco.Cms.Core.Configuration.Models;
using Umbraco.Cms.Core.Events;
using Umbraco.Cms.Core.Security;
using Umbraco.Cms.Web.Common.Security;

namespace DarkStrata.CredentialCheck.Umbraco;

/// <summary>
/// Member sign-in manager that checks the login pair against the breach corpus.
/// A compromised pair is treated exactly like a wrong password, including Umbraco's lockout counter.
/// </summary>
public sealed class DarkStrataMemberSignInManager : MemberSignInManager
{
    private readonly CompromisedCredentialService _service;
    private readonly IOptionsMonitor<DarkStrataOptions> _options;

    public DarkStrataMemberSignInManager(
        CompromisedCredentialService service,
        IOptionsMonitor<DarkStrataOptions> options,
        UserManager<MemberIdentityUser> memberManager,
        IHttpContextAccessor contextAccessor,
        IUserClaimsPrincipalFactory<MemberIdentityUser> claimsFactory,
        IOptions<IdentityOptions> optionsAccessor,
        ILogger<SignInManager<MemberIdentityUser>> logger,
        IAuthenticationSchemeProvider schemes,
        IUserConfirmation<MemberIdentityUser> confirmation,
        IMemberExternalLoginProviders memberExternalLoginProviders,
        IEventAggregator eventAggregator,
        IOptions<SecuritySettings> securitySettings,
        IRequestCache requestCache)
        : base(memberManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation, memberExternalLoginProviders, eventAggregator, securitySettings, requestCache)
    {
        _service = service;
        _options = options;
    }

    public override async Task<SignInResult> CheckPasswordSignInAsync(MemberIdentityUser user, string password, bool lockoutOnFailure)
    {
        var options = _options.CurrentValue;
        if (options.CheckLogins
            && await _service.IsCompromisedAsync(CompromisedCredentialSource.MemberLogin, user.Email, password, user.Id)
            && options.LoginAction == LoginAction.Deny)
        {
            if (lockoutOnFailure)
            {
                await UserManager.AccessFailedAsync(user);
            }

            return SignInResult.Failed;
        }

        return await base.CheckPasswordSignInAsync(user, password, lockoutOnFailure);
    }
}
