using DarkStrata.CredentialCheck.Umbraco;
using Microsoft.Extensions.Options;
using Umbraco.Cms.Core.Configuration.Models;
using Umbraco.Cms.Core.Security;
using Xunit;

namespace DarkStrata.CredentialCheck.Umbraco.Tests;

public class DarkStrataBackOfficePasswordCheckerTests
{
    private static BackOfficeIdentityUser User() =>
        BackOfficeIdentityUser.CreateNew(new GlobalSettings(), "admin", "admin@example.com", "en-GB");

    [Theory]
    [InlineData(LoginAction.Deny, BackOfficeUserPasswordCheckerResult.InvalidCredentials)]
    [InlineData(LoginAction.Warn, BackOfficeUserPasswordCheckerResult.FallbackToDefaultChecker)]
    public async Task Compromised_login_follows_configured_action(LoginAction action, BackOfficeUserPasswordCheckerResult expected)
    {
        var options = new DarkStrataOptions { ApiKey = TestSupport.ApiKey, LoginAction = action };
        var checker = new DarkStrataBackOfficePasswordChecker(
            TestSupport.Service(TestSupport.Client(found: true).Object, options),
            TestSupport.Options(options));

        Assert.Equal(expected, await checker.CheckPasswordAsync(User(), "hunter2"));
    }

    [Fact]
    public async Task Clean_login_falls_back_to_default_checker()
    {
        var options = new DarkStrataOptions { ApiKey = TestSupport.ApiKey };
        var checker = new DarkStrataBackOfficePasswordChecker(
            TestSupport.Service(TestSupport.Client(found: false).Object, options),
            TestSupport.Options(options));

        Assert.Equal(BackOfficeUserPasswordCheckerResult.FallbackToDefaultChecker, await checker.CheckPasswordAsync(User(), "hunter2"));
    }
}
