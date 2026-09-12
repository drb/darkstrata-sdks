using DarkStrata.CredentialCheck.Umbraco;
using Moq;
using Umbraco.Cms.Core.Events;
using Umbraco.Cms.Core.Security;
using Xunit;

namespace DarkStrata.CredentialCheck.Umbraco.Tests;

public class BreachedPasswordValidatorTests
{
    private static readonly MemberIdentityUser Member = new() { Id = "42", Email = "user@example.com" };

    [Fact]
    public async Task Found_returns_failed_with_darkstrata_code_and_publishes_notification()
    {
        var events = new Mock<IEventAggregator>();
        var options = new DarkStrataOptions { ApiKey = TestSupport.ApiKey };
        var validator = new BreachedPasswordValidator<MemberIdentityUser>(
            TestSupport.Service(TestSupport.Client(found: true).Object, options, events.Object),
            TestSupport.Options(options));

        var result = await validator.ValidateAsync(null!, Member, "hunter2");

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, e => e.Code == DarkStrataOptions.IdentityErrorCode);
        events.Verify(
            e => e.PublishAsync(
                It.Is<CompromisedCredentialDetectedNotification>(n => n.Source == CompromisedCredentialSource.MemberPassword && n.UserId == "42"),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Not_found_returns_success()
    {
        var options = new DarkStrataOptions { ApiKey = TestSupport.ApiKey };
        var validator = new BreachedPasswordValidator<MemberIdentityUser>(
            TestSupport.Service(TestSupport.Client(found: false).Object, options),
            TestSupport.Options(options));

        Assert.True((await validator.ValidateAsync(null!, Member, "hunter2")).Succeeded);
    }

    [Fact]
    public async Task Api_failure_with_fail_open_returns_success()
    {
        var options = new DarkStrataOptions { ApiKey = TestSupport.ApiKey, FailOpen = true };
        var validator = new BreachedPasswordValidator<MemberIdentityUser>(
            TestSupport.Service(TestSupport.FailingClient().Object, options),
            TestSupport.Options(options));

        Assert.True((await validator.ValidateAsync(null!, Member, "hunter2")).Succeeded);
    }

    [Fact]
    public async Task Api_failure_with_fail_closed_throws()
    {
        var options = new DarkStrataOptions { ApiKey = TestSupport.ApiKey, FailOpen = false };
        var validator = new BreachedPasswordValidator<MemberIdentityUser>(
            TestSupport.Service(TestSupport.FailingClient().Object, options),
            TestSupport.Options(options));

        await Assert.ThrowsAsync<NetworkException>(() => validator.ValidateAsync(null!, Member, "hunter2"));
    }

    [Fact]
    public async Task No_api_key_skips_check()
    {
        var client = TestSupport.Client(found: true);
        var options = new DarkStrataOptions();
        var validator = new BreachedPasswordValidator<MemberIdentityUser>(
            TestSupport.Service(client.Object, options),
            TestSupport.Options(options));

        Assert.True((await validator.ValidateAsync(null!, Member, "hunter2")).Succeeded);
        client.VerifyNoOtherCalls();
    }
}
