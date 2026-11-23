using DarkStrata.CredentialCheck.Umbraco;
using DarkStrata.CredentialCheck.Umbraco.Automate;
using Xunit;

namespace DarkStrata.CredentialCheck.Umbraco.Automate.Tests;

public class CompromisedCredentialTriggerTests
{
    private static readonly DateTime T0 = new(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);

    private static CompromisedCredentialDetectedNotification Hit(
        CompromisedCredentialSource source = CompromisedCredentialSource.MemberLogin, string email = "a@example.com", string? userId = "42") =>
        new(source, email, userId);

    // A brute-force burst against one account must start one run, not one per attempt.
    [Fact]
    public void Repeat_hits_inside_the_window_share_a_key()
    {
        var first = CompromisedCredentialTrigger.IdempotencyKey(Hit(), T0);
        Assert.Equal(first, CompromisedCredentialTrigger.IdempotencyKey(Hit(), T0.AddSeconds(30)));
        Assert.NotEqual(first, CompromisedCredentialTrigger.IdempotencyKey(Hit(), T0 + CompromisedCredentialTrigger.DedupeWindow));
    }

    [Fact]
    public void Different_users_and_sources_get_their_own_runs()
    {
        var key = CompromisedCredentialTrigger.IdempotencyKey(Hit(), T0);
        Assert.NotEqual(key, CompromisedCredentialTrigger.IdempotencyKey(Hit(userId: "43"), T0));
        Assert.NotEqual(key, CompromisedCredentialTrigger.IdempotencyKey(Hit(CompromisedCredentialSource.MemberPassword), T0));
    }

    [Fact]
    public void Falls_back_to_email_case_insensitively_when_there_is_no_user_id()
    {
        Assert.Equal(
            CompromisedCredentialTrigger.IdempotencyKey(Hit(email: "A@Example.com", userId: null), T0),
            CompromisedCredentialTrigger.IdempotencyKey(Hit(email: "a@example.com", userId: null), T0));
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData("", true)]
    [InlineData("MemberLogin", true)]
    [InlineData(" backofficelogin , memberlogin ", true)]
    [InlineData("BackOfficeLogin", false)]
    public void Sources_filter(string? sources, bool expected) =>
        Assert.Equal(expected, CompromisedCredentialTrigger.MatchesSources("MemberLogin", sources));
}
