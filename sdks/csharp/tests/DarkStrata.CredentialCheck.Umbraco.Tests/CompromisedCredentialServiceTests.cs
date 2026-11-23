using DarkStrata.CredentialCheck.Umbraco;
using Moq;
using Umbraco.Cms.Core.Cache;
using Umbraco.Cms.Core.Events;
using Xunit;

namespace DarkStrata.CredentialCheck.Umbraco.Tests;

public class CompromisedCredentialServiceTests
{
    // Umbraco checks the same credentials twice per backoffice login; the key owner must only pay once.
    [Fact]
    public async Task Same_credentials_are_checked_once_per_request()
    {
        var client = TestSupport.Client(found: true);
        var events = new Mock<IEventAggregator>();
        var service = TestSupport.Service(client.Object, new DarkStrataOptions { ApiKey = TestSupport.ApiKey }, events.Object);

        Assert.True(await service.IsCompromisedAsync(CompromisedCredentialSource.BackOfficeLogin, "a@example.com", "hunter2", "1"));
        Assert.True(await service.IsCompromisedAsync(CompromisedCredentialSource.BackOfficeLogin, "a@example.com", "hunter2", "1"));

        client.Verify(c => c.CheckAsync(It.IsAny<string>(), It.IsAny<string>(), null, It.IsAny<CancellationToken>()), Times.Once);
        events.Verify(
            e => e.PublishAsync(It.IsAny<CompromisedCredentialDetectedNotification>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Different_credentials_are_checked_separately()
    {
        var client = TestSupport.Client(found: false);
        var service = TestSupport.Service(client.Object, new DarkStrataOptions { ApiKey = TestSupport.ApiKey });

        await service.IsCompromisedAsync(CompromisedCredentialSource.MemberLogin, "a@example.com", "hunter2", "1");
        await service.IsCompromisedAsync(CompromisedCredentialSource.MemberLogin, "a@example.com", "hunter3", "1");

        client.Verify(c => c.CheckAsync(It.IsAny<string>(), It.IsAny<string>(), null, It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    // A broken handler (e.g. Automate's outbox on a locked database) must not turn a hit into an error.
    [Fact]
    public async Task Failing_notification_handler_does_not_change_the_result()
    {
        var events = new Mock<IEventAggregator>();
        events
            .Setup(e => e.PublishAsync(It.IsAny<CompromisedCredentialDetectedNotification>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("database is locked"));
        var service = TestSupport.Service(TestSupport.Client(found: true).Object, new DarkStrataOptions { ApiKey = TestSupport.ApiKey }, events.Object);

        Assert.True(await service.IsCompromisedAsync(CompromisedCredentialSource.MemberLogin, "a@example.com", "hunter2", "1"));
    }

    [Fact]
    public async Task Stalled_notification_handler_is_abandoned_after_the_timeout()
    {
        var events = new Mock<IEventAggregator>();
        events
            .Setup(e => e.PublishAsync(It.IsAny<CompromisedCredentialDetectedNotification>(), It.IsAny<CancellationToken>()))
            .Returns(new TaskCompletionSource().Task);
        var options = new DarkStrataOptions { ApiKey = TestSupport.ApiKey, NotificationTimeout = TimeSpan.FromMilliseconds(50) };
        var service = TestSupport.Service(TestSupport.Client(found: true).Object, options, events.Object);

        var check = service.IsCompromisedAsync(CompromisedCredentialSource.MemberLogin, "a@example.com", "hunter2", "1");

        Assert.Same(check, await Task.WhenAny(check, Task.Delay(TimeSpan.FromSeconds(5))));
        Assert.True(await check);
    }

    // Seen in a real site: Automate's SQLite outbox write blocks the calling thread before PublishAsync returns.
    [Fact]
    public async Task Synchronously_blocking_notification_handler_is_abandoned_after_the_timeout()
    {
        using var release = new ManualResetEventSlim();
        var events = new Mock<IEventAggregator>();
        events
            .Setup(e => e.PublishAsync(It.IsAny<CompromisedCredentialDetectedNotification>(), It.IsAny<CancellationToken>()))
            .Returns(() =>
            {
                release.Wait(TimeSpan.FromSeconds(10));
                return Task.CompletedTask;
            });
        var options = new DarkStrataOptions { ApiKey = TestSupport.ApiKey, NotificationTimeout = TimeSpan.FromMilliseconds(50) };
        var service = TestSupport.Service(TestSupport.Client(found: true).Object, options, events.Object);

        var check = Task.Run(() => service.IsCompromisedAsync(CompromisedCredentialSource.MemberLogin, "a@example.com", "hunter2", "1"));

        Assert.Same(check, await Task.WhenAny(check, Task.Delay(TimeSpan.FromSeconds(5))));
        Assert.True(await check);
        release.Set();
    }

    // Outside an HTTP request there is no request cache; the check must still run.
    [Fact]
    public async Task Works_without_a_request_cache()
    {
        var client = TestSupport.Client(found: true);
        var service = TestSupport.Service(
            client.Object,
            new DarkStrataOptions { ApiKey = TestSupport.ApiKey },
            requestCache: AppCaches.Disabled.RequestCache);

        Assert.True(await service.IsCompromisedAsync(CompromisedCredentialSource.MemberPassword, "a@example.com", "hunter2", "1"));
    }
}
