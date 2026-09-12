using DarkStrata.CredentialCheck.Umbraco;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Umbraco.Cms.Core.Events;

namespace DarkStrata.CredentialCheck.Umbraco.Tests;

internal static class TestSupport
{
    public const string ApiKey = "ds_test_key";

    public static CheckResult Result(bool found) =>
        new(found, "user@example.com", new CheckMetadata("ABCDE", 1, HmacSource.Server, null, null, false, DateTimeOffset.UtcNow));

    public static Mock<IDarkStrataCredentialCheck> Client(bool found)
    {
        var client = new Mock<IDarkStrataCredentialCheck>();
        client
            .Setup(c => c.CheckAsync(It.IsAny<string>(), It.IsAny<string>(), null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result(found));
        return client;
    }

    public static Mock<IDarkStrataCredentialCheck> FailingClient()
    {
        var client = new Mock<IDarkStrataCredentialCheck>();
        client
            .Setup(c => c.CheckAsync(It.IsAny<string>(), It.IsAny<string>(), null, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new NetworkException("boom"));
        return client;
    }

    public static IOptionsMonitor<DarkStrataOptions> Options(DarkStrataOptions options)
    {
        var monitor = new Mock<IOptionsMonitor<DarkStrataOptions>>();
        monitor.Setup(m => m.CurrentValue).Returns(options);
        return monitor.Object;
    }

    public static CompromisedCredentialService Service(IDarkStrataCredentialCheck client, DarkStrataOptions options, IEventAggregator? events = null) =>
        new(client, events ?? Mock.Of<IEventAggregator>(), Options(options), NullLogger<CompromisedCredentialService>.Instance);
}
