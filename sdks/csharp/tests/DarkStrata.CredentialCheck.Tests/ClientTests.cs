using Xunit;

namespace DarkStrata.CredentialCheck.Tests;

public class ClientTests
{
    private const string ValidApiKey = "test-api-key-12345";
    private const string TestEmail = "user@example.com";
    private const string TestPassword = "password123";
    private const string TestHmacKey = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    #region Constructor Tests

    [Fact]
    public void Constructor_WithValidOptions_CreatesClient()
    {
        using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = ValidApiKey });
        Assert.NotNull(client);
    }

    [Fact]
    public void Constructor_WithNullApiKey_ThrowsValidationException()
    {
        var exception = Assert.Throws<ValidationException>(() =>
            new DarkStrataCredentialCheck(new ClientOptions { ApiKey = null! }));

        Assert.Equal("apiKey", exception.Field);
    }

    [Fact]
    public void Constructor_WithEmptyApiKey_ThrowsValidationException()
    {
        var exception = Assert.Throws<ValidationException>(() =>
            new DarkStrataCredentialCheck(new ClientOptions { ApiKey = "" }));

        Assert.Equal("apiKey", exception.Field);
    }

    [Fact]
    public void Constructor_WithWhitespaceApiKey_ThrowsValidationException()
    {
        var exception = Assert.Throws<ValidationException>(() =>
            new DarkStrataCredentialCheck(new ClientOptions { ApiKey = "   " }));

        Assert.Equal("apiKey", exception.Field);
    }

    [Fact]
    public void Constructor_WithNegativeTimeout_ThrowsValidationException()
    {
        var exception = Assert.Throws<ValidationException>(() =>
            new DarkStrataCredentialCheck(new ClientOptions
            {
                ApiKey = ValidApiKey,
                Timeout = TimeSpan.FromSeconds(-1)
            }));

        Assert.Equal("timeout", exception.Field);
    }

    [Fact]
    public void Constructor_WithNegativeRetries_ThrowsValidationException()
    {
        var exception = Assert.Throws<ValidationException>(() =>
            new DarkStrataCredentialCheck(new ClientOptions
            {
                ApiKey = ValidApiKey,
                Retries = -1
            }));

        Assert.Equal("retries", exception.Field);
    }

    [Fact]
    public void Constructor_WithNegativeCacheTtl_ThrowsValidationException()
    {
        var exception = Assert.Throws<ValidationException>(() =>
            new DarkStrataCredentialCheck(new ClientOptions
            {
                ApiKey = ValidApiKey,
                CacheTtl = TimeSpan.FromSeconds(-1)
            }));

        Assert.Equal("cacheTtl", exception.Field);
    }

    #endregion

    #region Validation Tests

    [Fact]
    public async Task CheckAsync_WithNullEmail_ThrowsValidationException()
    {
        using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = ValidApiKey });

        var exception = await Assert.ThrowsAsync<ValidationException>(() =>
            client.CheckAsync(null!, TestPassword));

        Assert.Equal("email", exception.Field);
    }

    [Fact]
    public async Task CheckAsync_WithEmptyEmail_ThrowsValidationException()
    {
        using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = ValidApiKey });

        var exception = await Assert.ThrowsAsync<ValidationException>(() =>
            client.CheckAsync("", TestPassword));

        Assert.Equal("email", exception.Field);
    }

    [Fact]
    public async Task CheckAsync_WithNullPassword_ThrowsValidationException()
    {
        using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = ValidApiKey });

        var exception = await Assert.ThrowsAsync<ValidationException>(() =>
            client.CheckAsync(TestEmail, null!));

        Assert.Equal("password", exception.Field);
    }

    [Fact]
    public async Task CheckAsync_WithEmptyPassword_ThrowsValidationException()
    {
        using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = ValidApiKey });

        var exception = await Assert.ThrowsAsync<ValidationException>(() =>
            client.CheckAsync(TestEmail, ""));

        Assert.Equal("password", exception.Field);
    }

    [Fact]
    public async Task CheckHashAsync_WithInvalidHash_ThrowsValidationException()
    {
        using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = ValidApiKey });

        var exception = await Assert.ThrowsAsync<ValidationException>(() =>
            client.CheckHashAsync("invalid"));

        Assert.Equal("hash", exception.Field);
    }

    [Fact]
    public async Task CheckAsync_WithShortClientHmac_ThrowsValidationException()
    {
        using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = ValidApiKey });

        var exception = await Assert.ThrowsAsync<ValidationException>(() =>
            client.CheckAsync(TestEmail, TestPassword, new CheckOptions { ClientHmac = "short" }));

        Assert.Equal("clientHmac", exception.Field);
    }

    [Fact]
    public async Task CheckAsync_WithNonHexClientHmac_ThrowsValidationException()
    {
        using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = ValidApiKey });

        var exception = await Assert.ThrowsAsync<ValidationException>(() =>
            client.CheckAsync(TestEmail, TestPassword, new CheckOptions
            {
                ClientHmac = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
            }));

        Assert.Equal("clientHmac", exception.Field);
    }

    [Fact]
    public async Task CheckAsync_WithNegativeSinceEpochDay_ThrowsValidationException()
    {
        using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = ValidApiKey });

        var exception = await Assert.ThrowsAsync<ValidationException>(() =>
            client.CheckAsync(TestEmail, TestPassword, new CheckOptions { SinceEpochDay = -1 }));

        Assert.Equal("sinceEpochDay", exception.Field);
    }

    #endregion

    #region CheckBatch Tests

    [Fact]
    public async Task CheckBatchAsync_WithEmptyList_ReturnsEmptyResults()
    {
        using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = ValidApiKey });

        var results = await client.CheckBatchAsync([]);

        Assert.Empty(results);
    }

    [Fact]
    public async Task CheckBatchAsync_ValidatesAllCredentials()
    {
        using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = ValidApiKey });

        var credentials = new[]
        {
            new Credential(TestEmail, TestPassword),
            new Credential("", TestPassword) // Invalid
        };

        await Assert.ThrowsAsync<ValidationException>(() =>
            client.CheckBatchAsync(credentials));
    }

    #endregion

    #region Cache Tests

    [Fact]
    public void ClearCache_ClearsAllEntries()
    {
        using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = ValidApiKey });

        // Cache starts empty
        Assert.Equal(0, client.GetCacheSize());

        client.ClearCache();

        Assert.Equal(0, client.GetCacheSize());
    }

    [Fact]
    public void GetCacheSize_ReturnsZeroInitially()
    {
        using var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = ValidApiKey });

        Assert.Equal(0, client.GetCacheSize());
    }

    #endregion

    #region Dispose Tests

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        var client = new DarkStrataCredentialCheck(new ClientOptions { ApiKey = ValidApiKey });

        client.Dispose();
        client.Dispose(); // Should not throw
    }

    #endregion

    #region Types Tests

    [Fact]
    public void Credential_RecordEquality()
    {
        var cred1 = new Credential("email", "pass");
        var cred2 = new Credential("email", "pass");

        Assert.Equal(cred1, cred2);
    }

    [Fact]
    public void HmacSource_HasExpectedValues()
    {
        Assert.Equal(0, (int)HmacSource.Server);
        Assert.Equal(1, (int)HmacSource.Client);
    }

    [Fact]
    public void CheckResult_Masked_AlwaysTrue()
    {
        var result = new CheckResult
        {
            Found = false,
            Email = "test@test.com",
            Metadata = new CheckMetadata
            {
                Prefix = "12345",
                TotalResults = 0,
                HmacSource = HmacSource.Server,
                CachedResult = false,
                CheckedAt = DateTimeOffset.UtcNow
            }
        };

        Assert.True(result.Masked);
    }

    #endregion
}
