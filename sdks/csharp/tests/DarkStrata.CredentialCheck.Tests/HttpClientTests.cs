using System.Net;
using System.Text.Json;
using DarkStrata.CredentialCheck;
using Xunit;

namespace DarkStrata.CredentialCheck.Tests;

public class HttpClientTests : IDisposable
{
    private readonly MockHttpHandler _handler;
    private readonly DarkStrataCredentialCheck _client;

    public HttpClientTests()
    {
        _handler = new MockHttpHandler();
        _client = new DarkStrataCredentialCheck(
            new ClientOptions
            {
                ApiKey = "test-api-key",
                BaseUrl = "https://api.test.local/v1/",
                Retries = 0,
                EnableCaching = false
            },
            _handler);
    }

    public void Dispose()
    {
        _client.Dispose();
        _handler.Dispose();
    }

    [Fact]
    public async Task CheckAsync_NotFound_ReturnsFoundFalse()
    {
        var hmacKey = new string('A', 64);
        _handler.SetResponse(HttpStatusCode.OK,
            JsonSerializer.Serialize(Array.Empty<string>()),
            new Dictionary<string, string>
            {
                ["X-Prefix"] = "ABCDE",
                ["X-HMAC-Key"] = hmacKey,
                ["X-HMAC-Source"] = "server",
                ["X-Total-Results"] = "0"
            });

        var result = await _client.CheckAsync("test@example.com", "password123");

        Assert.False(result.Found);
        Assert.Equal("test@example.com", result.Email);
        Assert.True(result.Masked);
        Assert.NotNull(result.Metadata);
    }

    [Fact]
    public async Task CheckAsync_Found_ReturnsFoundTrue()
    {
        var email = "test@example.com";
        var password = "password123";
        var hash = CryptoUtils.HashCredential(email, password);
        var hmacKey = new string('A', 64);
        var hmacOfHash = CryptoUtils.HmacSha256(hash, hmacKey);

        _handler.SetResponse(HttpStatusCode.OK,
            JsonSerializer.Serialize(new[] { hmacOfHash }),
            new Dictionary<string, string>
            {
                ["X-Prefix"] = CryptoUtils.ExtractPrefix(hash),
                ["X-HMAC-Key"] = hmacKey,
                ["X-HMAC-Source"] = "server",
                ["X-Total-Results"] = "1"
            });

        var result = await _client.CheckAsync(email, password);

        Assert.True(result.Found);
        Assert.Equal(email, result.Email);
    }

    [Fact]
    public async Task CheckAsync_401_ThrowsAuthenticationException()
    {
        _handler.SetResponse(HttpStatusCode.Unauthorized, "");

        await Assert.ThrowsAsync<AuthenticationException>(
            () => _client.CheckAsync("test@example.com", "password123"));
    }

    [Fact]
    public async Task CheckAsync_429_ThrowsRateLimitException()
    {
        _handler.SetResponse(HttpStatusCode.TooManyRequests, "",
            new Dictionary<string, string> { ["Retry-After"] = "60" });

        var ex = await Assert.ThrowsAsync<RateLimitException>(
            () => _client.CheckAsync("test@example.com", "password123"));

        Assert.Equal(60, ex.RetryAfter);
    }

    [Fact]
    public async Task CheckAsync_500_ThrowsApiException()
    {
        _handler.SetResponse(HttpStatusCode.InternalServerError,
            "{\"error\": \"Internal server error\"}");

        var ex = await Assert.ThrowsAsync<ApiException>(
            () => _client.CheckAsync("test@example.com", "password123"));

        Assert.Equal(500, ex.StatusCode);
        Assert.True(ex.IsRetryable);
    }

    [Fact]
    public async Task CheckHashAsync_Found_ReturnsCorrectResult()
    {
        var email = "test@example.com";
        var password = "password123";
        var hash = CryptoUtils.HashCredential(email, password);
        var hmacKey = new string('A', 64);
        var hmacOfHash = CryptoUtils.HmacSha256(hash, hmacKey);

        _handler.SetResponse(HttpStatusCode.OK,
            JsonSerializer.Serialize(new[] { hmacOfHash }),
            new Dictionary<string, string>
            {
                ["X-Prefix"] = CryptoUtils.ExtractPrefix(hash),
                ["X-HMAC-Key"] = hmacKey,
                ["X-HMAC-Source"] = "server",
                ["X-Total-Results"] = "1"
            });

        var result = await _client.CheckHashAsync(hash);

        Assert.True(result.Found);
        Assert.Equal("[hash-only]", result.Email);
    }

    [Fact]
    public async Task CheckBatchAsync_ReturnsResultsInOrder()
    {
        var hmacKey = new string('A', 64);

        _handler.SetResponse(HttpStatusCode.OK,
            JsonSerializer.Serialize(Array.Empty<string>()),
            new Dictionary<string, string>
            {
                ["X-Prefix"] = "12345",
                ["X-HMAC-Key"] = hmacKey,
                ["X-HMAC-Source"] = "server",
                ["X-Total-Results"] = "0"
            });

        var credentials = new[]
        {
            new Credential("user1@example.com", "pass1"),
            new Credential("user2@example.com", "pass2")
        };

        var results = await _client.CheckBatchAsync(credentials);

        Assert.Equal(2, results.Count);
        Assert.Equal("user1@example.com", results[0].Email);
        Assert.Equal("user2@example.com", results[1].Email);
    }

    [Fact]
    public async Task CheckAsync_ClientHmacOption_SendsQueryParameter()
    {
        var hmacKey = new string('A', 64);
        var clientHmac = new string('B', 64);

        _handler.SetResponse(HttpStatusCode.OK,
            JsonSerializer.Serialize(Array.Empty<string>()),
            new Dictionary<string, string>
            {
                ["X-Prefix"] = "ABCDE",
                ["X-HMAC-Key"] = hmacKey,
                ["X-HMAC-Source"] = "client",
                ["X-Total-Results"] = "0"
            });

        await _client.CheckAsync("test@example.com", "password123",
            new CheckOptions { ClientHmac = clientHmac });

        var lastUri = _handler.LastRequestUri!;
        Assert.Contains("clientHmac=" + clientHmac, lastUri.Query);
    }

    [Fact]
    public async Task CheckAsync_SinceOption_SendsQueryParameter()
    {
        var hmacKey = new string('A', 64);

        _handler.SetResponse(HttpStatusCode.OK,
            JsonSerializer.Serialize(Array.Empty<string>()),
            new Dictionary<string, string>
            {
                ["X-Prefix"] = "ABCDE",
                ["X-HMAC-Key"] = hmacKey,
                ["X-HMAC-Source"] = "server",
                ["X-Total-Results"] = "0"
            });

        var sinceDate = new DateTimeOffset(2023, 6, 15, 0, 0, 0, TimeSpan.Zero);
        await _client.CheckAsync("test@example.com", "password123",
            new CheckOptions { Since = sinceDate });

        var lastUri = _handler.LastRequestUri!;
        Assert.Contains("since=", lastUri.Query);
    }

    [Fact]
    public async Task CheckAsync_CachingEnabled_SecondCallUsesCache()
    {
        using var handler = new MockHttpHandler();
        using var cachingClient = new DarkStrataCredentialCheck(
            new ClientOptions
            {
                ApiKey = "test-api-key",
                BaseUrl = "https://api.test.local/v1/",
                Retries = 0,
                EnableCaching = true,
                CacheTtl = TimeSpan.FromMinutes(10)
            },
            handler);

        var hmacKey = new string('A', 64);
        var timeWindow = (int)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 3600);

        handler.SetResponse(HttpStatusCode.OK,
            JsonSerializer.Serialize(Array.Empty<string>()),
            new Dictionary<string, string>
            {
                ["X-Prefix"] = "ABCDE",
                ["X-HMAC-Key"] = hmacKey,
                ["X-HMAC-Source"] = "server",
                ["X-Time-Window"] = timeWindow.ToString(),
                ["X-Total-Results"] = "0"
            });

        // First call - should hit the handler
        await cachingClient.CheckAsync("test@example.com", "password123");
        Assert.Equal(1, handler.RequestCount);

        // Second call with same prefix - should use cache
        await cachingClient.CheckAsync("test@example.com", "password123");
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task CheckAsync_CachingEnabled_OptionsSkipCache()
    {
        using var handler = new MockHttpHandler();
        using var cachingClient = new DarkStrataCredentialCheck(
            new ClientOptions
            {
                ApiKey = "test-api-key",
                BaseUrl = "https://api.test.local/v1/",
                Retries = 0,
                EnableCaching = true,
                CacheTtl = TimeSpan.FromMinutes(10)
            },
            handler);

        var hmacKey = new string('A', 64);
        var clientHmac = new string('B', 64);
        var timeWindow = (int)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 3600);

        handler.SetResponse(HttpStatusCode.OK,
            JsonSerializer.Serialize(Array.Empty<string>()),
            new Dictionary<string, string>
            {
                ["X-Prefix"] = "ABCDE",
                ["X-HMAC-Key"] = hmacKey,
                ["X-HMAC-Source"] = "server",
                ["X-Time-Window"] = timeWindow.ToString(),
                ["X-Total-Results"] = "0"
            });

        // First call
        await cachingClient.CheckAsync("test@example.com", "password123");
        Assert.Equal(1, handler.RequestCount);

        // Second call with options - should NOT use cache
        await cachingClient.CheckAsync("test@example.com", "password123",
            new CheckOptions { ClientHmac = clientHmac });
        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task CheckAsync_SendsCorrectHeaders()
    {
        var hmacKey = new string('A', 64);
        _handler.SetResponse(HttpStatusCode.OK,
            JsonSerializer.Serialize(Array.Empty<string>()),
            new Dictionary<string, string>
            {
                ["X-Prefix"] = "ABCDE",
                ["X-HMAC-Key"] = hmacKey,
                ["X-HMAC-Source"] = "server",
                ["X-Total-Results"] = "0"
            });

        await _client.CheckAsync("test@example.com", "password123");

        var request = _handler.LastRequest!;
        Assert.Equal("test-api-key", request.Headers.GetValues("X-Api-Key").First());
        Assert.Contains("DarkStrata.CredentialCheck", request.Headers.UserAgent.ToString());
        Assert.Contains("application/json", request.Headers.Accept.ToString());
    }

    [Fact]
    public async Task CheckAsync_SendsCorrectPrefix()
    {
        var hmacKey = new string('A', 64);
        _handler.SetResponse(HttpStatusCode.OK,
            JsonSerializer.Serialize(Array.Empty<string>()),
            new Dictionary<string, string>
            {
                ["X-Prefix"] = "ABCDE",
                ["X-HMAC-Key"] = hmacKey,
                ["X-HMAC-Source"] = "server",
                ["X-Total-Results"] = "0"
            });

        await _client.CheckAsync("test@example.com", "password123");

        var lastUri = _handler.LastRequestUri!;
        var queryString = lastUri.Query;
        Assert.Contains("prefix=", queryString);
        // Extract prefix value and verify it's 5 characters
        var prefixStart = queryString.IndexOf("prefix=", StringComparison.Ordinal) + "prefix=".Length;
        var prefixEnd = queryString.IndexOf('&', prefixStart);
        var prefix = prefixEnd == -1 ? queryString[prefixStart..] : queryString[prefixStart..prefixEnd];
        Assert.Equal(5, prefix.Length);
    }

    [Fact]
    public async Task CheckAsync_MetadataPopulatedCorrectly()
    {
        var hash = CryptoUtils.HashCredential("test@example.com", "password123");
        var expectedPrefix = CryptoUtils.ExtractPrefix(hash);
        var hmacKey = new string('A', 64);

        _handler.SetResponse(HttpStatusCode.OK,
            JsonSerializer.Serialize(Array.Empty<string>()),
            new Dictionary<string, string>
            {
                ["X-Prefix"] = expectedPrefix,
                ["X-HMAC-Key"] = hmacKey,
                ["X-HMAC-Source"] = "server",
                ["X-Time-Window"] = "12345",
                ["X-Total-Results"] = "100",
                ["X-Filter-Since"] = "19000"
            });

        var result = await _client.CheckAsync("test@example.com", "password123");
        var metadata = result.Metadata;

        Assert.Equal(expectedPrefix, metadata.Prefix);
        Assert.Equal(100, metadata.TotalResults);
        Assert.Equal(HmacSource.Server, metadata.HmacSource);
        Assert.Equal(12345, metadata.TimeWindow);
        Assert.Equal(19000, metadata.FilterSince);
        Assert.NotEqual(default, metadata.CheckedAt);
    }

    [Fact]
    public async Task CheckAsync_UsesGetMethod()
    {
        var hmacKey = new string('A', 64);
        _handler.SetResponse(HttpStatusCode.OK,
            JsonSerializer.Serialize(Array.Empty<string>()),
            new Dictionary<string, string>
            {
                ["X-Prefix"] = "ABCDE",
                ["X-HMAC-Key"] = hmacKey,
                ["X-HMAC-Source"] = "server",
                ["X-Total-Results"] = "0"
            });

        await _client.CheckAsync("test@example.com", "password123");

        Assert.Equal(HttpMethod.Get, _handler.LastRequest!.Method);
    }

    /// <summary>
    /// Mock HttpMessageHandler that returns configurable responses.
    /// </summary>
    private sealed class MockHttpHandler : HttpMessageHandler
    {
        private HttpStatusCode _statusCode = HttpStatusCode.OK;
        private string _content = "[]";
        private Dictionary<string, string>? _headers;

        public HttpRequestMessage? LastRequest { get; private set; }
        public Uri? LastRequestUri { get; private set; }
        public int RequestCount { get; private set; }

        public void SetResponse(HttpStatusCode statusCode, string content,
            Dictionary<string, string>? headers = null)
        {
            _statusCode = statusCode;
            _content = content;
            _headers = headers;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            LastRequestUri = request.RequestUri;
            RequestCount++;

            var response = new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_content, System.Text.Encoding.UTF8, "application/json")
            };

            if (_headers is not null)
            {
                foreach (var (key, value) in _headers)
                {
                    response.Headers.TryAddWithoutValidation(key, value);
                }
            }

            return Task.FromResult(response);
        }
    }
}
