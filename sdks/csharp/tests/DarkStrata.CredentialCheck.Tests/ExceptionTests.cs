using Xunit;

namespace DarkStrata.CredentialCheck.Tests;

public class ExceptionTests
{
    [Fact]
    public void DarkStrataException_SetsPropertiesCorrectly()
    {
        var exception = new DarkStrataException(
            "Test message",
            ErrorCode.ApiError,
            statusCode: 500,
            isRetryable: true);

        Assert.Equal("Test message", exception.Message);
        Assert.Equal(ErrorCode.ApiError, exception.Code);
        Assert.Equal(500, exception.StatusCode);
        Assert.True(exception.IsRetryable);
    }

    [Fact]
    public void DarkStrataException_PreservesInnerException()
    {
        var inner = new InvalidOperationException("Inner error");
        var exception = new DarkStrataException(
            "Outer message",
            ErrorCode.NetworkError,
            innerException: inner);

        Assert.Same(inner, exception.InnerException);
    }

    [Fact]
    public void AuthenticationException_HasCorrectDefaults()
    {
        var exception = new AuthenticationException();

        Assert.Equal("Invalid or missing API key", exception.Message);
        Assert.Equal(ErrorCode.AuthenticationError, exception.Code);
        Assert.Equal(401, exception.StatusCode);
        Assert.False(exception.IsRetryable);
    }

    [Fact]
    public void AuthenticationException_AcceptsCustomMessage()
    {
        var exception = new AuthenticationException("Custom auth error");

        Assert.Equal("Custom auth error", exception.Message);
        Assert.Equal(ErrorCode.AuthenticationError, exception.Code);
    }

    [Fact]
    public void ValidationException_SetsFieldProperty()
    {
        var exception = new ValidationException("Invalid email", "email");

        Assert.Equal("Invalid email", exception.Message);
        Assert.Equal(ErrorCode.ValidationError, exception.Code);
        Assert.Equal("email", exception.Field);
        Assert.False(exception.IsRetryable);
    }

    [Fact]
    public void ValidationException_FieldCanBeNull()
    {
        var exception = new ValidationException("General validation error");

        Assert.Null(exception.Field);
    }

    [Fact]
    public void ApiException_SetsAllProperties()
    {
        var exception = new ApiException(
            "Request failed",
            statusCode: 503,
            responseBody: "{\"error\": \"service unavailable\"}",
            isRetryable: true);

        Assert.Equal("Request failed", exception.Message);
        Assert.Equal(ErrorCode.ApiError, exception.Code);
        Assert.Equal(503, exception.StatusCode);
        Assert.Equal("{\"error\": \"service unavailable\"}", exception.ResponseBody);
        Assert.True(exception.IsRetryable);
    }

    [Fact]
    public void DarkStrataTimeoutException_SetsTimeoutMs()
    {
        var exception = new DarkStrataTimeoutException(30000);

        Assert.Equal("Request timed out after 30000ms", exception.Message);
        Assert.Equal(ErrorCode.TimeoutError, exception.Code);
        Assert.Equal(30000, exception.TimeoutMs);
        Assert.True(exception.IsRetryable);
    }

    [Fact]
    public void DarkStrataTimeoutException_PreservesInnerException()
    {
        var inner = new TaskCanceledException("Operation canceled");
        var exception = new DarkStrataTimeoutException(5000, inner);

        Assert.Same(inner, exception.InnerException);
    }

    [Fact]
    public void NetworkException_IsRetryable()
    {
        var exception = new NetworkException("Connection refused");

        Assert.Equal("Connection refused", exception.Message);
        Assert.Equal(ErrorCode.NetworkError, exception.Code);
        Assert.True(exception.IsRetryable);
    }

    [Fact]
    public void RateLimitException_WithRetryAfter()
    {
        var exception = new RateLimitException(60);

        Assert.Equal("Rate limit exceeded. Retry after 60 seconds.", exception.Message);
        Assert.Equal(ErrorCode.RateLimitError, exception.Code);
        Assert.Equal(429, exception.StatusCode);
        Assert.Equal(60, exception.RetryAfter);
        Assert.True(exception.IsRetryable);
    }

    [Fact]
    public void RateLimitException_WithoutRetryAfter()
    {
        var exception = new RateLimitException();

        Assert.Equal("Rate limit exceeded.", exception.Message);
        Assert.Null(exception.RetryAfter);
    }

    [Theory]
    [InlineData(ErrorCode.AuthenticationError)]
    [InlineData(ErrorCode.ValidationError)]
    [InlineData(ErrorCode.ApiError)]
    [InlineData(ErrorCode.TimeoutError)]
    [InlineData(ErrorCode.NetworkError)]
    [InlineData(ErrorCode.RateLimitError)]
    public void ErrorCode_AllValuesAreDefined(ErrorCode code)
    {
        Assert.True(Enum.IsDefined(code));
    }

    [Fact]
    public void AllExceptions_InheritFromDarkStrataException()
    {
        Assert.True(typeof(AuthenticationException).IsSubclassOf(typeof(DarkStrataException)));
        Assert.True(typeof(ValidationException).IsSubclassOf(typeof(DarkStrataException)));
        Assert.True(typeof(ApiException).IsSubclassOf(typeof(DarkStrataException)));
        Assert.True(typeof(DarkStrataTimeoutException).IsSubclassOf(typeof(DarkStrataException)));
        Assert.True(typeof(NetworkException).IsSubclassOf(typeof(DarkStrataException)));
        Assert.True(typeof(RateLimitException).IsSubclassOf(typeof(DarkStrataException)));
    }
}
