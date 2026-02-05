using Xunit;

namespace DarkStrata.CredentialCheck.Tests;

public class CryptoTests
{
    [Fact]
    public void Sha256_ReturnsCorrectHash()
    {
        // Known SHA-256 hash of "hello"
        var result = CryptoUtils.Sha256("hello");
        Assert.Equal("2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824", result);
    }

    [Fact]
    public void Sha256_ReturnsUppercaseHex()
    {
        var result = CryptoUtils.Sha256("test");
        Assert.Equal(result.ToUpperInvariant(), result);
    }

    [Fact]
    public void HashCredential_FormatsEmailPassword()
    {
        // SHA-256 of "user@example.com:password123"
        var expected = CryptoUtils.Sha256("user@example.com:password123");
        var result = CryptoUtils.HashCredential("user@example.com", "password123");
        Assert.Equal(expected, result);
    }

    [Fact]
    public void HashCredential_ReturnsUppercaseHex()
    {
        var result = CryptoUtils.HashCredential("test@test.com", "pass");
        Assert.Equal(result.ToUpperInvariant(), result);
    }

    [Fact]
    public void HmacSha256_ReturnsCorrectHmac()
    {
        // Test with known values
        var message = "test message";
        var keyHex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

        var result = CryptoUtils.HmacSha256(message, keyHex);

        Assert.NotNull(result);
        Assert.Equal(64, result.Length); // SHA-256 = 32 bytes = 64 hex chars
        Assert.Equal(result.ToUpperInvariant(), result);
    }

    [Fact]
    public void HmacSha256_SameInputProducesSameOutput()
    {
        var message = "consistent";
        var keyHex = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";

        var result1 = CryptoUtils.HmacSha256(message, keyHex);
        var result2 = CryptoUtils.HmacSha256(message, keyHex);

        Assert.Equal(result1, result2);
    }

    [Fact]
    public void HmacSha256_DifferentKeyProducesDifferentOutput()
    {
        var message = "test";
        var key1 = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        var key2 = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210";

        var result1 = CryptoUtils.HmacSha256(message, key1);
        var result2 = CryptoUtils.HmacSha256(message, key2);

        Assert.NotEqual(result1, result2);
    }

    [Fact]
    public void ExtractPrefix_ReturnsFirst5Characters()
    {
        var hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
        var result = CryptoUtils.ExtractPrefix(hash);
        Assert.Equal("5BAA6", result);
    }

    [Fact]
    public void ExtractPrefix_ReturnsUppercase()
    {
        var hash = "abcde1234567890";
        var result = CryptoUtils.ExtractPrefix(hash);
        Assert.Equal("ABCDE", result);
    }

    [Theory]
    [InlineData("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8000000000000000000000000", true)]
    [InlineData("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", true)]
    [InlineData("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", true)]
    [InlineData("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", false)] // Too short
    [InlineData("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD80000000000000000000000000", false)] // Too long
    [InlineData("ZZZZ61E4C9B93F3F0682250B6CF8331B7EE68FD8000000000000000000000000", false)] // Invalid chars
    [InlineData("", false)]
    public void IsValidHash_ValidatesCorrectly(string hash, bool expected)
    {
        var result = CryptoUtils.IsValidHash(hash);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("5BAA6", true)]
    [InlineData("ABCDE", true)]
    [InlineData("abcde", true)]
    [InlineData("12345", true)]
    [InlineData("5BAA", false)] // Too short
    [InlineData("5BAA61", false)] // Too long
    [InlineData("ZZZZZ", false)] // Invalid chars
    [InlineData("", false)]
    public void IsValidPrefix_ValidatesCorrectly(string prefix, bool expected)
    {
        var result = CryptoUtils.IsValidPrefix(prefix);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void IsHashInSet_ReturnsTrueWhenFound()
    {
        var hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8000000000000000000000000";
        var hmacKey = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

        // Compute expected HMAC
        var expectedHmac = CryptoUtils.HmacSha256(hash, hmacKey);

        var hmacHashes = new[] { "DEADBEEF", expectedHmac, "12345678" };

        var result = CryptoUtils.IsHashInSet(hash, hmacKey, hmacHashes);
        Assert.True(result);
    }

    [Fact]
    public void IsHashInSet_ReturnsFalseWhenNotFound()
    {
        var hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8000000000000000000000000";
        var hmacKey = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

        var hmacHashes = new[] { "DEADBEEF12345678901234567890123456789012345678901234567890123456", "CAFEBABE12345678901234567890123456789012345678901234567890123456" };

        var result = CryptoUtils.IsHashInSet(hash, hmacKey, hmacHashes);
        Assert.False(result);
    }

    [Fact]
    public void IsHashInSet_HandlesInvalidHexStrings()
    {
        var hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8000000000000000000000000";
        var hmacKey = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

        var hmacHashes = new[] { "INVALID_HEX", "NOT_HEX_AT_ALL", "!!!" };

        // Should not throw, just return false
        var result = CryptoUtils.IsHashInSet(hash, hmacKey, hmacHashes);
        Assert.False(result);
    }

    [Fact]
    public void IsHashInSet_HandlesEmptySet()
    {
        var hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8000000000000000000000000";
        var hmacKey = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

        var result = CryptoUtils.IsHashInSet(hash, hmacKey, []);
        Assert.False(result);
    }

    [Fact]
    public void GroupByPrefix_GroupsCorrectly()
    {
        var credentials = new[]
        {
            new TestCredential("hash1", "5BAA61234567890123456789012345678901234567890123456789012345678"),
            new TestCredential("hash2", "5BAA62234567890123456789012345678901234567890123456789012345678"),
            new TestCredential("hash3", "ABCDE1234567890123456789012345678901234567890123456789012345678"),
        };

        var groups = CryptoUtils.GroupByPrefix(credentials, c => c.Hash);

        Assert.Equal(2, groups.Count);
        Assert.Equal(2, groups["5BAA6"].Count);
        Assert.Single(groups["ABCDE"]);
    }

    [Fact]
    public void GroupByPrefix_HandlesEmptyInput()
    {
        var credentials = Array.Empty<TestCredential>();
        var groups = CryptoUtils.GroupByPrefix(credentials, c => c.Hash);
        Assert.Empty(groups);
    }

    private sealed record TestCredential(string Name, string Hash);
}
