using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DarkStrata.CredentialCheck;

/// <summary>
/// Cryptographic utility functions for credential checking.
/// </summary>
public static partial class CryptoUtils
{
    private const int PrefixLength = 5;

    /// <summary>
    /// Compute SHA-256 hash of a credential pair.
    /// The credential is formatted as "email:password" before hashing.
    /// </summary>
    /// <param name="email">The email address or username.</param>
    /// <param name="password">The password.</param>
    /// <returns>The SHA-256 hash as an uppercase hexadecimal string.</returns>
    public static string HashCredential(string email, string password)
    {
        var credential = $"{email}:{password}";
        return Sha256(credential);
    }

    /// <summary>
    /// Compute SHA-256 hash of a string.
    /// </summary>
    /// <param name="input">The string to hash.</param>
    /// <returns>The SHA-256 hash as an uppercase hexadecimal string.</returns>
    public static string Sha256(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash);
    }

    /// <summary>
    /// Compute HMAC-SHA256 of a message with a key.
    /// </summary>
    /// <param name="message">The message to authenticate.</param>
    /// <param name="keyHex">The HMAC key as a hexadecimal string.</param>
    /// <returns>The HMAC-SHA256 as an uppercase hexadecimal string.</returns>
    public static string HmacSha256(string message, string keyHex)
    {
        var keyBytes = Convert.FromHexString(keyHex);
        var messageBytes = Encoding.UTF8.GetBytes(message);
        var hmac = HMACSHA256.HashData(keyBytes, messageBytes);
        return Convert.ToHexString(hmac);
    }

    /// <summary>
    /// Extract the k-anonymity prefix from a hash.
    /// </summary>
    /// <param name="hash">The full SHA-256 hash (64 hex characters).</param>
    /// <returns>The first 5 characters (prefix) in uppercase.</returns>
    public static string ExtractPrefix(string hash)
    {
        return hash[..PrefixLength].ToUpperInvariant();
    }

    /// <summary>
    /// Check if a hash is in a set of HMAC'd hashes.
    /// Uses timing-safe comparison to prevent timing attacks.
    /// </summary>
    /// <param name="hash">The full hash to check.</param>
    /// <param name="hmacKey">The HMAC key from the API response.</param>
    /// <param name="hmacHashes">Collection of HMAC'd hashes from the API.</param>
    /// <returns>True if the hash is found in the set.</returns>
    public static bool IsHashInSet(string hash, string hmacKey, IEnumerable<string> hmacHashes)
    {
        // Compute HMAC of the full hash
        var targetHmac = HmacSha256(hash, hmacKey);
        var targetBytes = Convert.FromHexString(targetHmac);

        foreach (var hmacHash in hmacHashes)
        {
            try
            {
                var candidateBytes = Convert.FromHexString(hmacHash);
                if (targetBytes.Length == candidateBytes.Length &&
                    CryptographicOperations.FixedTimeEquals(targetBytes, candidateBytes))
                {
                    return true;
                }
            }
            catch (FormatException)
            {
                // Invalid hex string, skip
                continue;
            }
        }

        return false;
    }

    /// <summary>
    /// Validate that a string is a valid hexadecimal hash.
    /// </summary>
    /// <param name="hash">The string to validate.</param>
    /// <param name="expectedLength">Expected length (default: 64 for SHA-256).</param>
    /// <returns>True if the string is valid hex of the expected length.</returns>
    public static bool IsValidHash(string hash, int expectedLength = 64)
    {
        if (hash.Length != expectedLength)
        {
            return false;
        }
        return HexPattern().IsMatch(hash);
    }

    /// <summary>
    /// Validate that a string is a valid k-anonymity prefix.
    /// </summary>
    /// <param name="prefix">The prefix to validate.</param>
    /// <returns>True if the prefix is valid (5 hex characters).</returns>
    public static bool IsValidPrefix(string prefix)
    {
        return prefix.Length == PrefixLength && HexPattern().IsMatch(prefix);
    }

    /// <summary>
    /// Group credentials by their hash prefix for efficient batch processing.
    /// </summary>
    /// <typeparam name="T">The credential type (must have a Hash property).</typeparam>
    /// <param name="credentials">Array of credential objects with Hash property.</param>
    /// <param name="hashSelector">Function to extract the hash from a credential.</param>
    /// <returns>Dictionary of prefix to list of credentials.</returns>
    public static Dictionary<string, List<T>> GroupByPrefix<T>(
        IEnumerable<T> credentials,
        Func<T, string> hashSelector)
    {
        var groups = new Dictionary<string, List<T>>();

        foreach (var credential in credentials)
        {
            var prefix = ExtractPrefix(hashSelector(credential));
            if (!groups.TryGetValue(prefix, out var list))
            {
                list = [];
                groups[prefix] = list;
            }
            list.Add(credential);
        }

        return groups;
    }

    [GeneratedRegex("^[A-Fa-f0-9]+$")]
    private static partial Regex HexPattern();
}
