#if NETSTANDARD2_0
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace DarkStrata.CredentialCheck.Compatibility
{
    internal static class PolyfillHelpers
    {
        private static readonly char[] HexChars = "0123456789ABCDEF".ToCharArray();

        /// <summary>
        /// Converts a byte array to a hexadecimal string (uppercase).
        /// Polyfill for Convert.ToHexString() which is not available in .NET Standard 2.0.
        /// </summary>
        public static string ToHexString(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            var result = new char[bytes.Length * 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                result[i * 2] = HexChars[bytes[i] >> 4];
                result[i * 2 + 1] = HexChars[bytes[i] & 0x0F];
            }
            return new string(result);
        }

        /// <summary>
        /// Converts a hexadecimal string to a byte array.
        /// Polyfill for Convert.FromHexString() which is not available in .NET Standard 2.0.
        /// </summary>
        public static byte[] FromHexString(string hex)
        {
            if (hex == null)
                throw new ArgumentNullException(nameof(hex));

            if (hex.Length % 2 != 0)
                throw new FormatException("The input is not a valid hex string as its length is not a multiple of 2.");

            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = (byte)((GetHexValue(hex[i * 2]) << 4) + GetHexValue(hex[i * 2 + 1]));
            }
            return bytes;
        }

        private static int GetHexValue(char c)
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            throw new FormatException($"Invalid hex character: {c}");
        }

        /// <summary>
        /// Computes SHA256 hash of a byte array.
        /// Polyfill for SHA256.HashData() which is not available in .NET Standard 2.0.
        /// </summary>
        public static byte[] Sha256Hash(byte[] data)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(data);
            }
        }

        /// <summary>
        /// Computes HMAC-SHA256 of data with a key.
        /// Polyfill for HMACSHA256.HashData() which is not available in .NET Standard 2.0.
        /// </summary>
        public static byte[] HmacSha256Hash(byte[] key, byte[] data)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(data);
            }
        }

        /// <summary>
        /// Performs a timing-safe comparison of two byte arrays.
        /// Polyfill for CryptographicOperations.FixedTimeEquals() which is not available in .NET Standard 2.0.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            if (left == null || right == null)
                return left == right;

            if (left.Length != right.Length)
                return false;

            var result = 0;
            for (var i = 0; i < left.Length; i++)
            {
                result |= left[i] ^ right[i];
            }
            return result == 0;
        }
    }
}
#endif
