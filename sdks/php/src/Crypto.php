<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck;

use DarkStrata\CredentialCheck\Exception\ValidationException;

/**
 * Hashing helpers. All hex output is uppercase to match the server.
 */
final class Crypto
{
    /** SHA-256 of "email:password" with the email trimmed and lowercased. */
    public static function hashCredential(string $email, string $password): string
    {
        return self::sha256(strtolower(trim($email)) . ':' . $password);
    }

    public static function sha256(string $input): string
    {
        return strtoupper(hash('sha256', $input));
    }

    public static function hmacSha256(string $message, string $hexKey): string
    {
        if ($hexKey === '' || !self::isHex($hexKey) || strlen($hexKey) % 2 !== 0) {
            throw new ValidationException('hexKey', 'invalid hex key');
        }
        return strtoupper(hash_hmac('sha256', $message, hex2bin($hexKey)));
    }

    /** First $length characters of the hash (5 or 6), uppercased. */
    public static function extractPrefix(string $hash, int $length = Constants::PREFIX_LENGTH): string
    {
        return strtoupper(substr($hash, 0, $length));
    }

    /**
     * Timing-safe membership test: HMAC the hash with the server key and compare
     * against each returned HMAC.
     *
     * @param string[] $hmacHashes
     */
    public static function isHashInSet(string $hash, string $hmacKey, array $hmacHashes): bool
    {
        $computed = self::hmacSha256($hash, $hmacKey);
        $found = false;
        foreach ($hmacHashes as $candidate) {
            // No early return: keep the loop constant-time across the whole set.
            if (hash_equals($computed, strtoupper((string) $candidate))) {
                $found = true;
            }
        }
        return $found;
    }

    public static function isValidHash(string $hash, int $expectedLength = 64): bool
    {
        return strlen($hash) === $expectedLength && self::isHex($hash);
    }

    public static function isValidPrefix(string $prefix): bool
    {
        $len = strlen($prefix);
        return $len >= Constants::MIN_PREFIX_LENGTH && $len <= Constants::MAX_PREFIX_LENGTH && self::isHex($prefix);
    }

    private static function isHex(string $s): bool
    {
        return $s !== '' && ctype_xdigit($s);
    }
}
