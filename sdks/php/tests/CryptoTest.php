<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Tests;

use DarkStrata\CredentialCheck\Crypto;
use DarkStrata\CredentialCheck\Exception\ValidationException;
use PHPUnit\Framework\TestCase;

final class CryptoTest extends TestCase
{
    public function testHashCredentialNormalisesEmail(): void
    {
        // Same vector as the other SDKs: sha256("test@example.com:pw")
        $expected = '37B933DA6FDBBDF9659030E74472AB868335EB0E3616712BEDA96FB5A5B12246';
        self::assertSame($expected, Crypto::hashCredential(' Test@Example.com ', 'pw'));
    }

    public function testExtractPrefix(): void
    {
        self::assertSame('ABCDE', Crypto::extractPrefix('abcdef0123'));
        self::assertSame('ABCDEF', Crypto::extractPrefix('abcdef0123', 6));
    }

    public function testIsHashInSet(): void
    {
        $key = str_repeat('ab', 32);
        $hash = Crypto::sha256('x');
        $hmac = Crypto::hmacSha256($hash, $key);
        self::assertTrue(Crypto::isHashInSet($hash, $key, ['0000', strtolower($hmac)]));
        self::assertFalse(Crypto::isHashInSet($hash, $key, ['0000']));
    }

    public function testInvalidHexKeyThrows(): void
    {
        $this->expectException(ValidationException::class);
        Crypto::hmacSha256('x', 'zz');
    }

    public function testValidators(): void
    {
        self::assertTrue(Crypto::isValidHash(str_repeat('A', 64)));
        self::assertFalse(Crypto::isValidHash(str_repeat('A', 63)));
        self::assertFalse(Crypto::isValidHash(str_repeat('G', 64)));
        self::assertTrue(Crypto::isValidPrefix('ABCDE'));
        self::assertTrue(Crypto::isValidPrefix('ABCDEF'));
        self::assertFalse(Crypto::isValidPrefix('ABCD'));
        self::assertFalse(Crypto::isValidPrefix('ABCDEFA'));
    }
}
