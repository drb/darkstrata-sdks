<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck\Tests;

use DarkStrata\CredentialCheck\Client;
use DarkStrata\CredentialCheck\Constants;
use DarkStrata\CredentialCheck\Crypto;
use DarkStrata\CredentialCheck\Exception\ApiException;
use DarkStrata\CredentialCheck\Exception\AuthenticationException;
use DarkStrata\CredentialCheck\Exception\RateLimitException;
use DarkStrata\CredentialCheck\Exception\ValidationException;
use PHPUnit\Framework\TestCase;

final class ClientTest extends TestCase
{
    private const KEY = 'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789';

    /** @var array<int, array{url: string, headers: string[]}> */
    private array $requests = [];

    /** Client whose transport replays $responses in order (last one repeats). */
    private function client(array $responses, array $options = []): Client
    {
        $this->requests = [];
        $transport = function (string $url, array $headers) use (&$responses): array {
            $this->requests[] = ['url' => $url, 'headers' => $headers];
            return count($responses) > 1 ? array_shift($responses) : $responses[0];
        };
        return new Client($options + ['apiKey' => 'k', 'retries' => 0, 'transport' => $transport]);
    }

    private static function ok(array $hashes, array $extraHeaders = []): array
    {
        return [200, $extraHeaders + [
            'x-prefix' => 'ABCDE',
            'x-hmac-key' => self::KEY,
            'x-hmac-source' => 'server',
            'x-time-window' => (string) intdiv(time(), Constants::TIME_WINDOW_SECONDS),
            'x-total-results' => (string) count($hashes),
        ], json_encode($hashes)];
    }

    public function testRequiresApiKey(): void
    {
        $this->expectException(ValidationException::class);
        new Client([]);
    }

    public function testValidation(): void
    {
        $c = $this->client([self::ok([])]);
        foreach ([
            fn() => $c->check('', 'pw'),
            fn() => $c->check('a@b.c', ''),
            fn() => $c->checkHash('nothex'),
            fn() => $c->checkBatch([['email' => 'a@b.c']]),
            fn() => $c->checkHashBatch(['xyz']),
            fn() => $c->check('a@b.c', 'pw', ['clientHmac' => 'short']),
        ] as $call) {
            try {
                $call();
                self::fail('expected ValidationException');
            } catch (ValidationException $e) {
                self::assertSame('VALIDATION_ERROR', $e->getErrorCode());
            }
        }
        self::assertSame([], $this->requests);
    }

    public function testNotFound(): void
    {
        $c = $this->client([self::ok(['00'])]);
        $r = $c->check('user@example.com', 'pw');
        self::assertFalse($r->found);
        self::assertSame('user@example.com', $r->email);
        self::assertSame('server', $r->hmacSource);
        self::assertFalse($r->cachedResult);

        $url = $this->requests[0]['url'];
        $prefix = Crypto::extractPrefix(Crypto::hashCredential('user@example.com', 'pw'));
        self::assertSame(Constants::DEFAULT_BASE_URL . Constants::ENDPOINT . '?prefix=' . $prefix, $url);
        self::assertContains('X-Api-Key: k', $this->requests[0]['headers']);
        self::assertStringNotContainsString('user@example.com', $url);
    }

    public function testFoundAndCached(): void
    {
        $hash = Crypto::hashCredential('user@example.com', 'pw');
        $c = $this->client([self::ok([Crypto::hmacSha256($hash, self::KEY)])]);

        self::assertTrue($c->check('user@example.com', 'pw')->found);
        $second = $c->checkHash(strtolower($hash));
        self::assertTrue($second->found);
        self::assertTrue($second->cachedResult);
        self::assertSame('[hash-only]', $second->email);
        self::assertCount(1, $this->requests);
        self::assertSame(1, $c->getCacheSize());

        $c->clearCache();
        $c->check('user@example.com', 'pw');
        self::assertCount(2, $this->requests);
    }

    public function testCachingDisabled(): void
    {
        $c = $this->client([self::ok([])], ['enableCaching' => false]);
        $c->check('a@b.c', 'pw');
        $c->check('a@b.c', 'pw');
        self::assertCount(2, $this->requests);
        self::assertSame(0, $c->getCacheSize());
    }

    public function testBatchGroupsByPrefixAndKeepsOrder(): void
    {
        $creds = [];
        for ($i = 0; $i < 40; $i++) {
            $creds[] = ['email' => "u{$i}@x.io", 'password' => 'pw'];
        }
        $target = Crypto::hashCredential('u7@x.io', 'pw');
        $c = $this->client([self::ok([Crypto::hmacSha256($target, self::KEY)])]);

        $results = $c->checkBatch($creds);
        self::assertCount(40, $results);
        self::assertSame('u7@x.io', $results[7]->email);
        self::assertTrue($results[7]->found);
        self::assertSame(1, count(array_filter($results, fn($r) => $r->found)));

        $prefixes = array_unique(array_map(fn($cr) => Crypto::extractPrefix(Crypto::hashCredential($cr['email'], 'pw')), $creds));
        self::assertCount(count($prefixes), $this->requests);
    }

    public function testCheckOptions(): void
    {
        $c = $this->client([self::ok([], ['x-filter-since' => '20000'])]);
        $hmac = str_repeat('0', 64);
        $r = $c->check('a@b.c', 'pw', ['clientHmac' => $hmac, 'since' => new \DateTimeImmutable('@1728000000')]);
        self::assertStringContainsString('clientHmac=' . $hmac, $this->requests[0]['url']);
        self::assertStringContainsString('since=20000', $this->requests[0]['url']);
        self::assertSame(20000, $r->filterSince);
    }

    public function testErrors(): void
    {
        try {
            $this->client([[401, [], '']])->check('a@b.c', 'pw');
            self::fail();
        } catch (AuthenticationException $e) {
            self::assertFalse($e->isRetryable());
        }
        try {
            $this->client([[429, ['Retry-After' => '7'], '']])->check('a@b.c', 'pw');
            self::fail();
        } catch (RateLimitException $e) {
            self::assertSame(7, $e->getRetryAfter());
            self::assertTrue($e->isRetryable());
        }
        try {
            $this->client([[500, [], 'boom']])->check('a@b.c', 'pw');
            self::fail();
        } catch (ApiException $e) {
            self::assertSame(500, $e->getStatusCode());
            self::assertSame('boom', $e->getResponseBody());
            self::assertTrue($e->isRetryable());
        }
        try {
            $this->client([[200, [], 'not json']])->check('a@b.c', 'pw');
            self::fail();
        } catch (ApiException $e) {
            self::assertFalse($e->isRetryable());
        }
    }

    public function testRetriesTransientErrors(): void
    {
        $c = $this->client([[503, [], ''], self::ok([])], ['retries' => 1]);
        self::assertFalse($c->check('a@b.c', 'pw')->found);
        self::assertCount(2, $this->requests);
    }
}
