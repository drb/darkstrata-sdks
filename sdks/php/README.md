# DarkStrata Credential Check SDK for PHP

Check if credentials have been exposed in data breaches using k-anonymity to protect user privacy.

## Installation

```bash
composer require darkstrata/credential-check
```

## Prerequisites

- PHP 7.4 or newer (tested on 7.4 through 8.5)
- The `curl` and `json` extensions, which ship with virtually every PHP build
- A DarkStrata API key

No other dependencies.

## Quick Start

```php
<?php

require 'vendor/autoload.php';

use DarkStrata\CredentialCheck\Client;
use DarkStrata\CredentialCheck\Crypto;

$client = new Client(['apiKey' => getenv('DARKSTRATA_API_KEY')]);

// $email and $password come from your login form and are only ever used here.
// 1. Hash the credential locally: SHA-256 of "email:password".
//    The plaintext email and password never leave this process.
$hash = Crypto::hashCredential($email, $password);

// 2. Check the hash. The SDK sends only the first 5 characters (the
//    k-anonymity prefix) to the API and compares the full hash locally.
$result = $client->checkHash($hash);

if ($result->found) {
    echo "WARNING: Credential found in breach!";
} else {
    echo "OK: Credential not found in known breaches";
}
```

`$client->check($email, $password)` does both steps in one call.

## Features

- **Privacy-first k-anonymity** - Only the first 5 characters of the hash are sent to the server
- **Zero dependencies** - Only `ext-curl` and `ext-json`
- **Batch checking** - One API call per distinct prefix, results in input order
- **Automatic retries** - Exponential backoff for transient failures
- **Response caching** - In-memory, per-client, with TTL and server key-window awareness
- **Typed exceptions** - Every error reports whether it is retryable
- **Wide PHP support** - 7.4 through 8.5

## How It Works

1. The SDK computes `SHA-256(email:password)` locally, with the email trimmed and lowercased
2. Only the first 5 characters (the prefix) are sent to the server
3. The server returns HMACs of all hashes matching that prefix (typically 50-1000)
4. The SDK HMACs the full hash with the server's key and compares it against the response using a constant-time comparison
5. Your actual credential never leaves your server

## API Reference

### `Client`

#### Constructor

```php
$client = new Client([
    'apiKey'        => 'your-api-key',                  // Required
    'baseUrl'       => 'https://api.darkstrata.io/v1/', // Optional
    'timeout'       => 30,                              // Optional, seconds (float allowed)
    'retries'       => 3,                               // Optional, retry attempts for retryable errors
    'enableCaching' => true,                            // Optional
    'cacheTtl'      => 3600,                            // Optional, seconds
]);
```

Throws `ValidationException` if `apiKey` is missing.

#### `check(string $email, string $password, array $options = []): CheckResult`

Hashes the credential and checks it. Throws `ValidationException` if either value is empty.

```php
$result = $client->check('user@example.com', 'password123');
```

#### `checkHash(string $hash, array $options = []): CheckResult`

Checks a precomputed SHA-256 hash (64 hex characters, any case) from `Crypto::hashCredential()`. The result's `email` is `[hash-only]`.

```php
$hash = Crypto::hashCredential('user@example.com', 'password123');
$result = $client->checkHash($hash);
```

#### `checkBatch(array $credentials, array $options = []): CheckResult[]`

Checks many `['email' => ..., 'password' => ...]` pairs. Hashes are grouped by prefix so each prefix is fetched once. Results are in input order.

```php
$results = $client->checkBatch([
    ['email' => 'alice@example.com', 'password' => 'alice123'],
    ['email' => 'bob@example.com', 'password' => 'bob456'],
]);

foreach ($results as $result) {
    echo $result->email, ': ', $result->found ? 'COMPROMISED' : 'Safe', "\n";
}
```

#### `checkHashBatch(array $hashes, array $options = []): CheckResult[]`

Same as `checkBatch` for precomputed hashes. `$results[$i]` corresponds to `$hashes[$i]`.

```php
$hashes = array_map(fn($c) => Crypto::hashCredential($c['email'], $c['password']), $credentials);
$results = $client->checkHashBatch($hashes);
```

#### `clearCache(): void` and `getCacheSize(): int`

```php
$size = $client->getCacheSize();
$client->clearCache();
```

### Check Options

Every check method accepts an optional `$options` array:

| Key | Type | Description |
|-----|------|-------------|
| `clientHmac` | `string` | Your own HMAC key (64+ hex chars). The server uses it instead of its rotating key, so results are stable across calls |
| `since` | `DateTimeInterface\|int` | Only include breaches from this date (or epoch day) onwards |

```php
$result = $client->check($email, $password, [
    'clientHmac' => 'your-64-char-hex-key...',
    'since' => new DateTimeImmutable('2023-01-01'),
]);
```

### `CheckResult`

| Property | Type | Description |
|----------|------|-------------|
| `found` | `bool` | Credential appears in a known breach |
| `email` | `string` | Email as supplied, or `[hash-only]` for hash checks |
| `prefix` | `string` | The prefix that was sent to the API |
| `totalResults` | `int` | Candidate hashes returned for the prefix |
| `hmacSource` | `string` | `server` or `client` |
| `timeWindow` | `string` | Server HMAC key rotation window |
| `filterSince` | `?int` | Epoch-day filter applied, or `null` |
| `cachedResult` | `bool` | Result served from the in-memory cache |
| `checkedAt` | `DateTimeImmutable` | When the check ran |

### Caching

Caching is per `Client` instance, keyed by prefix and options. Entries expire after `cacheTtl` seconds or when the server's HMAC key window rolls over (hourly), whichever comes first.

Under PHP-FPM a client only lives for one request, so the cache mainly helps batch calls that share a prefix. For cross-request caching, keep the client alive in a long-running worker (Swoole, RoadRunner, Laravel Octane), or disable it with `enableCaching => false`.

## Error Handling

All exceptions extend `DarkStrata\CredentialCheck\Exception\DarkStrataException`, which extends `RuntimeException` and exposes `getErrorCode()` and `isRetryable()`.

```php
use DarkStrata\CredentialCheck\Exception\ApiException;
use DarkStrata\CredentialCheck\Exception\AuthenticationException;
use DarkStrata\CredentialCheck\Exception\DarkStrataException;
use DarkStrata\CredentialCheck\Exception\NetworkException;
use DarkStrata\CredentialCheck\Exception\RateLimitException;
use DarkStrata\CredentialCheck\Exception\TimeoutException;
use DarkStrata\CredentialCheck\Exception\ValidationException;

try {
    $result = $client->checkHash($hash);
} catch (AuthenticationException $e) {
    // 401 - invalid API key (not retryable)
} catch (ValidationException $e) {
    // Invalid input, see $e->getField()
} catch (RateLimitException $e) {
    // 429 - see $e->getRetryAfter() seconds
} catch (TimeoutException $e) {
    // Request timed out (retryable)
} catch (NetworkException $e) {
    // Connection failure (retryable)
} catch (ApiException $e) {
    // Other API error, see $e->getStatusCode() and $e->getResponseBody()
} catch (DarkStrataException $e) {
    // Anything else from the SDK
    if ($e->isRetryable()) {
        // Safe to try again later
    }
}
```

### Error Types

| Exception | Code | Retryable | Extra |
|-----------|------|-----------|-------|
| `AuthenticationException` | `AUTHENTICATION_ERROR` | No | |
| `ValidationException` | `VALIDATION_ERROR` | No | `getField()` |
| `ApiException` | `API_ERROR` | 408, 429, 5xx only | `getStatusCode()`, `getResponseBody()` |
| `RateLimitException` | `RATE_LIMIT_ERROR` | Yes | `getRetryAfter()` |
| `TimeoutException` | `TIMEOUT_ERROR` | Yes | |
| `NetworkException` | `NETWORK_ERROR` | Yes | |

Retryable errors are retried automatically up to `retries` times with exponential backoff (1s, 2s, 4s, capped at 10s) before being thrown.

## Cryptographic Utilities

`DarkStrata\CredentialCheck\Crypto` exposes the primitives for advanced use. All hex output is uppercase.

```php
// SHA-256 of "email:password" with the email trimmed and lowercased
$hash = Crypto::hashCredential($email, $password);

// Plain SHA-256
$hash = Crypto::sha256($input);

// HMAC-SHA256 with a hex-encoded key
$hmac = Crypto::hmacSha256($message, $hexKey);

// k-anonymity prefix (5 chars by default, pass 6 for a smaller response)
$prefix = Crypto::extractPrefix($hash);

// Validation
Crypto::isValidHash($hash);     // 64 hex chars
Crypto::isValidPrefix($prefix); // 5 or 6 hex chars
```

## Advanced Usage

### Pre-computed hashes

Hash once at signup, store the hash, and re-check it later without ever handling the password again:

```php
$hash = Crypto::hashCredential($email, $password);
// ...store $hash securely...
$result = $client->checkHash($hash);
```

### Framework integration

The client has no framework dependencies. Register it as a singleton in your container and inject it wherever logins are handled:

```php
// Laravel: AppServiceProvider::register()
$this->app->singleton(Client::class, fn() => new Client(['apiKey' => config('services.darkstrata.key')]));

// Symfony: services.yaml
// DarkStrata\CredentialCheck\Client:
//     arguments: [{ apiKey: '%env(DARKSTRATA_API_KEY)%' }]
```

## Examples

See the [`examples/`](./examples) directory:

- [`basic_usage.php`](./examples/basic_usage.php) - Single credential check
- [`batch_check.php`](./examples/batch_check.php) - Batch checking with prefix grouping
- [`error_handling.php`](./examples/error_handling.php) - Every exception type and retryability

## Testing

```bash
composer install
composer test
```

## Licence

Apache-2.0
