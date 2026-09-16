<?php

declare(strict_types=1);

namespace DarkStrata\CredentialCheck;

use DarkStrata\CredentialCheck\Exception\ApiException;
use DarkStrata\CredentialCheck\Exception\AuthenticationException;
use DarkStrata\CredentialCheck\Exception\DarkStrataException;
use DarkStrata\CredentialCheck\Exception\NetworkException;
use DarkStrata\CredentialCheck\Exception\RateLimitException;
use DarkStrata\CredentialCheck\Exception\TimeoutException;
use DarkStrata\CredentialCheck\Exception\ValidationException;

/**
 * DarkStrata credential check client.
 *
 * Options:
 *  - apiKey        (string, required)
 *  - baseUrl       (string, default https://api.darkstrata.io/v1/)
 *  - timeout       (float seconds, default 30)
 *  - retries       (int, default 3)
 *  - enableCaching (bool, default true)
 *  - cacheTtl      (int seconds, default 3600)
 *  - transport     (callable, testing only) fn(string $url, string[] $headers, float $timeout): array{int, array<string,string>, string}
 *
 * Check options (second argument to check*):
 *  - clientHmac (string, 64+ hex chars) deterministic HMAC key instead of the server's rotating one
 *  - since      (DateTimeInterface|int) only breaches from this date (or epoch day) onwards
 */
final class Client
{
    private string $apiKey;
    private string $baseUrl;
    private float $timeout;
    private int $retries;
    private bool $enableCaching;
    private int $cacheTtl;
    /** @var callable */
    private $transport;
    /** @var array<string, array{response: array, timestamp: int}> */
    private array $cache = [];

    public function __construct(array $options)
    {
        $apiKey = $options['apiKey'] ?? '';
        if (!is_string($apiKey) || $apiKey === '') {
            throw new ValidationException('apiKey', 'API key is required');
        }
        $this->apiKey = $apiKey;
        $this->baseUrl = rtrim((string) ($options['baseUrl'] ?? Constants::DEFAULT_BASE_URL), '/') . '/';
        $this->timeout = (float) ($options['timeout'] ?? Constants::DEFAULT_TIMEOUT);
        $this->retries = max(0, (int) ($options['retries'] ?? Constants::DEFAULT_RETRIES));
        $this->enableCaching = (bool) ($options['enableCaching'] ?? true);
        $this->cacheTtl = (int) ($options['cacheTtl'] ?? Constants::DEFAULT_CACHE_TTL);
        $this->transport = $options['transport'] ?? [$this, 'curlTransport'];
    }

    /** Check an email/password pair. Only a 5-char prefix of SHA-256("email:password") leaves this process. */
    public function check(string $email, string $password, array $options = []): CheckResult
    {
        if ($email === '') {
            throw new ValidationException('email', 'email is required');
        }
        if ($password === '') {
            throw new ValidationException('password', 'password is required');
        }
        return $this->checkHashes([Crypto::hashCredential($email, $password)], [$email], $options)[0];
    }

    /** Check a precomputed SHA-256 hash (64 hex chars) from Crypto::hashCredential(). */
    public function checkHash(string $hash, array $options = []): CheckResult
    {
        $hash = strtoupper($hash);
        if (!Crypto::isValidHash($hash)) {
            throw new ValidationException('hash', 'invalid SHA-256 hash format (expected 64 hex characters)');
        }
        return $this->checkHashes([$hash], ['[hash-only]'], $options)[0];
    }

    /**
     * Check many credentials; one API call per distinct prefix. Results are in input order.
     *
     * @param array<array{email: string, password: string}> $credentials
     * @return CheckResult[]
     */
    public function checkBatch(array $credentials, array $options = []): array
    {
        $hashes = [];
        $emails = [];
        foreach (array_values($credentials) as $i => $cred) {
            $email = (string) ($cred['email'] ?? '');
            $password = (string) ($cred['password'] ?? '');
            if ($email === '') {
                throw new ValidationException("credentials[{$i}].email", 'email is required');
            }
            if ($password === '') {
                throw new ValidationException("credentials[{$i}].password", 'password is required');
            }
            $hashes[] = Crypto::hashCredential($email, $password);
            $emails[] = $email;
        }
        return $this->checkHashes($hashes, $emails, $options);
    }

    /**
     * Check many precomputed hashes; one API call per distinct prefix. Results are in input order.
     *
     * @param string[] $hashes
     * @return CheckResult[]
     */
    public function checkHashBatch(array $hashes, array $options = []): array
    {
        $upper = [];
        foreach (array_values($hashes) as $i => $hash) {
            $hash = strtoupper((string) $hash);
            if (!Crypto::isValidHash($hash)) {
                throw new ValidationException("hashes[{$i}]", 'invalid SHA-256 hash format (expected 64 hex characters)');
            }
            $upper[] = $hash;
        }
        return $this->checkHashes($upper, array_fill(0, count($upper), '[hash-only]'), $options);
    }

    public function clearCache(): void
    {
        $this->cache = [];
    }

    public function getCacheSize(): int
    {
        return count($this->cache);
    }

    /** @return CheckResult[] */
    private function checkHashes(array $hashes, array $emails, array $options): array
    {
        $query = $this->buildQuery($options);
        $responses = [];
        $results = [];
        foreach ($hashes as $i => $hash) {
            $prefix = Crypto::extractPrefix($hash);
            if (!isset($responses[$prefix])) {
                $responses[$prefix] = $this->fetchWithCache($prefix, $query);
            }
            [$response, $cached] = $responses[$prefix];
            $found = Crypto::isHashInSet($hash, $response['headers']['hmacKey'], $response['hashes']);
            $results[] = new CheckResult($found, $emails[$i], $response['headers'], $cached);
        }
        return $results;
    }

    /** @return array{0: array, 1: bool} response and whether it came from cache */
    private function fetchWithCache(string $prefix, array $query): array
    {
        if (!$this->enableCaching) {
            return [$this->fetchWithRetry($prefix, $query), false];
        }
        $key = $prefix . '|' . http_build_query($query);
        $entry = $this->cache[$key] ?? null;
        if ($entry !== null && $this->isCacheValid($entry)) {
            return [$entry['response'], true];
        }
        $response = $this->fetchWithRetry($prefix, $query);
        $this->cache[$key] = ['response' => $response, 'timestamp' => time()];
        return [$response, false];
    }

    private function isCacheValid(array $entry): bool
    {
        if (time() - $entry['timestamp'] > $this->cacheTtl) {
            return false;
        }
        // Server HMAC key rotates each time window; a cached response from an old window is useless.
        $window = $entry['response']['headers']['timeWindow'];
        return $window === '' || $window === (string) intdiv(time(), Constants::TIME_WINDOW_SECONDS);
    }

    private function fetchWithRetry(string $prefix, array $query): array
    {
        for ($attempt = 0; ; $attempt++) {
            try {
                return $this->doRequest($prefix, $query);
            } catch (DarkStrataException $e) {
                if (!$e->isRetryable() || $attempt >= $this->retries) {
                    throw $e;
                }
                $delay = min(
                    Constants::RETRY_INITIAL_DELAY * Constants::RETRY_BACKOFF_BASE ** $attempt,
                    Constants::RETRY_MAX_DELAY
                );
                usleep((int) ($delay * 1_000_000));
            }
        }
    }

    private function buildQuery(array $options): array
    {
        $query = [];
        if (isset($options['clientHmac'])) {
            $hmac = (string) $options['clientHmac'];
            if (strlen($hmac) < 64 || !ctype_xdigit($hmac)) {
                throw new ValidationException('clientHmac', 'clientHmac must be at least 64 hex characters');
            }
            $query['clientHmac'] = $hmac;
        }
        if (isset($options['since'])) {
            $since = $options['since'];
            $query['since'] = $since instanceof \DateTimeInterface ? intdiv($since->getTimestamp(), 86400) : (int) $since;
        }
        return $query;
    }

    private function doRequest(string $prefix, array $query): array
    {
        $url = $this->baseUrl . Constants::ENDPOINT . '?' . http_build_query(['prefix' => $prefix] + $query);
        $headers = [
            Constants::API_KEY_HEADER . ': ' . $this->apiKey,
            'Accept: application/json',
            'User-Agent: darkstrata-php/' . Constants::VERSION,
        ];

        [$status, $responseHeaders, $body] = ($this->transport)($url, $headers, $this->timeout);
        $responseHeaders = array_change_key_case($responseHeaders, CASE_LOWER);

        if ($status === 401) {
            throw new AuthenticationException('invalid or expired API key');
        }
        if ($status === 429) {
            throw new RateLimitException('rate limit exceeded', (int) ($responseHeaders['retry-after'] ?? 0));
        }
        if ($status !== 200) {
            throw new ApiException($status, "API request failed with status {$status}", $body);
        }

        $hashes = json_decode($body, true);
        if (!is_array($hashes)) {
            throw new ApiException($status, 'failed to parse response', $body);
        }

        return [
            'hashes' => $hashes,
            'headers' => [
                'prefix' => $responseHeaders[Constants::HEADER_PREFIX] ?? $prefix,
                'hmacKey' => $responseHeaders[Constants::HEADER_HMAC_KEY] ?? '',
                'hmacSource' => $responseHeaders[Constants::HEADER_HMAC_SOURCE] ?? '',
                'timeWindow' => $responseHeaders[Constants::HEADER_TIME_WINDOW] ?? '',
                'totalResults' => (int) ($responseHeaders[Constants::HEADER_TOTAL_RESULTS] ?? count($hashes)),
                'filterSince' => isset($responseHeaders[Constants::HEADER_FILTER_SINCE]) ? (int) $responseHeaders[Constants::HEADER_FILTER_SINCE] : null,
            ],
        ];
    }

    /** @return array{int, array<string,string>, string} */
    private function curlTransport(string $url, array $headers, float $timeout): array
    {
        $responseHeaders = [];
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT_MS => (int) ($timeout * 1000),
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$responseHeaders): int {
                $parts = explode(':', $line, 2);
                if (count($parts) === 2) {
                    $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                }
                return strlen($line);
            },
        ]);
        $body = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        if (PHP_VERSION_ID < 80000) {
            curl_close($ch); // no-op and deprecated from 8.0, still frees the handle on 7.4
        }

        if ($body === false) {
            if ($errno === CURLE_OPERATION_TIMEDOUT) {
                throw new TimeoutException("request timed out: {$error}");
            }
            throw new NetworkException("request failed: {$error}");
        }
        return [$status, $responseHeaders, (string) $body];
    }
}
