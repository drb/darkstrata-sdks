<?php

require __DIR__ . '/../vendor/autoload.php';

use DarkStrata\CredentialCheck\Client;
use DarkStrata\CredentialCheck\Crypto;
use DarkStrata\CredentialCheck\Exception\DarkStrataException;

$client = new Client(['apiKey' => getenv('DARKSTRATA_API_KEY')]);

// email and password come from your login form and are only ever used here.
// 1. Hash locally: SHA-256 of "email:password". Plaintext never leaves this process.
$hash = Crypto::hashCredential($argv[1] ?? 'user@example.com', $argv[2] ?? 'password123');

try {
    // 2. Only the first 5 characters of the hash are sent; the full hash is compared locally.
    $result = $client->checkHash($hash);
    echo $result->found ? "WARNING: credential found in a breach\n" : "OK: not found in known breaches\n";
    echo "prefix={$result->prefix} candidates={$result->totalResults} cached=" . var_export($result->cachedResult, true) . "\n";
} catch (DarkStrataException $e) {
    fwrite(STDERR, $e->getMessage() . ($e->isRetryable() ? ' (retryable)' : '') . "\n");
    exit(1);
}
