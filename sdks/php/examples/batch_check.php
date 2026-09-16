<?php

/**
 * Batch credential check example.
 *
 * Run: DARKSTRATA_API_KEY=... php examples/batch_check.php
 */

require __DIR__ . '/../vendor/autoload.php';

use DarkStrata\CredentialCheck\Client;
use DarkStrata\CredentialCheck\Crypto;

$client = new Client(['apiKey' => getenv('DARKSTRATA_API_KEY') ?: 'your-api-key-here']);

$credentials = [
    ['email' => 'alice@example.com', 'password' => 'alice123'],
    ['email' => 'bob@example.com', 'password' => 'bob456'],
    ['email' => 'charlie@example.com', 'password' => 'charlie789'],
    ['email' => 'diana@example.com', 'password' => 'diana012'],
];

echo 'Checking ', count($credentials), " credentials...\n---\n";

// 1. Hash every credential locally. Only the hashes are handed to the client;
//    the plaintext emails and passwords never leave this process.
$hashes = array_map(fn($c) => Crypto::hashCredential($c['email'], $c['password']), $credentials);

// 2. Check the hashes in one batch. The SDK groups them by 5-character prefix,
//    fetches each prefix once, and compares the full hashes locally.
//    $results[$i] corresponds to $hashes[$i] (and so to $credentials[$i]).
$start = microtime(true);
$results = $client->checkHashBatch($hashes);
$durationMs = (microtime(true) - $start) * 1000;

printf("\nResults (completed in %.0fms):\n\n", $durationMs);
foreach ($results as $i => $result) {
    printf("  %s: %s\n", $credentials[$i]['email'], $result->found ? 'COMPROMISED' : 'Safe');
}

$compromised = count(array_filter($results, fn($r) => $r->found));
$prefixes = array_unique(array_map(fn($r) => $r->prefix, $results));

echo "\nSummary:\n";
echo '  - Total checked: ', count($results), "\n";
echo '  - Compromised: ', $compromised, "\n";
echo '  - Safe: ', count($results) - $compromised, "\n";
echo '  - API calls made: ', count($prefixes), " (grouped by prefix)\n";
