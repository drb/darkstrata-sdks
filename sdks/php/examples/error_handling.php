<?php

/**
 * Error handling example.
 *
 * Run: DARKSTRATA_API_KEY=... php examples/error_handling.php
 */

require __DIR__ . '/../vendor/autoload.php';

use DarkStrata\CredentialCheck\Client;
use DarkStrata\CredentialCheck\Crypto;
use DarkStrata\CredentialCheck\Exception\ApiException;
use DarkStrata\CredentialCheck\Exception\AuthenticationException;
use DarkStrata\CredentialCheck\Exception\DarkStrataException;
use DarkStrata\CredentialCheck\Exception\NetworkException;
use DarkStrata\CredentialCheck\Exception\RateLimitException;
use DarkStrata\CredentialCheck\Exception\TimeoutException;
use DarkStrata\CredentialCheck\Exception\ValidationException;

// Hash the credential once, locally. Only this hash is handed to the client,
// and only its 5-character prefix is ever sent to the API.
$hash = Crypto::hashCredential('user@example.com', 'password');

// Example 1: Validation errors are thrown before any request is made
echo "Example 1: Validation Error\n---\n";
try {
    new Client(['apiKey' => '']);
} catch (ValidationException $e) {
    echo 'Validation error on field "', $e->getField(), '": ', $e->getMessage(), "\n";
}

// Example 2: Authentication errors (401)
echo "\nExample 2: Authentication Error\n---\n";
try {
    (new Client(['apiKey' => 'invalid-api-key', 'retries' => 0]))->checkHash($hash);
} catch (AuthenticationException $e) {
    echo 'Authentication failed: ', $e->getMessage(), "\nPlease check your API key.\n";
}

// Example 3: Comprehensive error handling
echo "\nExample 3: Comprehensive Error Handling\n---\n";
$client = new Client([
    'apiKey' => getenv('DARKSTRATA_API_KEY') ?: 'your-api-key',
    'timeout' => 5,
    'retries' => 2,
]);

try {
    $result = $client->checkHash($hash);
    echo 'Check completed. Found: ', var_export($result->found, true), "\n";
} catch (AuthenticationException $e) {
    echo "Authentication failed. Check your API key.\n";
} catch (ValidationException $e) {
    echo 'Invalid input: ', $e->getMessage(), "\n";
} catch (RateLimitException $e) {
    echo $e->getRetryAfter() > 0
        ? "Rate limited. Retry after {$e->getRetryAfter()} seconds.\n"
        : "Rate limited. Please slow down requests.\n";
} catch (TimeoutException $e) {
    echo "Request timed out. Consider increasing the timeout setting.\n";
} catch (NetworkException $e) {
    echo 'Network error: ', $e->getMessage(), "\nCheck your internet connection.\n";
} catch (ApiException $e) {
    echo 'API error (', $e->getStatusCode(), '): ', $e->getMessage(), "\n";
    if ($e->isRetryable()) {
        echo "This error is retryable.\n";
    }
} catch (DarkStrataException $e) {
    echo 'DarkStrata error [', $e->getErrorCode(), ']: ', $e->getMessage(), "\n";
}

// Example 4: Which errors are retryable
echo "\nExample 4: Retryable Errors\n---\n";
foreach ([
    new AuthenticationException('invalid or expired API key'),
    new ValidationException('email', 'email is required'),
    new TimeoutException('request timed out'),
    new NetworkException('connection refused'),
    new RateLimitException('rate limit exceeded', 60),
    new ApiException(500, 'server error'),
    new ApiException(404, 'not found'),
] as $e) {
    printf("%s: retryable = %s\n", (new ReflectionClass($e))->getShortName(), var_export($e->isRetryable(), true));
}
