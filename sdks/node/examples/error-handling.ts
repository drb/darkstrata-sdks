/**
 * Error handling example for @darkstrata/credential-check
 *
 * This example demonstrates how to handle various error scenarios
 * when using the SDK.
 *
 * Run: npx tsx examples/error-handling.ts
 */

import {
  DarkStrataCredentialCheck,
  AuthenticationError,
  ValidationError,
  ApiError,
  TimeoutError,
  NetworkError,
  RateLimitError,
  isDarkStrataError,
} from '../src/index.js';

async function main() {
  // Example 1: Handling validation errors
  console.log('Example 1: Validation Error');
  console.log('---');

  try {
    const client = new DarkStrataCredentialCheck({
      apiKey: '', // Empty API key - will throw ValidationError
    });
    await client.check('user@example.com', 'password');
  } catch (error) {
    if (error instanceof ValidationError) {
      console.log(`Validation error on field "${error.field}": ${error.message}`);
    }
  }

  console.log('');

  // Example 2: Handling authentication errors
  console.log('Example 2: Authentication Error');
  console.log('---');

  try {
    const client = new DarkStrataCredentialCheck({
      apiKey: 'invalid-api-key',
    });
    await client.check('user@example.com', 'password');
  } catch (error) {
    if (error instanceof AuthenticationError) {
      console.log(`Authentication failed: ${error.message}`);
      console.log('Please check your API key.');
    }
  }

  console.log('');

  // Example 3: Comprehensive error handling
  console.log('Example 3: Comprehensive Error Handling');
  console.log('---');

  const client = new DarkStrataCredentialCheck({
    apiKey: process.env.DARKSTRATA_API_KEY ?? 'your-api-key',
    timeout: 5000, // 5 second timeout
    retries: 2,
  });

  try {
    const result = await client.check('user@example.com', 'password');
    console.log(`Check completed. Found: ${result.found}`);
  } catch (error) {
    if (error instanceof AuthenticationError) {
      // 401 - Invalid API key
      console.error('Authentication failed. Check your API key.');
    } else if (error instanceof ValidationError) {
      // Invalid input
      console.error(`Invalid input: ${error.message}`);
    } else if (error instanceof RateLimitError) {
      // 429 - Too many requests
      if (error.retryAfter) {
        console.error(`Rate limited. Retry after ${error.retryAfter} seconds.`);
      } else {
        console.error('Rate limited. Please slow down requests.');
      }
    } else if (error instanceof TimeoutError) {
      // Request timed out
      console.error(`Request timed out after ${error.timeoutMs}ms.`);
      console.error('Consider increasing the timeout setting.');
    } else if (error instanceof NetworkError) {
      // Network connectivity issue
      console.error(`Network error: ${error.message}`);
      console.error('Check your internet connection.');
    } else if (error instanceof ApiError) {
      // Other API errors
      console.error(`API error (${error.statusCode}): ${error.message}`);
      if (error.retryable) {
        console.error('This error is retryable.');
      }
    } else if (isDarkStrataError(error)) {
      // Generic DarkStrata error
      console.error(`DarkStrata error [${error.code}]: ${error.message}`);
    } else {
      // Unknown error
      throw error;
    }
  }

  console.log('');

  // Example 4: Checking if errors are retryable
  console.log('Example 4: Retryable Errors');
  console.log('---');

  const errorExamples = [
    new AuthenticationError(),
    new ValidationError('Invalid email'),
    new TimeoutError(5000),
    new NetworkError('Connection refused'),
    new RateLimitError(60),
    new ApiError('Server error', 500, { retryable: true }),
    new ApiError('Not found', 404, { retryable: false }),
  ];

  for (const error of errorExamples) {
    console.log(`${error.name}: retryable = ${error.retryable}`);
  }
}

main().catch(console.error);
