# @darkstrata/credential-check

Check if credentials have been exposed in data breaches using k-anonymity.

[![npm version](https://img.shields.io/npm/v/@darkstrata/credential-check.svg)](https://www.npmjs.com/package/@darkstrata/credential-check)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Features

- **Privacy-first**: Uses k-anonymity to check credentials without exposing them
- **Type-safe**: Full TypeScript support with comprehensive type definitions
- **Zero dependencies**: Uses Node.js built-in `crypto` and `fetch`
- **Automatic caching**: Intelligent caching aligned with server time windows
- **Batch processing**: Efficiently check multiple credentials with automatic prefix grouping
- **Retry logic**: Built-in exponential backoff for transient failures
- **Comprehensive errors**: Detailed error types for easy error handling

## Prerequisites

1. **Get an API key** from [https://darkstrata.io](https://darkstrata.io)
2. Node.js 18.0.0 or higher

## Installation

```bash
npm install @darkstrata/credential-check
```

```bash
yarn add @darkstrata/credential-check
```

```bash
pnpm add @darkstrata/credential-check
```

## Quick Start

```typescript
import { DarkStrataCredentialCheck } from '@darkstrata/credential-check';

// Create a client
const client = new DarkStrataCredentialCheck({
  apiKey: 'your-api-key',
});

// Check a single credential
const result = await client.check('user@example.com', 'password123');

if (result.found) {
  console.log('⚠️ This credential was found in a data breach!');
} else {
  console.log('✓ Credential not found in known breaches.');
}
```

## How It Works

This SDK uses **k-anonymity** to check credentials without exposing them:

1. Your credential is hashed locally: `SHA256(email:password)`
2. Only the first 5 characters (prefix) of the hash are sent to the API
3. The API returns all hashes matching that prefix (1-in-1,000,000 anonymity)
4. The SDK checks if your full hash is in the returned set

**Your actual credentials never leave your system.**

```
┌─────────────────────┐         ┌─────────────────────┐
│     Your System     │         │   DarkStrata API    │
│                     │         │                     │
│  email:password     │         │                     │
│        ↓            │         │                     │
│  SHA256 hash        │         │                     │
│        ↓            │         │                     │
│  Extract prefix ────┼────────→│  Lookup by prefix   │
│  (5 chars only)     │         │        ↓            │
│                     │←────────┼─ Return all matches │
│  Check membership   │         │                     │
│        ↓            │         │                     │
│  found: true/false  │         │                     │
└─────────────────────┘         └─────────────────────┘
```

## API Reference

### `DarkStrataCredentialCheck`

The main client class.

#### Constructor

```typescript
new DarkStrataCredentialCheck(options: ClientOptions)
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | `string` | *required* | Your DarkStrata API key |
| `baseUrl` | `string` | `'https://api.darkstrata.io/v1/'` | API base URL |
| `timeout` | `number` | `30000` | Request timeout in milliseconds |
| `retries` | `number` | `3` | Number of retry attempts |
| `enableCaching` | `boolean` | `true` | Enable response caching |
| `cacheTTL` | `number` | `3600000` | Cache TTL in milliseconds (1 hour) |

#### Methods

##### `check(email, password)`

Check a single credential.

```typescript
const result = await client.check('user@example.com', 'password123');
```

**Returns:** `Promise<CheckResult>`

##### `checkHash(hash)`

Check a pre-computed SHA-256 hash.

```typescript
const hash = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8...';
const result = await client.checkHash(hash);
```

**Returns:** `Promise<CheckResult>`

##### `checkBatch(credentials)`

Check multiple credentials efficiently.

```typescript
const results = await client.checkBatch([
  { email: 'user1@example.com', password: 'pass1' },
  { email: 'user2@example.com', password: 'pass2' },
]);
```

**Returns:** `Promise<CheckResult[]>`

##### `clearCache()`

Clear the internal response cache.

```typescript
client.clearCache();
```

##### `getCacheSize()`

Get the number of cached entries.

```typescript
const size = client.getCacheSize();
```

### `CheckResult`

The result of a credential check.

```typescript
interface CheckResult {
  found: boolean;              // true if credential was in a breach
  credential: {
    email: string;             // The email that was checked
    masked: true;              // Password is always masked
  };
  metadata: {
    prefix: string;            // The 5-char prefix used
    totalResults: number;      // Total hashes returned by API
    hmacSource: 'server' | 'client'; // Source of HMAC key
    timeWindow?: number;       // Server time window (server HMAC only)
    filterSince?: number;      // Epoch day filter (if since was used)
    cachedResult: boolean;     // Whether result was from cache
    checkedAt: Date;           // When the check was performed
  };
}
```

### `CheckOptions`

Optional parameters for check requests.

```typescript
interface CheckOptions {
  clientHmac?: string;  // Your own HMAC key (64+ hex chars)
  since?: number | Date; // Filter by breach date
}
```

## Error Handling

The SDK provides specific error types for different failure scenarios:

```typescript
import {
  DarkStrataCredentialCheck,
  AuthenticationError,
  ValidationError,
  ApiError,
  TimeoutError,
  NetworkError,
  RateLimitError,
  isDarkStrataError,
} from '@darkstrata/credential-check';

const client = new DarkStrataCredentialCheck({ apiKey: 'your-key' });

try {
  const result = await client.check('user@example.com', 'password');
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.error('Invalid API key');
  } else if (error instanceof ValidationError) {
    console.error(`Invalid input: ${error.field}`);
  } else if (error instanceof RateLimitError) {
    console.error(`Rate limited. Retry after ${error.retryAfter} seconds`);
  } else if (error instanceof TimeoutError) {
    console.error(`Request timed out after ${error.timeoutMs}ms`);
  } else if (error instanceof NetworkError) {
    console.error('Network error:', error.message);
  } else if (error instanceof ApiError) {
    console.error(`API error ${error.statusCode}:`, error.message);
  } else if (isDarkStrataError(error)) {
    console.error(`DarkStrata error [${error.code}]:`, error.message);
  } else {
    throw error;
  }
}
```

### Error Types

| Error | Code | Description |
|-------|------|-------------|
| `AuthenticationError` | `AUTHENTICATION_ERROR` | Invalid or missing API key |
| `ValidationError` | `VALIDATION_ERROR` | Invalid input parameters |
| `ApiError` | `API_ERROR` | API request failed |
| `TimeoutError` | `TIMEOUT_ERROR` | Request timed out |
| `NetworkError` | `NETWORK_ERROR` | Network connectivity issue |
| `RateLimitError` | `RATE_LIMIT_ERROR` | Rate limit exceeded |

## Advanced Usage

### Pre-computed Hashes

If you're storing hashed credentials, you can check them directly:

```typescript
import { hashCredential, DarkStrataCredentialCheck } from '@darkstrata/credential-check';

// Compute hash once
const hash = hashCredential('user@example.com', 'password123');
// Store hash securely...

// Later, check the hash
const client = new DarkStrataCredentialCheck({ apiKey: 'your-key' });
const result = await client.checkHash(hash);
```

### Batch Processing

For checking multiple credentials, use `checkBatch` for efficiency:

```typescript
const credentials = [
  { email: 'user1@example.com', password: 'pass1' },
  { email: 'user2@example.com', password: 'pass2' },
  { email: 'user3@example.com', password: 'pass3' },
];

const results = await client.checkBatch(credentials);

const compromised = results.filter(r => r.found);
console.log(`${compromised.length} credentials were compromised`);
```

Batch processing automatically groups credentials by prefix to minimise API calls.

### Client-Provided HMAC Key

By default, the server generates a time-rotating HMAC key. For deterministic results across requests, provide your own key:

```typescript
import { randomBytes } from 'node:crypto';

// Generate a secure key once and store it securely
const clientHmac = randomBytes(32).toString('hex');

const result = await client.check('user@example.com', 'password', {
  clientHmac,
});

// Results are now deterministic (not time-windowed)
console.log(result.metadata.hmacSource); // 'client'
```

**When to use client HMAC:**
- You need consistent results across multiple requests
- You're comparing results from different time periods
- You want to avoid server-side key rotation

### Date Filtering

Filter results to only include breaches from a specific date onwards:

```typescript
// Only check breaches from 2024 onwards
const result = await client.check('user@example.com', 'password', {
  since: new Date('2024-01-01'),
});

// Or use epoch day (days since 1 January 1970)
const result = await client.check('user@example.com', 'password', {
  since: 19724, // 2024-01-01
});

// Check the filter applied
console.log(result.metadata.filterSince); // 19724
```

### Combined Options

You can combine multiple options:

```typescript
const result = await client.check('user@example.com', 'password', {
  clientHmac: 'your-256-bit-hex-key...',
  since: new Date('2024-01-01'),
});
```

### Disabling Cache

For real-time checks where you need fresh results:

```typescript
const client = new DarkStrataCredentialCheck({
  apiKey: 'your-key',
  enableCaching: false,
});
```

### Custom Timeout and Retries

```typescript
const client = new DarkStrataCredentialCheck({
  apiKey: 'your-key',
  timeout: 60000,  // 60 seconds
  retries: 5,      // 5 retry attempts
});
```

## Security Considerations

### What is sent to the API?

- Only the **first 5 characters** of the SHA-256 hash
- Your API key for authentication

### What is NOT sent?

- Your email address
- Your password
- The full hash of your credentials

### Best Practices

1. **Never log credentials** - The SDK never logs credentials, and you shouldn't either
2. **Use HTTPS** - The SDK enforces HTTPS for all API calls
3. **Secure your API key** - Store your API key securely (environment variables, secrets manager)
4. **Handle errors gracefully** - Don't expose internal errors to end users

## TypeScript

This package is written in TypeScript and includes full type definitions.

```typescript
import type {
  ClientOptions,
  Credential,
  CheckResult,
  CheckMetadata,
} from '@darkstrata/credential-check';
```

## CommonJS Support

The package supports both ESM and CommonJS:

```javascript
// ESM
import { DarkStrataCredentialCheck } from '@darkstrata/credential-check';

// CommonJS
const { DarkStrataCredentialCheck } = require('@darkstrata/credential-check');
```

## Contributing

See the [contributing guide](https://github.com/darkstrata/darkstrata-sdks/blob/main/CONTRIBUTING.md).

## Licence

Apache 2.0 © [DarkStrata](https://darkstrata.io)
