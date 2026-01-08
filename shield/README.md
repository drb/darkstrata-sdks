# @darkstrata/shield

Browser SDK for DarkStrata Shield login risk scoring.

## Features

- **Device Fingerprinting** — Canvas, WebGL, audio, fonts, hardware characteristics
- **Anomaly Detection** — Headless browsers, automation frameworks, VMs, spoofing
- **Secure Credential Handling** — HMAC-SHA256 for user IDs, k-anonymity for passwords
- **Automatic Collection** — Fingerprinting happens transparently on first API call
- **Lightweight** — < 15KB gzipped, zero dependencies

## Installation

```bash
npm install @darkstrata/shield
```

## Quick Start

```typescript
import { DarkStrataShield } from '@darkstrata/shield';

const shield = new DarkStrataShield({
  apiKey: 'shld_live_xxx',
  salt: 'your_customer_salt',  // From Shield dashboard
});

// Score a login attempt
const result = await shield.score({
  email: 'user@example.com',
  password: 'userpassword',  // Hashed with k-anonymity, never sent in plain
});

console.log(result);
// {
//   riskScore: 0.15,
//   riskLevel: 'LOW',
//   recommendedAction: 'ALLOW',
//   signals: [...],
//   processingTimeMs: 45
// }

// Handle based on risk
switch (result.recommendedAction) {
  case 'ALLOW':
    // Proceed with login
    break;
  case 'REQUIRE_MFA':
    // Trigger MFA challenge
    break;
  case 'BLOCK':
    // Reject login
    break;
}
```

## Usage Options

### Class Instance

```typescript
import { DarkStrataShield } from '@darkstrata/shield';

const shield = new DarkStrataShield({
  apiKey: 'shld_live_xxx',
  salt: 'your_customer_salt',
  debug: true,  // Enable console logging
});

const result = await shield.score({ email, password });
```

### Singleton Pattern

```typescript
import { init, score } from '@darkstrata/shield';

// Initialise once (e.g., on app startup)
init({
  apiKey: 'shld_live_xxx',
  salt: 'your_customer_salt',
});

// Use anywhere
const result = await score({ email, password });
```

### Script Tag (CDN)

```html
<script src="https://cdn.darkstrata.io/shield/v1.js"></script>
<script>
  DarkStrataShield.init({
    apiKey: 'shld_live_xxx',
    salt: 'your_customer_salt',
  });

  async function onLogin(email, password) {
    const result = await DarkStrataShield.score({ email, password });
    if (result.recommendedAction === 'BLOCK') {
      alert('Login blocked due to suspicious activity');
      return;
    }
    // Continue with login...
  }
</script>
```

## Security

### User ID Hashing

User emails are **never** sent to Shield in plaintext. They are:

1. Normalised (lowercase, Gmail dot handling)
2. Hashed with HMAC-SHA256 using your customer-specific salt

```typescript
// This happens automatically in score()
const userIdHash = await shield.hashUserId('user@example.com');
// => "a3f2b1c4d5e6..." (64-char hex)
```

### Password Handling (k-Anonymity)

Passwords are **never** sent to Shield. For breach checking:

1. Password is hashed with SHA-1
2. Only the first 5 characters of the hash are sent
3. Server returns matching breach entries, client checks locally

This means Shield never knows the actual password or even its full hash.

## Configuration

```typescript
interface ShieldConfig {
  /** Shield API key (required) */
  apiKey: string;

  /** Customer HMAC salt for user ID hashing (required) */
  salt: string;

  /** Base URL (default: https://shield.darkstrata.io) */
  baseUrl?: string;

  /** Request timeout in ms (default: 10000) */
  timeout?: number;

  /** Enable debug logging (default: false) */
  debug?: boolean;
}
```

## Fingerprint Access

The fingerprint is collected automatically, but you can access it directly:

```typescript
// Get full fingerprint
const fp = await shield.getFingerprint();
console.log(fp.fingerprintId);     // SHA-256 hash
console.log(fp.confidence);        // 0.0-1.0
console.log(fp.components);        // Individual hashes
console.log(fp.signals);           // Raw browser signals
console.log(fp.anomalies);         // Detected anomalies

// Get ID only
const id = await shield.getFingerprintId();

// Force refresh (rare use case)
const freshFp = await shield.refreshFingerprint();
```

## Risk Levels & Actions

| Score | Level | Default Action |
|-------|-------|----------------|
| 0.0-0.2 | LOW | ALLOW |
| 0.2-0.4 | MEDIUM | FLAG_FOR_REVIEW |
| 0.4-0.6 | HIGH | REQUIRE_CAPTCHA |
| 0.6-0.8 | CRITICAL | REQUIRE_MFA |
| 0.8-1.0 | SEVERE | BLOCK |

## Error Handling

```typescript
import {
  DarkStrataShield,
  NetworkError,
  TimeoutError,
  ApiError,
  isRetryableError
} from '@darkstrata/shield';

try {
  const result = await shield.score({ email, password });
} catch (err) {
  if (err instanceof TimeoutError) {
    // Request timed out - maybe allow login with flag
  } else if (err instanceof NetworkError) {
    // Network issue - fail open or retry
  } else if (err instanceof ApiError) {
    console.error(`API error: ${err.statusCode}`, err.response);
  }

  // Check if retryable
  if (isRetryableError(err)) {
    // Safe to retry
  }
}
```

## Browser Support

- Chrome 60+
- Firefox 55+
- Safari 11+
- Edge 79+

Requires `crypto.subtle` (Web Crypto API) for secure hashing.

## Bundle Size

- ESM: ~12KB gzipped
- IIFE (global): ~14KB gzipped

## TypeScript

Full TypeScript support with exported types:

```typescript
import type {
  ShieldConfig,
  ScoreResult,
  DeviceFingerprint,
  RiskLevel,
  RecommendedAction,
} from '@darkstrata/shield';
```

## Licence

Apache-2.0
