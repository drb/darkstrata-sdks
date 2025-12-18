# DarkStrata SDKs

Official SDKs for integrating with [DarkStrata](https://darkstrata.io) services.

## Available SDKs

| Language | Package | Version | Documentation |
|----------|---------|---------|---------------|
| Node.js / TypeScript | `@darkstrata/credential-check` | [![npm](https://badge.fury.io/js/%40darkstrata%2Fcredential-check.svg)](https://www.npmjs.com/package/@darkstrata/credential-check) | [README](./node/README.md) |
| Python | Coming soon | - | - |
| Go | Coming soon | - | - |

## Credential Check SDK

Check if credentials have been exposed in data breaches using k-anonymity.

### Features

- **Privacy-first**: Only a 5-character hash prefix is sent to our servers
- **No credential exposure**: Your passwords never leave your system
- **Batch processing**: Efficiently check multiple credentials
- **Full type safety**: Written in TypeScript with comprehensive types

### Quick Example (Node.js)

```typescript
import { DarkStrataCredentialCheck } from '@darkstrata/credential-check';

const client = new DarkStrataCredentialCheck({
  apiKey: 'your-api-key',
});

const result = await client.check('user@example.com', 'password123');

if (result.found) {
  console.log('Credential found in breach database!');
}
```

### How K-Anonymity Works

```
Your System                         DarkStrata API
    │                                    │
    │  Hash: email:password              │
    │  SHA256 → 5BAA61E4C9B93F3F...     │
    │                                    │
    │  Send prefix only: "5BAA6"  ──────→│
    │                                    │
    │  ←────── All hashes with prefix    │
    │                                    │
    │  Check if your hash is in set      │
    │  Result: found or not found        │
    │                                    │
```

Only **5 characters** of a 64-character hash are sent. This provides:
- 1-in-1,000,000 anonymity set
- Your actual credentials are never transmitted
- Even if intercepted, the prefix reveals nothing

## Getting Started

1. **Get an API key** from your [DarkStrata dashboard](https://app.darkstrata.io)
2. **Install the SDK** for your language (see table above)
3. **Start checking credentials**

## Documentation

- [Node.js SDK Documentation](./node/README.md)
- [API Documentation](https://docs.darkstrata.io)
- [DarkStrata Dashboard](https://app.darkstrata.io)

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/darkstrata/darkstrata-sdks.git
cd darkstrata-sdks

# Install dependencies for Node SDK
cd node
npm install

# Run tests
npm test

# Build
npm run build
```

## Security

If you discover a security vulnerability, please email security@darkstrata.io instead of using the issue tracker.

## Licence

Apache 2.0 © [DarkStrata Ltd](https://darkstrata.io)
