# darkstrata-credential-check

Check if credentials have been exposed in data breaches using k-anonymity.

[![PyPI version](https://img.shields.io/pypi/v/darkstrata-credential-check.svg)](https://pypi.org/project/darkstrata-credential-check/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Features

- **Privacy-first**: Uses k-anonymity to check credentials without exposing them
- **Type-safe**: Full type hints with comprehensive dataclass definitions
- **Async-first**: Built on `httpx` for efficient async HTTP operations
- **Automatic caching**: Intelligent caching aligned with server time windows
- **Batch processing**: Efficiently check multiple credentials with automatic prefix grouping
- **Retry logic**: Built-in exponential backoff for transient failures
- **Comprehensive errors**: Detailed error types for easy error handling

## Prerequisites

1. **Get an API key** from [https://darkstrata.io](https://darkstrata.io)
2. Python 3.10 or higher

## Installation

```bash
pip install darkstrata-credential-check
```

```bash
poetry add darkstrata-credential-check
```

```bash
uv add darkstrata-credential-check
```

## Quick Start

```python
import asyncio
from darkstrata_credential_check import DarkStrataCredentialCheck

async def main():
    # Create a client
    async with DarkStrataCredentialCheck(api_key='your-api-key') as client:
        # Check a single credential
        result = await client.check('user@example.com', 'password123')

        if result.found:
            print('WARNING: This credential was found in a data breach!')
        else:
            print('Credential not found in known breaches.')

asyncio.run(main())
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

```python
DarkStrataCredentialCheck(
    api_key: str,
    *,
    base_url: str = 'https://api.darkstrata.io/v1/',
    timeout: float = 30.0,
    retries: int = 3,
    enable_caching: bool = True,
    cache_ttl: int = 3600,
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_key` | `str` | *required* | Your DarkStrata API key |
| `base_url` | `str` | `'https://api.darkstrata.io/v1/'` | API base URL |
| `timeout` | `float` | `30.0` | Request timeout in seconds |
| `retries` | `int` | `3` | Number of retry attempts |
| `enable_caching` | `bool` | `True` | Enable response caching |
| `cache_ttl` | `int` | `3600` | Cache TTL in seconds (1 hour) |

#### Methods

##### `check(email, password, options?)`

Check a single credential.

```python
result = await client.check('user@example.com', 'password123')
```

**Returns:** `CheckResult`

##### `check_hash(hash, options?)`

Check a pre-computed SHA-256 hash.

```python
hash_value = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8...'
result = await client.check_hash(hash_value)
```

**Returns:** `CheckResult`

##### `check_batch(credentials, options?)`

Check multiple credentials efficiently.

```python
from darkstrata_credential_check import Credential

results = await client.check_batch([
    Credential(email='user1@example.com', password='pass1'),
    Credential(email='user2@example.com', password='pass2'),
])
```

**Returns:** `list[CheckResult]`

##### `clear_cache()`

Clear the internal response cache.

```python
client.clear_cache()
```

##### `get_cache_size()`

Get the number of cached entries.

```python
size = client.get_cache_size()
```

### `CheckResult`

The result of a credential check.

```python
@dataclass
class CheckResult:
    found: bool                    # true if credential was in a breach
    credential: CredentialInfo     # info about the credential checked
    metadata: CheckMetadata        # additional metadata
```

### `CheckMetadata`

Metadata returned with check results.

```python
@dataclass
class CheckMetadata:
    prefix: str                    # The 5-char prefix used
    total_results: int             # Total hashes returned by API
    hmac_source: Literal['server', 'client']  # Source of HMAC key
    time_window: int | None        # Server time window (server HMAC only)
    filter_since: int | None       # Epoch day filter (if since was used)
    cached_result: bool            # Whether result was from cache
    checked_at: datetime           # When the check was performed
```

### `CheckOptions`

Optional parameters for check requests.

```python
@dataclass
class CheckOptions:
    client_hmac: str | None = None   # Your own HMAC key (64+ hex chars)
    since: int | datetime | None = None  # Filter by breach date
```

## Error Handling

The SDK provides specific error types for different failure scenarios:

```python
from darkstrata_credential_check import (
    DarkStrataCredentialCheck,
    AuthenticationError,
    ValidationError,
    ApiError,
    TimeoutError,
    NetworkError,
    RateLimitError,
    is_darkstrata_error,
)

async with DarkStrataCredentialCheck(api_key='your-key') as client:
    try:
        result = await client.check('user@example.com', 'password')
    except AuthenticationError:
        print('Invalid API key')
    except ValidationError as error:
        print(f'Invalid input: {error.field}')
    except RateLimitError as error:
        if error.retry_after:
            print(f'Rate limited. Retry after {error.retry_after} seconds')
    except TimeoutError as error:
        print(f'Request timed out after {error.timeout_seconds}s')
    except NetworkError as error:
        print(f'Network error: {error}')
    except ApiError as error:
        print(f'API error ({error.status_code}): {error}')
    except Exception as error:
        if is_darkstrata_error(error):
            print(f'DarkStrata error [{error.code}]: {error}')
        else:
            raise
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

```python
from darkstrata_credential_check import hash_credential, DarkStrataCredentialCheck

# Compute hash once
hash_value = hash_credential('user@example.com', 'password123')
# Store hash securely...

# Later, check the hash
async with DarkStrataCredentialCheck(api_key='your-key') as client:
    result = await client.check_hash(hash_value)
```

### Batch Processing

For checking multiple credentials, use `check_batch` for efficiency:

```python
from darkstrata_credential_check import Credential

credentials = [
    Credential(email='user1@example.com', password='pass1'),
    Credential(email='user2@example.com', password='pass2'),
    Credential(email='user3@example.com', password='pass3'),
]

results = await client.check_batch(credentials)

compromised = [r for r in results if r.found]
print(f'{len(compromised)} credentials were compromised')
```

Batch processing automatically groups credentials by prefix to minimise API calls.

### Client-Provided HMAC Key

By default, the server generates a time-rotating HMAC key. For deterministic results across requests, provide your own key:

```python
import secrets
from darkstrata_credential_check import CheckOptions

# Generate a secure key once and store it securely
client_hmac = secrets.token_hex(32)  # 64 hex chars = 256 bits

result = await client.check('user@example.com', 'password',
    CheckOptions(client_hmac=client_hmac))

# Results are now deterministic (not time-windowed)
print(result.metadata.hmac_source)  # 'client'
```

**When to use client HMAC:**
- You need consistent results across multiple requests
- You're comparing results from different time periods
- You want to avoid server-side key rotation

### Date Filtering

Filter results to only include breaches from a specific date onwards:

```python
from datetime import datetime
from darkstrata_credential_check import CheckOptions

# Only check breaches from 2024 onwards
result = await client.check('user@example.com', 'password',
    CheckOptions(since=datetime(2024, 1, 1)))

# Or use epoch day (days since 1 January 1970)
result = await client.check('user@example.com', 'password',
    CheckOptions(since=19724))  # 2024-01-01

# Check the filter applied
print(result.metadata.filter_since)  # 19724
```

### Combined Options

You can combine multiple options:

```python
result = await client.check('user@example.com', 'password',
    CheckOptions(
        client_hmac='your-256-bit-hex-key...',
        since=datetime(2024, 1, 1),
    ))
```

### Disabling Cache

For real-time checks where you need fresh results:

```python
client = DarkStrataCredentialCheck(
    api_key='your-key',
    enable_caching=False,
)
```

### Custom Timeout and Retries

```python
client = DarkStrataCredentialCheck(
    api_key='your-key',
    timeout=60.0,  # 60 seconds
    retries=5,     # 5 retry attempts
)
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

## Type Hints

This package includes comprehensive type hints and exports all types:

```python
from darkstrata_credential_check import (
    ClientOptions,
    Credential,
    CheckOptions,
    CheckResult,
    CheckMetadata,
    CredentialInfo,
)
```

## Context Manager

The client supports async context manager for proper resource cleanup:

```python
async with DarkStrataCredentialCheck(api_key='your-key') as client:
    result = await client.check('user@example.com', 'password')
# HTTP client is automatically closed
```

Alternatively, close manually:

```python
client = DarkStrataCredentialCheck(api_key='your-key')
try:
    result = await client.check('user@example.com', 'password')
finally:
    await client.close()
```

## Contributing

See the [contributing guide](https://github.com/darkstrata/darkstrata-sdks/blob/main/CONTRIBUTING.md).

## Licence

Apache 2.0 (c) [DarkStrata](https://darkstrata.io)
