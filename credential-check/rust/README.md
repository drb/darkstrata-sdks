# DarkStrata Credential Check SDK for Rust

A Rust SDK for checking if credentials have been exposed in data breaches using the DarkStrata API with k-anonymity privacy protection.

## Features

- **Privacy-First**: Uses k-anonymity to ensure your credentials are never exposed
- **Async/Await**: Built on tokio for efficient async operations
- **Batch Processing**: Check multiple credentials efficiently with optimized API calls
- **Automatic Retries**: Exponential backoff for transient failures
- **Response Caching**: Reduces API calls with intelligent caching
- **Type-Safe**: Comprehensive Rust types with full error handling
- **Zero Unsafe Code**: 100% safe Rust implementation

## Prerequisites

1. **Get an API key** from [https://darkstrata.io](https://darkstrata.io)
2. Rust 1.70 or higher

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
darkstrata-credential-check = "0.1"
tokio = { version = "1.0", features = ["rt-multi-thread", "macros"] }
```

## Quick Start

```rust
use darkstrata_credential_check::{DarkStrataCredentialCheck, ClientOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a client with your API key
    let client = DarkStrataCredentialCheck::new(
        ClientOptions::new("your-api-key")
    )?;

    // Check a single credential
    let result = client.check("user@example.com", "password123", None).await?;

    if result.found {
        println!("This credential has been compromised!");
    } else {
        println!("Credential not found in any known breaches.");
    }

    Ok(())
}
```

## Usage

### Check a Single Credential

```rust
let result = client.check("user@example.com", "password123", None).await?;

println!("Found: {}", result.found);
println!("Prefix: {}", result.metadata.prefix);
println!("Total matches: {}", result.metadata.total_results);
```

### Check a Pre-computed Hash

If you've already computed the SHA-256 hash of the credential (`email:password`):

```rust
use darkstrata_credential_check::crypto_utils;

// Compute hash yourself
let hash = crypto_utils::hash_credential("user@example.com", "password123");

// Or use a pre-computed hash
let result = client.check_hash(&hash, None).await?;
```

### Batch Check

Check multiple credentials efficiently:

```rust
use darkstrata_credential_check::Credential;

let credentials = vec![
    Credential::new("alice@example.com", "password1"),
    Credential::new("bob@example.com", "password2"),
    Credential::new("carol@example.com", "password3"),
];

let results = client.check_batch(&credentials, None).await?;

for (cred, result) in credentials.iter().zip(results.iter()) {
    println!("{}: {}", cred.email, if result.found { "compromised" } else { "safe" });
}
```

### Check Options

Filter by date or use a custom HMAC key:

```rust
use darkstrata_credential_check::CheckOptions;

// Filter to breaches since a specific date
let options = CheckOptions::new()
    .since_epoch_day(19724);  // 2024-01-01

let result = client.check("user@example.com", "password", Some(options)).await?;

// Use a custom HMAC key for deterministic results
let options = CheckOptions::new()
    .client_hmac("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

let result = client.check("user@example.com", "password", Some(options)).await?;
```

### Client Configuration

```rust
use std::time::Duration;

let client = DarkStrataCredentialCheck::new(
    ClientOptions::new("your-api-key")
        .base_url("https://custom.api.com/v1/")
        .timeout(Duration::from_secs(60))
        .retries(5)
        .enable_caching(true)
        .cache_ttl(Duration::from_secs(1800))
)?;
```

## Error Handling

The SDK provides detailed error types for comprehensive error handling:

```rust
use darkstrata_credential_check::DarkStrataError;

match client.check("user@example.com", "password", None).await {
    Ok(result) => {
        println!("Found: {}", result.found);
    }
    Err(DarkStrataError::Authentication { .. }) => {
        println!("Invalid API key");
    }
    Err(DarkStrataError::RateLimit { retry_after }) => {
        if let Some(duration) = retry_after {
            println!("Rate limited. Retry after {:?}", duration);
        }
    }
    Err(DarkStrataError::Validation { message, field }) => {
        println!("Validation error: {} (field: {:?})", message, field);
    }
    Err(e) if e.is_retryable() => {
        println!("Transient error, can retry: {}", e);
    }
    Err(e) => {
        println!("Error: {}", e);
    }
}
```

## How It Works

The SDK uses k-anonymity to protect your credentials:

1. Your credential is hashed using SHA-256: `SHA256(email:password)`
2. Only the first 5 characters (prefix) are sent to the API
3. The API returns all hashes matching that prefix (1-in-1,000,000 anonymity)
4. The SDK checks locally if your full hash exists in the returned set
5. Timing-safe comparison prevents timing attacks

Your actual credentials or full hashes are **never** sent to the server.

## API Reference

### `DarkStrataCredentialCheck`

The main client for interacting with the DarkStrata API.

| Method | Description |
|--------|-------------|
| `new(options)` | Create a new client |
| `check(email, password, options)` | Check a single credential |
| `check_hash(hash, options)` | Check a pre-computed hash |
| `check_batch(credentials, options)` | Check multiple credentials |
| `clear_cache()` | Clear the response cache |
| `cache_size()` | Get the current cache size |

### `ClientOptions`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api_key` | `String` | Required | Your API key |
| `base_url` | `Option<String>` | `https://api.darkstrata.io/v1/` | API base URL |
| `timeout` | `Option<Duration>` | 30 seconds | Request timeout |
| `retries` | `Option<u32>` | 3 | Number of retry attempts |
| `enable_caching` | `Option<bool>` | true | Enable response caching |
| `cache_ttl` | `Option<Duration>` | 1 hour | Cache time-to-live |

### `CheckOptions`

| Option | Type | Description |
|--------|------|-------------|
| `client_hmac` | `Option<String>` | Custom HMAC key (64+ hex chars) |
| `since` | `Option<SinceFilter>` | Filter by breach date |

### `CheckResult`

| Field | Type | Description |
|-------|------|-------------|
| `found` | `bool` | Whether credential was found in a breach |
| `credential` | `CredentialInfo` | Info about the checked credential |
| `metadata` | `CheckMetadata` | Additional metadata about the check |

## Examples

Run the examples with:

```bash
DARKSTRATA_API_KEY=your-key cargo run --example basic_usage
DARKSTRATA_API_KEY=your-key cargo run --example batch_check
DARKSTRATA_API_KEY=your-key cargo run --example error_handling
```

## Testing

```bash
# Run unit tests
cargo test

# Run with all features
cargo test --all-features
```

## Requirements

- Rust 1.70 or later
- tokio runtime

## License

Apache License 2.0 - see [LICENSE](../LICENSE) for details.
