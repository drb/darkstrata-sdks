# DarkStrata Credential Check SDK for Go

Check if credentials have been exposed in data breaches using k-anonymity to protect user privacy.

## Installation

```bash
go get github.com/darkstrata/darkstrata-sdks/sdks/go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    credentialcheck "github.com/darkstrata/darkstrata-sdks/sdks/go"
)

func main() {
    // Create client
    client, err := credentialcheck.NewClient(credentialcheck.ClientOptions{
        APIKey: os.Getenv("DARKSTRATA_API_KEY"),
    })
    if err != nil {
        log.Fatal(err)
    }

    // Check a credential
    result, err := client.Check(context.Background(), "user@example.com", "password123", nil)
    if err != nil {
        log.Fatal(err)
    }

    if result.Found {
        fmt.Println("WARNING: Credential found in breach!")
    } else {
        fmt.Println("OK: Credential not found in known breaches")
    }
}
```

## Features

- **Privacy-first k-anonymity** - Only the first 5 characters of the hash are sent to the server
- **Zero external dependencies** - Uses only Go standard library
- **Batch checking** - Efficiently check multiple credentials with automatic prefix grouping
- **Automatic retries** - Exponential backoff for transient failures
- **Response caching** - In-memory cache with TTL and time-window awareness
- **Comprehensive error types** - Detailed error handling with retryability info
- **Context support** - Full support for Go context cancellation and timeouts

## API Reference

### Creating a Client

```go
client, err := credentialcheck.NewClient(credentialcheck.ClientOptions{
    APIKey:        "your-api-key",           // Required
    BaseURL:       "https://custom.api/v1/", // Optional (default: https://api.darkstrata.io/v1/)
    Timeout:       30 * time.Second,         // Optional (default: 30s)
    Retries:       3,                        // Optional (default: 3)
    EnableCaching: &trueVal,                 // Optional (default: true)
    CacheTTL:      1 * time.Hour,           // Optional (default: 1 hour)
})
```

### Check Methods

#### Check a credential

```go
result, err := client.Check(ctx, email, password, nil)
```

#### Check a pre-computed hash

```go
hash := credentialcheck.HashCredential(email, password)
result, err := client.CheckHash(ctx, hash, nil)
```

#### Batch check multiple credentials

```go
credentials := []credentialcheck.Credential{
    {Email: "alice@example.com", Password: "alice123"},
    {Email: "bob@example.com", Password: "bob456"},
}
results, err := client.CheckBatch(ctx, credentials, nil)
```

### Check Options

```go
since := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
result, err := client.Check(ctx, email, password, &credentialcheck.CheckOptions{
    ClientHMAC: "your-64-char-hex-key...", // For deterministic results
    Since:      &since,                     // Filter breaches by date
})
```

### Check Result

```go
type CheckResult struct {
    Found      bool           // true if found in breach
    Credential CredentialInfo // Masked credential info
    Metadata   CheckMetadata  // Additional information
}

type CheckMetadata struct {
    Prefix       string    // 5-char hash prefix used
    TotalResults int       // Number of matching hashes
    HMACSource   string    // "server" or "client"
    TimeWindow   string    // Server HMAC rotation window
    FilterSince  int64     // Epoch day filter applied
    CachedResult bool      // Whether from cache
    CheckedAt    time.Time // Timestamp of check
}
```

### Cache Management

```go
// Get cache size
size := client.GetCacheSize()

// Clear cache
client.ClearCache()
```

## Error Handling

The SDK provides specific error types for different failure scenarios:

```go
result, err := client.Check(ctx, email, password, nil)
if err != nil {
    switch e := err.(type) {
    case *credentialcheck.AuthenticationError:
        // Invalid API key (not retryable)

    case *credentialcheck.ValidationError:
        // Invalid input, check e.Field

    case *credentialcheck.RateLimitError:
        // Rate limited, check e.RetryAfter

    case *credentialcheck.TimeoutError:
        // Request timed out (retryable)

    case *credentialcheck.NetworkError:
        // Network failure (retryable)

    case *credentialcheck.APIError:
        // API error, check e.StatusCode
    }
}

// Check if an error is retryable
if credentialcheck.IsRetryable(err) {
    // Implement retry logic
}
```

## Cryptographic Utilities

The SDK exports utility functions for advanced use cases:

```go
// Hash a credential
hash := credentialcheck.HashCredential(email, password)

// SHA-256 hash
hash := credentialcheck.SHA256(input)

// HMAC-SHA256
hmac, err := credentialcheck.HMACSHA256(message, hexKey)

// Extract k-anonymity prefix
prefix := credentialcheck.ExtractPrefix(hash)

// Validate hash format
valid := credentialcheck.IsValidHash(hash, 64)

// Validate prefix format
valid := credentialcheck.IsValidPrefix(prefix)
```

## How K-Anonymity Works

1. The SDK computes `SHA-256(email:password)` locally
2. Only the first 5 characters (prefix) are sent to the server
3. The server returns all hashes matching that prefix (typically 50-1000)
4. The SDK checks if the full hash is in the response using HMAC verification
5. Your actual credential never leaves your device

## License

Apache-2.0
