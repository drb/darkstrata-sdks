# DarkStrata Credential Check - C# SDK

Check if credentials have been exposed in data breaches using k-anonymity to protect the credentials being checked.

[![NuGet](https://img.shields.io/nuget/v/DarkStrata.CredentialCheck.svg)](https://www.nuget.org/packages/DarkStrata.CredentialCheck)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Features

- **Privacy-First**: Uses k-anonymity so your credentials are never sent to our servers
- **Type-Safe**: Full nullable reference types and modern C# patterns
- **Async/Await**: Native async support with cancellation tokens
- **Batch Processing**: Check multiple credentials efficiently with automatic prefix grouping
- **Smart Caching**: Built-in caching aligned with server HMAC rotation
- **Retry Logic**: Automatic retries with exponential backoff
- **Comprehensive Errors**: Typed exceptions for all error scenarios

## Prerequisites

- .NET 8.0 or later
- DarkStrata API key (obtain from your dashboard)

## Installation

```bash
dotnet add package DarkStrata.CredentialCheck
```

Or via Package Manager:

```powershell
Install-Package DarkStrata.CredentialCheck
```

## Quick Start

```csharp
using DarkStrata.CredentialCheck;

// Create client
using var client = new DarkStrataCredentialCheck(new ClientOptions
{
    ApiKey = Environment.GetEnvironmentVariable("DARKSTRATA_API_KEY")!
});

// Check a credential
var result = await client.CheckAsync("user@example.com", "password123");

if (result.Found)
{
    Console.WriteLine("This credential was found in a data breach!");
}
```

## How It Works

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│                 │         │                 │         │                 │
│   Your App      │         │   DarkStrata    │         │   Breach DB     │
│                 │         │      API        │         │                 │
└────────┬────────┘         └────────┬────────┘         └────────┬────────┘
         │                           │                           │
    1. Hash credential               │                           │
    (SHA-256)                        │                           │
         │                           │                           │
    2. Send only first 5            │                           │
    chars of hash (prefix)───────────►                           │
         │                           │                           │
         │                      3. Find all matching             │
         │                      hashes with prefix ──────────────►
         │                           │                           │
         │                           │◄──────────────────────────┤
         │                      4. Apply HMAC to                 │
         │                      matching hashes                  │
         │                           │                           │
         │◄──────────────────────────┤                           │
    5. Compare HMAC                  │                           │
    locally                          │                           │
         │                           │                           │
```

Your actual credentials never leave your system - only a 5-character prefix of the hash is sent to the API.

## API Reference

### DarkStrataCredentialCheck

#### Constructor

```csharp
new DarkStrataCredentialCheck(ClientOptions options)
```

**ClientOptions:**
| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `ApiKey` | `string` | *required* | Your DarkStrata API key |
| `BaseUrl` | `string?` | `https://api.darkstrata.io/v1/` | API base URL |
| `Timeout` | `TimeSpan?` | 30 seconds | Request timeout |
| `Retries` | `int?` | 3 | Number of retry attempts |
| `EnableCaching` | `bool?` | `true` | Enable response caching |
| `CacheTtl` | `TimeSpan?` | 1 hour | Cache time-to-live |

#### Methods

##### CheckAsync

```csharp
Task<CheckResult> CheckAsync(
    string email,
    string password,
    CheckOptions? options = null,
    CancellationToken cancellationToken = default)
```

Check if a credential has been exposed in a data breach.

##### CheckHashAsync

```csharp
Task<CheckResult> CheckHashAsync(
    string hash,
    CheckOptions? options = null,
    CancellationToken cancellationToken = default)
```

Check a pre-computed SHA-256 hash of `email:password`.

##### CheckBatchAsync

```csharp
Task<IReadOnlyList<CheckResult>> CheckBatchAsync(
    IEnumerable<Credential> credentials,
    CheckOptions? options = null,
    CancellationToken cancellationToken = default)
```

Check multiple credentials efficiently with automatic prefix grouping.

### CheckOptions

| Property | Type | Description |
|----------|------|-------------|
| `ClientHmac` | `string?` | Client-provided HMAC key for deterministic results (64+ hex chars) |
| `Since` | `DateTimeOffset?` | Filter breaches from this date onwards |
| `SinceEpochDay` | `int?` | Filter breaches from this epoch day onwards |

### CheckResult

| Property | Type | Description |
|----------|------|-------------|
| `Found` | `bool` | Whether the credential was found in a breach |
| `Email` | `string` | The email that was checked |
| `Masked` | `bool` | Always `true` - password is never returned |
| `Metadata` | `CheckMetadata` | Additional information about the check |

## Examples

### Basic Check

```csharp
var result = await client.CheckAsync("user@example.com", "password123");
Console.WriteLine($"Found: {result.Found}");
Console.WriteLine($"Prefix: {result.Metadata.Prefix}");
Console.WriteLine($"Total matches: {result.Metadata.TotalResults}");
```

### Batch Check

```csharp
var credentials = new Credential[]
{
    new("user1@example.com", "pass1"),
    new("user2@example.com", "pass2"),
    new("user3@example.com", "pass3"),
};

var results = await client.CheckBatchAsync(credentials);

foreach (var result in results)
{
    if (result.Found)
    {
        Console.WriteLine($"Compromised: {result.Email}");
    }
}
```

### With Date Filter

```csharp
// Only check breaches from 2024 onwards
var result = await client.CheckAsync("user@example.com", "password", new CheckOptions
{
    Since = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero)
});
```

### Error Handling

```csharp
try
{
    var result = await client.CheckAsync(email, password);
}
catch (AuthenticationException)
{
    Console.WriteLine("Invalid API key");
}
catch (RateLimitException ex)
{
    Console.WriteLine($"Rate limited. Retry after {ex.RetryAfter} seconds");
}
catch (DarkStrataTimeoutException ex)
{
    Console.WriteLine($"Request timed out after {ex.TimeoutMs}ms");
}
catch (NetworkException ex)
{
    Console.WriteLine($"Network error: {ex.Message}");
}
catch (ApiException ex)
{
    Console.WriteLine($"API error {ex.StatusCode}: {ex.ResponseBody}");
}
```

## Exception Types

| Exception | Code | Retryable | Description |
|-----------|------|-----------|-------------|
| `AuthenticationException` | 401 | No | Invalid API key |
| `ValidationException` | - | No | Invalid input parameters |
| `RateLimitException` | 429 | Yes | Rate limit exceeded |
| `DarkStrataTimeoutException` | - | Yes | Request timed out |
| `NetworkException` | - | Yes | Network connectivity issue |
| `ApiException` | varies | varies | General API error |

## License

Apache 2.0 - see [LICENSE](LICENSE)
