# DarkStrata Credential Check SDK for Java

Check if credentials have been exposed in data breaches using k-anonymity.

## Installation

### Maven

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.darkstrata</groupId>
    <artifactId>credential-check</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'io.darkstrata:credential-check:1.0.0'
```

## Quick Start

```java
import io.darkstrata.credentialcheck.*;

public class Example {
    public static void main(String[] args) throws Exception {
        try (DarkStrataCredentialCheck client = new DarkStrataCredentialCheck(
                ClientOptions.builder("your-api-key").build()
        )) {
            CheckResult result = client.check("user@example.com", "password123");

            if (result.isFound()) {
                System.out.println("Credential found in breach database!");
            }
        }
    }
}
```

## Features

- **Privacy-first**: Only a 5-character hash prefix is sent to our servers
- **No credential exposure**: Your passwords never leave your system
- **Batch processing**: Efficiently check multiple credentials
- **Automatic retries**: Built-in retry logic with exponential backoff
- **Caching**: Optional in-memory caching to reduce API calls
- **Async support**: CompletableFuture-based async methods

## Usage

### Basic Credential Check

```java
try (DarkStrataCredentialCheck client = new DarkStrataCredentialCheck(
        ClientOptions.builder("your-api-key").build()
)) {
    CheckResult result = client.check("user@example.com", "password123");

    if (result.isFound()) {
        System.out.println("WARNING: Credential exposed in a data breach!");
    } else {
        System.out.println("Credential not found in any known breaches.");
    }
}
```

### Check a Pre-computed Hash

```java
// SHA-256 hash of "email:password"
String hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8...";

CheckResult result = client.checkHash(hash);
```

### Batch Check

```java
List<Credential> credentials = Arrays.asList(
    new Credential("user1@example.com", "password1"),
    new Credential("user2@example.com", "password2"),
    new Credential("user3@example.com", "password3")
);

List<CheckResult> results = client.checkBatch(credentials);

for (int i = 0; i < results.size(); i++) {
    CheckResult result = results.get(i);
    if (result.isFound()) {
        System.out.println("Compromised: " + credentials.get(i).getEmail());
    }
}
```

### Async Check

```java
CompletableFuture<CheckResult> future = client.checkAsync("user@example.com", "password123");

future.thenAccept(result -> {
    if (result.isFound()) {
        System.out.println("Found in breach database!");
    }
}).exceptionally(ex -> {
    System.err.println("Error: " + ex.getMessage());
    return null;
});
```

### Configuration Options

```java
ClientOptions options = ClientOptions.builder("your-api-key")
    .baseUrl("https://api.darkstrata.io/v1/")  // Custom API URL
    .timeout(60000)                              // Request timeout (ms)
    .retries(5)                                  // Retry attempts
    .enableCaching(true)                         // Enable response caching
    .cacheTTL(3600000)                           // Cache TTL (ms)
    .build();

DarkStrataCredentialCheck client = new DarkStrataCredentialCheck(options);
```

### Check Options

```java
CheckOptions options = CheckOptions.builder()
    .clientHmac("your-256-bit-hex-key")  // Use your own HMAC key
    .since(LocalDate.of(2024, 1, 1))     // Only check breaches since this date
    .build();

CheckResult result = client.check("user@example.com", "password123", options);
```

## Error Handling

```java
try {
    CheckResult result = client.check("user@example.com", "password123");
} catch (ValidationException e) {
    // Input validation failed
    System.err.println("Invalid input: " + e.getMessage());
    System.err.println("Field: " + e.getField());
} catch (AuthenticationException e) {
    // API key is invalid
    System.err.println("Auth failed: " + e.getMessage());
} catch (RateLimitException e) {
    // Rate limited
    System.err.println("Rate limited, retry after: " + e.getRetryAfter() + "s");
} catch (TimeoutException e) {
    // Request timed out
    System.err.println("Timed out after: " + e.getTimeoutMs() + "ms");
} catch (NetworkException e) {
    // Network error
    System.err.println("Network error: " + e.getMessage());
} catch (ApiException e) {
    // API error
    System.err.println("API error " + e.getStatusCode() + ": " + e.getMessage());
} catch (DarkStrataException e) {
    // Any other SDK error
    System.err.println("Error: " + e.getMessage());
    System.err.println("Retryable: " + e.isRetryable());
}
```

## Cache Management

```java
// Get cache size
int size = client.getCacheSize();

// Clear cache
client.clearCache();
```

## How K-Anonymity Works

```
Your System                         DarkStrata API
    |                                    |
    |  Hash: email:password              |
    |  SHA256 -> 5BAA61E4C9B93F3F...     |
    |                                    |
    |  Send prefix only: "5BAA6"  ------>|
    |                                    |
    |  <------ All hashes with prefix    |
    |                                    |
    |  Check if your hash is in set      |
    |  Result: found or not found        |
    |                                    |
```

Only **5 characters** of a 64-character hash are sent. This provides:
- 1-in-1,000,000 anonymity set
- Your actual credentials are never transmitted
- Even if intercepted, the prefix reveals nothing

## Requirements

- Java 11 or higher
- OkHttp (included as dependency)
- Gson (included as dependency)

## Licence

Apache 2.0
