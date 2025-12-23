# DarkStrata SDKs

Official SDKs for integrating with [DarkStrata](https://darkstrata.io) services.

## Available SDKs

| Language | Package | Version | Documentation |
|----------|---------|---------|---------------|
| Node.js / TypeScript | `@darkstrata/credential-check` | [![npm](https://img.shields.io/npm/v/@darkstrata/credential-check.svg)](https://www.npmjs.com/package/@darkstrata/credential-check) | [README](./node/README.md) |
| Python | `darkstrata-credential-check` | [![PyPI](https://img.shields.io/pypi/v/darkstrata-credential-check.svg)](https://pypi.org/project/darkstrata-credential-check/) | [README](./python/README.md) |
| Rust | `darkstrata-credential-check` | [![crates.io](https://img.shields.io/crates/v/darkstrata-credential-check.svg)](https://crates.io/crates/darkstrata-credential-check) | [README](./rust/README.md) |
| C# / .NET | `DarkStrata.CredentialCheck` | [![NuGet](https://img.shields.io/nuget/v/DarkStrata.CredentialCheck.svg)](https://www.nuget.org/packages/DarkStrata.CredentialCheck) | [README](./csharp/README.md) |
| Go | `github.com/darkstrata/darkstrata-sdks/go` | [![Go Reference](https://pkg.go.dev/badge/github.com/darkstrata/darkstrata-sdks/go.svg)](https://pkg.go.dev/github.com/darkstrata/darkstrata-sdks/go) | [README](./go/README.md) |
| Java | `io.darkstrata:credential-check` | [![Maven Central](https://img.shields.io/maven-central/v/io.darkstrata/credential-check.svg)](https://central.sonatype.com/artifact/io.darkstrata/credential-check) | [README](./java/README.md) |

## Credential Check SDK

Check if credentials have been exposed in data breaches using k-anonymity.

### Features

- **Privacy-first**: Only a 5-character hash prefix is sent to our servers
- **No credential exposure**: Your passwords never leave your system
- **Batch processing**: Efficiently check multiple credentials
- **Full type safety**: TypeScript types, Python type hints, Rust's strong typing, Go's static types, and Java's strong typing

### Quick Example

#### Node.js / TypeScript

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

#### Python

```python
import asyncio
from darkstrata_credential_check import DarkStrataCredentialCheck

async def main():
    async with DarkStrataCredentialCheck(api_key='your-api-key') as client:
        result = await client.check('user@example.com', 'password123')

        if result.found:
            print('Credential found in breach database!')

asyncio.run(main())
```

#### Rust

```rust
use darkstrata_credential_check::{DarkStrataCredentialCheck, ClientOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = DarkStrataCredentialCheck::new(
        ClientOptions::new("your-api-key")
    )?;

    let result = client.check("user@example.com", "password123", None).await?;

    if result.found {
        println!("Credential found in breach database!");
    }

    Ok(())
}
```

#### C# / .NET

```csharp
using DarkStrata.CredentialCheck;

using var client = new DarkStrataCredentialCheck(new ClientOptions
{
    ApiKey = "your-api-key"
});

var result = await client.CheckAsync("user@example.com", "password123");

if (result.Found)
{
    Console.WriteLine("Credential found in breach database!");
}
```

#### Go

```go
package main

import (
    "context"
    "fmt"
    "log"

    credentialcheck "github.com/darkstrata/darkstrata-sdks/go"
)

func main() {
    client, err := credentialcheck.NewClient(credentialcheck.ClientOptions{
        APIKey: "your-api-key",
    })
    if err != nil {
        log.Fatal(err)
    }

    result, err := client.Check(context.Background(), "user@example.com", "password123", nil)
    if err != nil {
        log.Fatal(err)
    }

    if result.Found {
        fmt.Println("Credential found in breach database!")
    }
}
```

#### Java

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
- [Python SDK Documentation](./python/README.md)
- [Rust SDK Documentation](./rust/README.md)
- [C# SDK Documentation](./csharp/README.md)
- [Go SDK Documentation](./go/README.md)
- [Java SDK Documentation](./java/README.md)
- [API Documentation](https://docs.darkstrata.io)
- [DarkStrata Dashboard](https://app.darkstrata.io)

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## Security

If you discover a security vulnerability, please email security@darkstrata.io instead of using the issue tracker.

## Licence

Apache 2.0 © [DarkStrata Ltd](https://darkstrata.io)
