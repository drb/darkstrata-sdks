# DarkStrata SDKs & Integrations

Official SDKs and platform integrations for [DarkStrata](https://darkstrata.io) credential exposure detection services.

## Table of Contents

- [Overview](#overview)
- [SDKs](#sdks)
  - [Available SDKs](#available-sdks)
  - [Features](#features)
  - [Quick Start](#quick-start)
  - [How K-Anonymity Works](#how-k-anonymity-works)
- [Integrations](#integrations)
  - [Splunk Technology Add-on](#splunk-technology-add-on)
  - [Umbraco CMS Package](#umbraco-cms-package)
- [Getting Started](#getting-started)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Security](#security)
- [Licence](#licence)

---

## Overview

This monorepo contains everything you need to integrate with DarkStrata:

- **SDKs** - Client libraries for 6 languages to check credentials against the DarkStrata breach database using k-anonymity
- **Integrations** - Pre-built platform integrations that bring DarkStrata threat intelligence into your existing security tooling

---

## SDKs

### Available SDKs

| Language | Package | Version | Documentation |
|----------|---------|---------|---------------|
| Node.js / TypeScript | `@darkstrata/credential-check` | [![npm](https://img.shields.io/npm/v/@darkstrata/credential-check.svg)](https://www.npmjs.com/package/@darkstrata/credential-check) | [README](./sdks/node/README.md) |
| Python | `darkstrata-credential-check` | [![PyPI](https://img.shields.io/pypi/v/darkstrata-credential-check.svg)](https://pypi.org/project/darkstrata-credential-check/) | [README](./sdks/python/README.md) |
| Rust | `darkstrata-credential-check` | [![crates.io](https://img.shields.io/crates/v/darkstrata-credential-check.svg)](https://crates.io/crates/darkstrata-credential-check) | [README](./sdks/rust/README.md) |
| C# / .NET | `DarkStrata.CredentialCheck` | [![NuGet](https://img.shields.io/nuget/v/DarkStrata.CredentialCheck.svg)](https://www.nuget.org/packages/DarkStrata.CredentialCheck) | [README](./sdks/csharp/README.md) |
| Go | `github.com/darkstrata/darkstrata-sdks/sdks/go` | [![Go Reference](https://pkg.go.dev/badge/github.com/darkstrata/darkstrata-sdks/sdks/go.svg)](https://pkg.go.dev/github.com/darkstrata/darkstrata-sdks/sdks/go) | [README](./sdks/go/README.md) |
| Java | `io.darkstrata:credential-check` | [![Maven Central](https://img.shields.io/maven-central/v/io.darkstrata/credential-check.svg)](https://central.sonatype.com/artifact/io.darkstrata/credential-check) | [README](./sdks/java/README.md) |

> **Note:** The C# SDK supports both modern .NET (8.0+) and .NET Framework (4.6.1+) via multi-targeting.

### Features

- **Privacy-first**: Only a 5 or 6-character hash prefix is sent to our servers
- **No credential exposure**: Your passwords never leave your system
- **Batch processing**: Efficiently check multiple credentials
- **Full type safety**: TypeScript types, Python type hints, Rust's strong typing, Go's static types, and Java's strong typing

### Quick Start

#### Node.js / TypeScript

```typescript
import { DarkStrataCredentialCheck, hashCredential } from '@darkstrata/credential-check';

const client = new DarkStrataCredentialCheck({
  apiKey: 'your-api-key',
});

// email and password come from your login form and are only ever used here.
// 1. Hash the credential locally: SHA-256 of "email:password".
//    The plaintext email and password never leave this process.
const hash = hashCredential(email, password);

// 2. Check the hash. The SDK sends only the first 5-6 characters (the
//    k-anonymity prefix) to the API and compares the full hash locally.
const result = await client.checkHash(hash);

if (result.found) {
  console.log('Credential found in breach database!');
}
```

#### Python

```python
import asyncio
from darkstrata_credential_check import DarkStrataCredentialCheck, hash_credential

async def main():
    async with DarkStrataCredentialCheck(api_key='your-api-key') as client:
        # email and password come from your login form and are only ever used here.
        # 1. Hash the credential locally: SHA-256 of "email:password".
        #    The plaintext email and password never leave this process.
        hash_value = hash_credential(email, password)

        # 2. Check the hash. The SDK sends only the first 5-6 characters (the
        #    k-anonymity prefix) to the API and compares the full hash locally.
        result = await client.check_hash(hash_value)

        if result.found:
            print('Credential found in breach database!')

asyncio.run(main())
```

#### Rust

```rust
use darkstrata_credential_check::{crypto_utils::hash_credential, ClientOptions, DarkStrataCredentialCheck};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = DarkStrataCredentialCheck::new(
        ClientOptions::new("your-api-key")
    )?;

    // email and password come from your login form and are only ever used here.
    // 1. Hash the credential locally: SHA-256 of "email:password".
    //    The plaintext email and password never leave this process.
    let hash = hash_credential(&email, &password);

    // 2. Check the hash. The SDK sends only the first 5-6 characters (the
    //    k-anonymity prefix) to the API and compares the full hash locally.
    let result = client.check_hash(&hash, None).await?;

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

// email and password come from your login form and are only ever used here.
// 1. Hash the credential locally: SHA-256 of "email:password".
//    The plaintext email and password never leave this process.
var hash = CryptoUtils.HashCredential(email, password);

// 2. Check the hash. The SDK sends only the first 5-6 characters (the
//    k-anonymity prefix) to the API and compares the full hash locally.
var result = await client.CheckHashAsync(hash);

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

    credentialcheck "github.com/darkstrata/darkstrata-sdks/sdks/go"
)

func main() {
    client, err := credentialcheck.NewClient(credentialcheck.ClientOptions{
        APIKey: "your-api-key",
    })
    if err != nil {
        log.Fatal(err)
    }

    // email and password come from your login form and are only ever used here.
    // 1. Hash the credential locally: SHA-256 of "email:password".
    //    The plaintext email and password never leave this process.
    hash := credentialcheck.HashCredential(email, password)

    // 2. Check the hash. The SDK sends only the first 5-6 characters (the
    //    k-anonymity prefix) to the API and compares the full hash locally.
    result, err := client.CheckHash(context.Background(), hash, nil)
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
            // email and password come from your login form and are only ever used here.
            // 1. Hash the credential locally: SHA-256 of "email:password".
            //    The plaintext email and password never leave this process.
            String hash = CryptoUtils.hashCredential(email, password);

            // 2. Check the hash. The SDK sends only the first 5-6 characters (the
            //    k-anonymity prefix) to the API and compares the full hash locally.
            CheckResult result = client.checkHash(hash);

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
    │  Send prefix: "5BAA6" (or "5BAA61") ─→│
    │                                    │
    │  ←────── All hashes with prefix    │
    │                                    │
    │  Check if your hash is in set      │
    │  Result: found or not found        │
    │                                    │
```

Only **5 or 6 characters** of a 64-character hash are sent. This provides:
- 1-in-1,000,000 anonymity set (5 chars) or 1-in-16,000,000 (6 chars)
- Using 6 characters returns ~16x fewer results for faster responses
- Your actual credentials are never transmitted
- Even if intercepted, the prefix reveals nothing

---

## Integrations

### Splunk Technology Add-on

Ingest DarkStrata threat intelligence into Splunk Enterprise Security. The Technology Add-on (TA) provides modular inputs for credential exposure alerts and indicators, enabling real-time monitoring of compromised credentials affecting your organisation.

| | |
|---|---|
| **Splunkbase** | [DarkStrata Threat Intelligence Add-on for Splunk](https://splunkbase.splunk.com/app/8955) |
| **Compatibility** | Splunk Enterprise 9.0+, Splunk Cloud, ES 7.0+ (optional) |
| **Data Models** | CIM-compliant: Authentication, Threat Intelligence |
| **Formats** | Native STIX 2.1 ingestion |
| **Documentation** | [Full Splunk TA guide](./integrations/splunk-ta/README.md) |

#### Key Capabilities

- **STIX 2.1 ingestion** with incremental checkpoint-based sync
- **CIM-compliant** field mappings for Authentication and Threat Intelligence data models
- **Enterprise Security integration** with pre-built correlation searches, threat intel lookups, and risk scoring
- **Adaptive Response actions** to acknowledge, close, and reopen alerts directly from Splunk
- **SOAR playbooks** for Splunk SOAR, XSOAR, Swimlane, and generic REST platforms
- **Privacy controls** with optional SHA-256 email hashing

#### Quick Install

1. Install from [Splunkbase](https://splunkbase.splunk.com/app/8955), or download the latest release from [GitHub Releases](https://github.com/darkstrata/darkstrata-sdks/releases?q=splunk-ta)
2. Install via **Apps** > **Manage Apps** > **Install app from file**, or extract to `$SPLUNK_HOME/etc/apps/`
3. Navigate to the **DarkStrata Technology Add-on** and configure your account:
   - **API Base URL**: `https://api.darkstrata.io/v1`
   - **API Key**: Your DarkStrata API key with `siem:read` scope
4. Create inputs for **Indicators** and/or **Alerts** under the **Inputs** tab

> For full installation, configuration, ES integration, performance tuning, and troubleshooting, see the [Splunk TA README](./integrations/splunk-ta/README.md).

---

### Umbraco CMS Package

Block compromised passwords for Umbraco members and backoffice users, check backoffice logins, and receive DarkStrata alert webhooks as Umbraco notifications. Built on the .NET SDK, so every check uses k-anonymity.

| | |
|---|---|
| **NuGet** | [DarkStrata.CredentialCheck.Umbraco](https://www.nuget.org/packages/DarkStrata.CredentialCheck.Umbraco) |
| **Compatibility** | Umbraco 13 LTS (.NET 8), Umbraco 15 and 16 (.NET 9) |
| **Documentation** | [Umbraco package guide](./sdks/csharp/src/DarkStrata.CredentialCheck.Umbraco/README.md) |

```bash
dotnet add package DarkStrata.CredentialCheck.Umbraco
```

## Getting Started

1. **Get an API key** from your [DarkStrata dashboard](https://app.darkstrata.io)
2. **Install an SDK** for your language (see [Available SDKs](#available-sdks)) or deploy the [Splunk TA](#splunk-technology-add-on)
3. **Start checking credentials** or monitoring threat intelligence

---

## Documentation

### SDKs

- [Node.js SDK Documentation](./sdks/node/README.md)
- [Python SDK Documentation](./sdks/python/README.md)
- [Rust SDK Documentation](./sdks/rust/README.md)
- [C# SDK Documentation](./sdks/csharp/README.md)
- [Go SDK Documentation](./sdks/go/README.md)
- [Java SDK Documentation](./sdks/java/README.md)

### Integrations

- [Splunk Technology Add-on Documentation](./integrations/splunk-ta/README.md)
- [Umbraco CMS Package Documentation](./sdks/csharp/src/DarkStrata.CredentialCheck.Umbraco/README.md)

### General

- [API Documentation](https://docs.darkstrata.io)
- [DarkStrata Dashboard](https://app.darkstrata.io)

---

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## Security

If you discover a security vulnerability, please email security@darkstrata.io instead of using the issue tracker.

## Licence

Apache 2.0 © [DarkStrata Ltd](https://darkstrata.io)
