# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-20

### Added

- Initial release
- `NewClient` - Create a new DarkStrata credential check client
- `Check` - Check a single email/password credential
- `CheckHash` - Check a pre-computed SHA-256 hash
- `CheckBatch` - Efficiently check multiple credentials with automatic prefix grouping
- `ClearCache` / `GetCacheSize` - Cache management
- Comprehensive error types: `AuthenticationError`, `ValidationError`, `APIError`, `TimeoutError`, `NetworkError`, `RateLimitError`
- Cryptographic utilities: `HashCredential`, `SHA256`, `HMACSHA256`, `ExtractPrefix`, `IsValidHash`, `IsValidPrefix`
- Automatic retry with exponential backoff
- In-memory response caching with TTL and time-window awareness
- Full context support for cancellation and timeouts
- Zero external dependencies (uses only Go standard library)
