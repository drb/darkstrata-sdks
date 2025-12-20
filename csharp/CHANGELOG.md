# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2024-12-20

### Added

- Initial release of the C# SDK
- `DarkStrataCredentialCheck` client for checking credentials
- `CheckAsync` method for single credential checks
- `CheckHashAsync` method for pre-computed hash checks
- `CheckBatchAsync` method for batch processing with prefix grouping
- Built-in caching with time window alignment
- Automatic retry with exponential backoff
- Comprehensive exception hierarchy
- Full async/await support with cancellation tokens
- Examples for basic usage, batch processing, and error handling
