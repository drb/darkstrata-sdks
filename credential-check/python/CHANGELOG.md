# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-12-18

### Added

- Initial release
- `DarkStrataCredentialCheck` client class
- `check()` method for single credential checks
- `check_hash()` method for pre-hashed credentials
- `check_batch()` method for batch processing
- K-anonymity implementation for privacy-preserving checks
- Automatic caching aligned with server time windows
- Retry logic with exponential backoff
- Full type hints and py.typed marker
- Async support via httpx

### Security

- Uses timing-safe comparison to prevent timing attacks
- Only 5-character hash prefixes are transmitted to the API
- Credentials are never logged or included in error messages
