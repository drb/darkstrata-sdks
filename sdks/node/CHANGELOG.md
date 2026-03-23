# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2025-12-18

### Fixed

- Republished with correct npm credentials

## [0.1.0] - 2025-12-18 [YANKED]

### Added

- Initial release
- `DarkStrataCredentialCheck` client class
- `check()` method for single credential checks
- `checkHash()` method for pre-hashed credentials
- `checkBatch()` method for batch processing
- K-anonymity implementation for privacy-preserving checks
- Automatic caching aligned with server time windows
- Retry logic with exponential backoff
- Comprehensive TypeScript types
- Full documentation and examples

### Security

- Uses timing-safe comparison to prevent timing attacks
- Only 5-character hash prefixes are transmitted to the API
- Credentials are never logged or included in error messages
