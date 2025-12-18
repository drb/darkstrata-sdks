# Contributing to DarkStrata SDKs

Thank you for your interest in contributing to the DarkStrata SDKs!

## Building SDKs for Other Languages

We welcome community contributions for SDKs in languages we don't currently support. If you'd like to build an SDK for a new language (Python, Go, Ruby, PHP, etc.), here's how to get started:

### Getting Started

1. **Fork the repository** and create a new directory for your language (e.g., `/python/`, `/go/`)

2. **Study the existing Node.js implementation** in `/node/` to understand:
   - The k-anonymity protocol flow
   - API endpoints and parameters
   - Error handling patterns
   - Type definitions

3. **Review the API documentation** at [docs.darkstrata.io](https://docs.darkstrata.io)

### SDK Requirements

Your SDK should implement:

1. **Core functionality**:
   - `check(email, password)` - Check a single credential
   - `checkHash(hash)` - Check a pre-computed hash
   - `checkBatch(credentials)` - Batch checking (optional but recommended)

2. **Protocol implementation**:
   - SHA-256 hashing of credentials (`email:password`)
   - Extract 5-character prefix for k-anonymity
   - HMAC-SHA256 for result verification
   - Timing-safe comparison to prevent timing attacks

3. **Optional features**:
   - `clientHmac` - Client-provided HMAC key support
   - `since` - Date filtering support
   - Response caching aligned with server time windows

4. **Error handling**:
   - Authentication errors (401)
   - Validation errors
   - Rate limiting (429)
   - Network errors with retry logic

### Code Quality Standards

- Full test coverage with unit and integration tests
- Comprehensive documentation with examples
- Type safety (where the language supports it)
- Follow the language's idiomatic conventions
- No unnecessary dependencies

### Directory Structure

```
your-language/
├── src/              # Source code
├── tests/            # Test files
├── examples/         # Usage examples
├── README.md         # Language-specific documentation
├── CHANGELOG.md      # Version history
└── [package config]  # Language-specific package configuration
```

### Submitting Your SDK

1. Ensure all tests pass
2. Include comprehensive documentation
3. Add examples demonstrating common use cases
4. Open a pull request with:
   - Description of the SDK
   - Test coverage report
   - Any language-specific considerations

## Contributing to Existing SDKs

### Bug Fixes

1. Open an issue describing the bug
2. Fork the repository and create a branch
3. Write a failing test that reproduces the bug
4. Fix the bug
5. Ensure all tests pass
6. Open a pull request

### New Features

1. Open an issue to discuss the feature
2. Wait for approval before starting work
3. Implement with tests and documentation
4. Open a pull request

### Code Style

- Follow the existing code style in each SDK
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and small

## Questions?

If you have questions about contributing, please open an issue or contact us at support@darkstrata.io.

## Licence

By contributing to this project, you agree that your contributions will be licensed under the Apache 2.0 licence.
