# Changelog

All notable changes to the DarkStrata Technology Add-on for Splunk will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2024-XX-XX

### Added

- **Adaptive Response Actions** for ES integration
  - Acknowledge Alert action
  - Close Alert action
  - Reopen Alert action
  - Get Alert Details enrichment action
- **SOAR Integration** support
  - Sample Splunk SOAR playbooks (credential_exposure_triage, auto_acknowledge, alert_enrichment)
  - SOAR platform integration documentation
  - REST API reference for custom integrations
- **Performance Tuning** configuration
  - Configurable batch size (10-500)
  - Request timeout settings
  - Rate limiting controls
  - Connection pooling options
  - Max concurrent connections setting

### Changed

- Updated README with comprehensive Phase 3 documentation
- Enhanced globalConfig.json with Performance settings tab

## [1.0.0] - 2024-XX-XX

### Added

- Initial release of DarkStrata Technology Add-on for Splunk
- Modular input for `/stix/indicators` endpoint
- Modular input for `/stix/alerts` endpoint
- Checkpoint-based incremental sync
- CIM field mappings for Authentication and Threat_Intelligence data models
- Enterprise Security threat intel KV store collections
- Pre-built correlation searches for notable events
- Reusable search macros
- Event types and tags for filtering
- Proxy support with authentication
- Email hashing for privacy compliance
- Confidence threshold filtering
- API key validation on save
- Comprehensive documentation

### Security

- API keys stored encrypted using Splunk credential storage
- Proxy passwords encrypted
- No secrets committed to package

[Unreleased]: https://github.com/darkstrata/darkstrata-sdks/compare/splunk-ta-v1.0.0...HEAD
[1.0.0]: https://github.com/darkstrata/darkstrata-sdks/releases/tag/splunk-ta-v1.0.0
