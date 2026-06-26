# Changelog

All notable changes to the DarkStrata Threat Intelligence Add-on for Splunk will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.1] - 2026-06-26

### Added

- App icons (`appIcon`/`appIconAlt`, 36×36 and 72×72) for the Splunk launcher and
  Splunkbase listing, and a valid alert-action `icon_path` (the previous reference
  pointed at a file that did not exist).

### Security

- Adaptive response actions now verify TLS server certificates and enforce a
  TLS 1.2 minimum (previously certificate verification was disabled), matching
  the modular inputs' secure transport posture.

### Changed

- Declared `python.required = 3.9,3.13` on the modular inputs, REST handlers and
  adaptive-response actions for Splunk Enterprise 10.2+ forward compatibility
  (the deprecated `python.version` is retained for older Splunk releases).
- Renamed the add-on to **DarkStrata Threat Intelligence Add-on for Splunk**
  across `app.manifest`, the `app.conf` label, and the `globalConfig` display
  name to follow Splunkbase naming conventions.

### Fixed

- Bundled the Apache-2.0 `LICENSE` file referenced by `app.manifest` so the
  package passes AppInspect and Splunkbase validation.
- Reconciled the add-on version across `app.manifest`, `app.conf`,
  `globalConfig.json`, `package.json`, `pyproject.toml`, and the request
  `User-Agent` strings (build metadata removed for a clean semantic version).
- Fixed `app.manifest` so it passes SLIM validation (Splunkbase's Splunk
  Enterprise vetting): valid CIM version spec for Authentication, removed the
  unrecognised Threat_Intelligence CIM entry, a supported platform version
  range, and release notes referenced by URL. CI and the release workflow now
  gate on `slim validate`.

## [1.1.0] - 2026-02-05

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

- Updated README with comprehensive documentation
- Enhanced globalConfig.json with Performance settings tab

## [1.0.0] - 2026-02-05

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

[Unreleased]: https://github.com/darkstrata/darkstrata-sdks/compare/splunk-ta-v1.1.1...HEAD
[1.1.1]: https://github.com/darkstrata/darkstrata-sdks/compare/splunk-ta-v1.1.0...splunk-ta-v1.1.1
[1.1.0]: https://github.com/darkstrata/darkstrata-sdks/compare/splunk-ta-v1.0.0...splunk-ta-v1.1.0
[1.0.0]: https://github.com/darkstrata/darkstrata-sdks/releases/tag/splunk-ta-v1.0.0
