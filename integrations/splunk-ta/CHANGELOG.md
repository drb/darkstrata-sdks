# Changelog

All notable changes to the DarkStrata Threat Intelligence Add-on for Splunk will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- DarkStrata Ghost Events modular input (`darkstrata_ghost_events`). It reads
  ghost (honeytoken) events from the `/ghosts/events` JSON feed with its
  cursor, saving each event's `seq` so every event is indexed once across
  restarts. Sourcetype `darkstrata:ghost:event`, `_time` from `received_at`
  (falling back to `observed_at`). Options: include test events (off by
  default) and a minimum severity. Needs the `ghost:read` API key permission;
  a 403 is logged as such.
- CIM Intrusion Detection mapping for `ghost.seen` events (eventtype
  `darkstrata_ghost_seen`, tags `ids` and `attack`; test events excluded), with
  `signature`, `severity`, `user`, `dest`, `category`, `vendor_product` and
  per-event MITRE ATT&CK fields.
- Correlation searches **DarkStrata - Ghost Seen** (severity, risk score and
  ATT&CK techniques from the event; annotated T1589.001 and T1589.002) and
  **DarkStrata - Ghost Retired** (medium tamper alarm; annotated T1562).
- Correlation search **DarkStrata - Ghost Proof of Life Missing** (daily; one
  medium notable per ghost, at most weekly, when a ghost that is not retired
  has had no monthly `ghost.verified` for 33 days; annotated T1562).
- Disabled template searches for DC-side honey accounts: **DarkStrata - Honey
  SPN Kerberos Service Ticket** (4769, T1558.003) and **DarkStrata - Honey
  Account AS-REP Roasting** (4768 without pre-authentication, T1558.004), with
  the `darkstrata_honey_accounts` lookup and the `darkstrata_windows_security`
  macro for customers to fill in.

## [1.2.0] - 2026-10-19

### Added

- MITRE ATT&CK annotations on the four Enterprise Security correlation searches
  (`action.correlationsearch.annotations`): Malware Credential Detected and
  Potential Malware Campaign carry T1555.003 and T1589.001; Third Party
  Credential Exposure and Critical Credential Exposure carry T1589.001.
- Per-event ATT&CK techniques. The DarkStrata API labels each credential
  exposure with `mitre:<technique id>`; the add-on extracts these into the
  multivalue fields `mitre_technique_id`, `mitre_technique` and
  `annotations.mitre_attack` on `darkstrata:stix:observed-data` and
  `darkstrata:stix:alert` (deduplicated across the bundle). The correlation
  searches pass them through to notable events.

### Fixed

- `app.manifest` `platformRequirements.splunk.Enterprise` is `*` again. The
  `>=9.0` floor set in 1.1.2 has no match in SLIM 1.2.8's version list, so
  `slim validate` (and CI) failed on every build since. The Splunk 9.0 minimum
  is still documented in the README and the Splunkbase listing.
- `darkstrata:stix:alert` read `alert_name`, `alert_description` and
  `alert_severity` from the second bundle object; the report is the first
  (`objects{0}`).
- `source_type` and `flow_direction` on `darkstrata:stix:observed-data` always
  evaluated to `unknown` because they read `labels` instead of the
  JSON-extracted `labels{}`.
- `user`, `user_type`, `dest`, `threat_key`, `threat_match_value` and
  `signature` on `darkstrata:stix:observed-data` read a non-existent `objects`
  field; they now read `objects.0.*` / `objects.1.*` from the raw event.
- Reconciled the `pyproject.toml` version with the rest of the add-on.

## [1.1.2] - 2026-07-31

### Fixed

- Resolved the Splunkbase AppInspect `check_for_custom_mako_templates` finding
  against 1.1.1. The add-on is now built with UCC framework 6.5.3 (1.1.1 was
  built with 5.52.0), whose `appserver/templates/base.html` is plain HTML rather
  than a Mako template, per Splunk's remediation guidance for the Splunk
  Enterprise 10.4 Mako deprecation. The build floor is raised to
  `splunk-add-on-ucc-framework>=6.3.0` so a Mako-era build cannot recur.

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

[Unreleased]: https://github.com/darkstrata/darkstrata-sdks/compare/splunk-ta-v1.2.0...HEAD
[1.2.0]: https://github.com/darkstrata/darkstrata-sdks/compare/splunk-ta-v1.1.2...splunk-ta-v1.2.0
[1.1.2]: https://github.com/darkstrata/darkstrata-sdks/compare/splunk-ta-v1.1.1...splunk-ta-v1.1.2
[1.1.1]: https://github.com/darkstrata/darkstrata-sdks/compare/splunk-ta-v1.1.0...splunk-ta-v1.1.1
[1.1.0]: https://github.com/darkstrata/darkstrata-sdks/compare/splunk-ta-v1.0.0...splunk-ta-v1.1.0
[1.0.0]: https://github.com/darkstrata/darkstrata-sdks/releases/tag/splunk-ta-v1.0.0
