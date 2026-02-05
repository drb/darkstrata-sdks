# DarkStrata Technology Add-on for Splunk

Ingest DarkStrata threat intelligence into Splunk Enterprise Security. This Technology Add-on (TA) provides modular inputs for credential exposure alerts and indicators, enabling real-time monitoring of compromised credentials affecting your organisation.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Getting Your API Key](#getting-your-api-key)
- [Configuration](#configuration)
- [Input Parameters Reference](#input-parameters-reference)
- [Data Format](#data-format)
- [Event Types and Tags](#event-types-and-tags)
- [CIM Field Mappings](#cim-field-mappings)
- [Enterprise Security Integration](#enterprise-security-integration)
- [Adaptive Response Actions](#adaptive-response-actions)
- [SOAR Integration](#soar-integration)
- [Performance Tuning](#performance-tuning)
- [Search Macros Reference](#search-macros-reference)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Upgrading](#upgrading)
- [Development](#development)
- [Support](#support)

---

## Overview

The DarkStrata Technology Add-on for Splunk enables security teams to:

- **Detect compromised credentials** before they're used maliciously
- **Identify malware infections** through infostealer credential detection
- **Monitor third-party risk** by tracking corporate credentials on external sites
- **Automate incident response** via ES notable events and correlation searches
- **Enrich threat hunting** with credential exposure context

### Key Features

| Feature | Description |
|---------|-------------|
| **STIX 2.1 Ingestion** | Native support for STIX observed-data and indicator formats |
| **Incremental Sync** | Checkpoint-based collection fetches only new data |
| **CIM Compliance** | Maps to Authentication and Threat_Intelligence data models |
| **ES Integration** | Pre-built correlation searches and threat intel lookups |
| **Adaptive Response** | Alert actions for acknowledge, close, reopen alerts in DarkStrata |
| **SOAR Integration** | Sample playbooks for Splunk SOAR and other platforms |
| **Privacy Controls** | Optional SHA-256 email hashing for compliance |
| **Confidence Filtering** | Filter by STIX confidence score (maps to threat severity) |
| **Performance Tuning** | Configurable batch size, rate limiting, connection pooling |
| **Connection Validation** | API credentials tested on save |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         DarkStrata Cloud                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │ Breach Database │  │ Malware Intel   │  │ Threat Scoring  │         │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │
│           └────────────────────┼────────────────────┘                   │
│                                ▼                                         │
│                    ┌───────────────────────┐                            │
│                    │   STIX 2.1 API        │                            │
│                    │  /stix/indicators     │                            │
│                    │  /stix/alerts         │                            │
│                    └───────────┬───────────┘                            │
└────────────────────────────────┼────────────────────────────────────────┘
                                 │ HTTPS (Bearer Auth)
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Splunk Enterprise                                   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                  TA-DarkStrata                                   │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────┐  │   │
│  │  │ Indicators      │  │ Alerts Input    │  │ Checkpoints    │  │   │
│  │  │ Modular Input   │  │ Modular Input   │  │ (KV Store)     │  │   │
│  │  └────────┬────────┘  └────────┬────────┘  └────────────────┘  │   │
│  └───────────┼────────────────────┼─────────────────────────────────┘   │
│              ▼                    ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     Splunk Indexes                               │   │
│  │  sourcetype=darkstrata:stix:observed-data                       │   │
│  │  sourcetype=darkstrata:stix:alert                               │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│              │                                                          │
│              ▼                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │              Splunk Enterprise Security                          │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────┐  │   │
│  │  │ Threat Intel    │  │ Correlation     │  │ Notable        │  │   │
│  │  │ Framework       │  │ Searches        │  │ Events         │  │   │
│  │  │ (KV Stores)     │  │                 │  │                │  │   │
│  │  └─────────────────┘  └─────────────────┘  └────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Requirements

### Splunk Platform

| Component | Minimum Version | Recommended |
|-----------|-----------------|-------------|
| Splunk Enterprise | 8.2.0 | 9.0+ |
| Splunk Cloud | Victoria Experience | Latest |
| Splunk Enterprise Security | 7.0.0 (optional) | 7.3+ |

### DarkStrata Account

- Active DarkStrata subscription (any tier)
- API key with `siem:read` permission scope
- Network access to `api.darkstrata.io` (HTTPS/443)

### System Requirements

- Python 3.9+ (included with Splunk 8.2+)
- Outbound HTTPS connectivity to DarkStrata API
- Sufficient index storage for credential exposure events

---

## Installation

### Option 1: Splunkbase (Recommended)

1. Log in to Splunk Web as an administrator
2. Navigate to **Apps** > **Find More Apps**
3. Search for "DarkStrata"
4. Click **Install**
5. Enter your Splunk.com credentials if prompted
6. Restart Splunk when prompted

### Option 2: Manual Installation

1. Download the latest release from [GitHub Releases](https://github.com/drb/darkstrata-sdks/releases?q=splunk-ta)
   ```
   TA-darkstrata-x.x.x.tar.gz
   ```

2. Install via Splunk Web:
   - Navigate to **Apps** > **Manage Apps** > **Install app from file**
   - Upload the `.tar.gz` file
   - Restart Splunk if prompted

3. Or install via CLI:
   ```bash
   # Extract to apps directory
   tar -xzf TA-darkstrata-x.x.x.tar.gz -C $SPLUNK_HOME/etc/apps/

   # Restart Splunk
   $SPLUNK_HOME/bin/splunk restart
   ```

### Option 3: Splunk Cloud

For Splunk Cloud deployments:

1. Download the Splunk TA package from [GitHub Releases](https://github.com/drb/darkstrata-sdks/releases?q=splunk-ta)
2. Submit to Splunk Cloud via the **Install App** feature
3. Wait for Splunk Cloud Operations to approve and deploy

> **Note**: The TA passes AppInspect cloud certification checks.

---

## Getting Your API Key

1. Log in to your DarkStrata dashboard at [app.darkstrata.io](https://app.darkstrata.io)

2. Navigate to **Settings** > **API Keys**

3. Click **Create API Key**

4. Configure the key:
   - **Name**: `splunk-integration` (or descriptive name)
   - **Permissions**: Select `siem:read` scope
   - **Expiry**: Set according to your security policy

5. Copy the generated API key (it won't be shown again)

### Required Permissions

| Scope | Description | Required |
|-------|-------------|----------|
| `siem:read` | Read STIX indicators and alerts | Yes |
| `data:read` | Read raw credential data | No (optional) |

---

## Configuration

### Step 1: Configure Account

The account stores your DarkStrata API credentials securely.

1. Navigate to **Apps** > **DarkStrata Technology Add-on**
2. Click **Configuration** tab
3. Select **Account** > **Add**
4. Enter:

| Field | Description | Example |
|-------|-------------|---------|
| **Account Name** | Unique identifier (alphanumeric + underscore) | `production` |
| **API Base URL** | DarkStrata API endpoint | `https://api.darkstrata.io/v1` |
| **API Key** | Your DarkStrata API key | `ds_live_xxxx...` |

5. Click **Add** - the connection will be validated automatically

### Step 2: Configure Inputs

#### Indicators Input

Collects individual compromised credential indicators from `/stix/indicators`.

1. Navigate to **Inputs** tab
2. Click **Create New Input** > **DarkStrata Indicators**
3. Configure:

| Field | Description | Recommended |
|-------|-------------|-------------|
| **Name** | Unique input name | `darkstrata_indicators` |
| **Interval** | Collection frequency (seconds) | `300` (5 min) |
| **Index** | Target Splunk index | `threat_intel` |
| **Account** | Select configured account | - |
| **Confidence Threshold** | Minimum STIX confidence (0-100) | `0` (all) |
| **Hash Emails** | SHA-256 hash emails for privacy | Disabled |

#### Alerts Input

Collects credential exposure alert bundles from `/stix/alerts`.

1. Navigate to **Inputs** tab
2. Click **Create New Input** > **DarkStrata Alerts**
3. Configure:

| Field | Description | Recommended |
|-------|-------------|-------------|
| **Name** | Unique input name | `darkstrata_alerts` |
| **Interval** | Collection frequency (seconds) | `300` (5 min) |
| **Index** | Target Splunk index | `threat_intel` |
| **Account** | Select configured account | - |
| **Detail Level** | Report detail (`summary` or `full`) | `full` |
| **Include Identities** | Include STIX Identity objects | Enabled |
| **Confidence Threshold** | Minimum STIX confidence (0-100) | `0` (all) |
| **Hash Emails** | SHA-256 hash emails for privacy | Disabled |

### Step 3: Configure Proxy (Optional)

If your Splunk instance requires a proxy for outbound connections:

1. Navigate to **Configuration** > **Proxy**
2. Configure:

| Field | Description |
|-------|-------------|
| **Enable Proxy** | Toggle on |
| **Proxy Type** | `HTTP` or `SOCKS5` |
| **Proxy Host** | Proxy server hostname |
| **Proxy Port** | Proxy server port |
| **Proxy Username** | (Optional) Authentication username |
| **Proxy Password** | (Optional) Authentication password |

### Step 4: Configure Logging

1. Navigate to **Configuration** > **Logging**
2. Set **Log Level**:
   - `INFO` - Normal operation (recommended)
   - `DEBUG` - Troubleshooting (verbose)
   - `WARNING` - Only warnings and errors
   - `ERROR` - Only errors

---

## Input Parameters Reference

### Indicators Input Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | string | (required) | Unique input identifier |
| `interval` | integer | `300` | Collection interval in seconds |
| `index` | string | `default` | Target Splunk index |
| `account` | string | (required) | Account configuration to use |
| `confidence_threshold` | integer | `0` | Minimum STIX confidence (0-100) |
| `hash_emails` | boolean | `false` | SHA-256 hash email addresses |

### Alerts Input Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | string | (required) | Unique input identifier |
| `interval` | integer | `300` | Collection interval in seconds |
| `index` | string | `default` | Target Splunk index |
| `account` | string | (required) | Account configuration to use |
| `detail` | string | `full` | Report detail level (`summary`/`full`) |
| `include_identities` | boolean | `true` | Include STIX Identity objects |
| `confidence_threshold` | integer | `0` | Minimum STIX confidence (0-100) |
| `hash_emails` | boolean | `false` | SHA-256 hash email addresses |

### Confidence Threshold Mapping

The confidence threshold maps to DarkStrata threat scores:

| STIX Confidence | DarkStrata Score | Severity | Description |
|-----------------|------------------|----------|-------------|
| 0-19 | 1 | Info | Low-risk exposure, possibly old |
| 20-39 | 2 | Low | Needs review, limited context |
| 40-59 | 3 | Medium | Confirmed exposure, moderate risk |
| 60-79 | 4 | High | Recent exposure, high risk |
| 80-100 | 5 | Critical | Active threat, immediate action |

---

## Data Format

### Sourcetypes

| Sourcetype | Description | Volume |
|------------|-------------|--------|
| `darkstrata:stix:observed-data` | Individual credential indicators | High |
| `darkstrata:stix:alert` | Alert bundles (report + indicators) | Low |

### Sample Event: observed-data

```json
{
  "type": "observed-data",
  "id": "observed-data--abc123",
  "created": "2024-01-15T10:00:00.000Z",
  "modified": "2024-01-15T10:00:00.000Z",
  "first_observed": "2024-01-14T08:00:00.000Z",
  "last_observed": "2024-01-15T10:00:00.000Z",
  "number_observed": 1,
  "objects": {
    "0": {
      "type": "user-account",
      "account_login": "user@example.com",
      "account_type": "email"
    },
    "1": {
      "type": "domain-name",
      "value": "slack.com"
    }
  },
  "labels": [
    "darkstrata",
    "credential-exposure",
    "source:malware",
    "flow:outbound",
    "severity-high"
  ]
}
```

### Key Fields

| JSON Path | Field | Description |
|-----------|-------|-------------|
| `objects.0.account_login` | `user` | Compromised email or username |
| `objects.0.account_type` | `user_type` | `email` or `username` |
| `objects.1.value` | `dest` | Service domain where credentials exposed |
| `labels[]` | `labels` | Metadata tags (source, flow, severity) |
| `created` | `_time` | Event timestamp |

### Labels Reference

| Label Pattern | Values | Description |
|---------------|--------|-------------|
| `source:*` | `malware`, `breach` | Credential source |
| `flow:*` | `inbound`, `outbound` | Exposure direction |
| `severity-*` | `info`, `low`, `medium`, `high`, `critical` | Risk level |

---

## Event Types and Tags

### Event Types

```spl
# All DarkStrata events
eventtype=darkstrata_events

# Individual credential indicators
eventtype=darkstrata_credential_exposure

# Alert bundles
eventtype=darkstrata_alerts

# Inbound exposures (your domain in breach)
eventtype=darkstrata_inbound_exposure

# Outbound exposures (credentials on third-party sites)
eventtype=darkstrata_outbound_exposure

# Malware-sourced (infostealers, keyloggers)
eventtype=darkstrata_malware_credentials

# Breach-sourced (data leaks)
eventtype=darkstrata_breach_credentials

# Critical/high severity only
eventtype=darkstrata_critical_exposure

# For CIM Authentication mapping
eventtype=darkstrata_authentication
```

### CIM Tags

| Event Type | Tags |
|------------|------|
| `darkstrata_credential_exposure` | `threat`, `threatintel` |
| `darkstrata_alerts` | `threat`, `alert` |
| `darkstrata_authentication` | `authentication` |
| `darkstrata_inbound_exposure` | `identity`, `change` |
| `darkstrata_outbound_exposure` | `web` |
| `darkstrata_malware_credentials` | `malware`, `attack` |
| `darkstrata_critical_exposure` | `alert`, `notable` |

---

## CIM Field Mappings

### Threat Intelligence Data Model

| CIM Field | Extraction | Description |
|-----------|------------|-------------|
| `threat_key` | `objects.0.account_login` | Compromised identity |
| `threat_match_value` | `objects.1.value` | Associated domain |
| `threat_match_type` | `observed-data` | STIX object type |

### Authentication Data Model

| CIM Field | Extraction | Description |
|-----------|------------|-------------|
| `user` | `objects.0.account_login` | Compromised user |
| `dest` | `objects.1.value` | Target service |
| `action` | `success` | Credential was compromised |
| `app` | `darkstrata` | Source application |
| `authentication_method` | `compromised_credential` | Auth type |
| `signature` | Auto-generated | Human-readable description |

---

## Enterprise Security Integration

### Overview

The add-on integrates with Splunk Enterprise Security through:

1. **Threat Intel Framework** - Populates KV store lookups
2. **Correlation Searches** - Creates notable events
3. **Risk Scoring** - Assigns risk to users
4. **CIM Compliance** - Works with ES data models

### Threat Intel Lookups

The add-on includes saved searches that populate threat intel KV stores every 15 minutes:

| Lookup | Key Field | Use Case |
|--------|-----------|----------|
| `darkstrata_email_intel` | `email` | Match compromised emails |
| `darkstrata_domain_intel` | `domain` | Match compromised domains |
| `darkstrata_user_intel` | `user` | Match compromised users |

#### Lookup Fields

**darkstrata_email_intel**:
```
email, description, threat_key, weight, first_seen, last_seen, source_type, flow_direction
```

**darkstrata_domain_intel**:
```
domain, description, threat_key, weight, first_seen, last_seen
```

**darkstrata_user_intel**:
```
user, description, threat_key, weight, first_seen, last_seen, email
```

### Pre-built Correlation Searches

| Search Name | Triggers On | Severity | Risk Score |
|-------------|-------------|----------|------------|
| **DarkStrata - Critical Credential Exposure Detected** | High/critical exposures | High | 80 |
| **DarkStrata - Malware Credential Detected** | Malware-sourced creds | Critical | 100 |
| **DarkStrata - Third Party Credential Exposure** | Outbound flow | Medium | 50 |
| **DarkStrata - Potential Malware Campaign** | 3+ users from malware | High | 90 |
| **DarkStrata - New Alert Received** | New alert bundles | Info | - |

### Enabling Correlation Searches

1. Navigate to **Enterprise Security** > **Configure** > **Content** > **Content Management**
2. Filter by **App**: `TA-darkstrata`
3. Enable desired correlation searches
4. Configure notification actions as needed

### Enabling Threat Intel Lookups

1. Navigate to **Enterprise Security** > **Configure** > **Data Enrichment** > **Threat Intelligence Management**
2. Add a new threat intel source:
   - **Name**: DarkStrata Email Intel
   - **Type**: Local lookup
   - **Lookup**: `darkstrata_email_intel`
3. Repeat for domain and user intel lookups

### Risk-Based Alerting

The correlation searches assign risk scores to users:

| Exposure Type | Risk Score | Risk Object |
|---------------|------------|-------------|
| Malware-sourced credential | 100 | user |
| Critical severity exposure | 80 | user |
| High severity exposure | 80 | user |
| Third-party exposure | 50 | user |

---

## Adaptive Response Actions

The TA includes Adaptive Response actions for automated incident response workflows in Splunk ES.

### Available Actions

| Action | Description | Use Case |
|--------|-------------|----------|
| **DarkStrata: Acknowledge Alert** | Mark an alert as under investigation | Initial triage response |
| **DarkStrata: Close Alert** | Close an alert after investigation | Mark resolved cases |
| **DarkStrata: Reopen Alert** | Reopen a previously closed alert | Re-investigate if needed |
| **DarkStrata: Get Alert Details** | Retrieve full alert information | Enrichment action |

### Configuring Alert Actions

1. Navigate to **Settings** > **Alert Actions**
2. Click on the DarkStrata action you want to configure
3. Select the **Account** to use for API calls
4. Set the **Alert ID** field:
   - Use `$result.alert_id$` to extract from notable events
   - Or specify a static alert ID

### Using in Correlation Searches

Add adaptive response to correlation searches:

```
[savedsearches/DarkStrata - Malware Credential Detected]
# ... existing settings ...
action.darkstrata_acknowledge_alert = 1
action.darkstrata_acknowledge_alert.param.account = your_account_name
action.darkstrata_acknowledge_alert.param.alert_id = $result.alert_id$
```

### Using in Notable Event Response

1. Open a notable event in ES Incident Review
2. Click **Run Adaptive Response Action**
3. Select the DarkStrata action
4. Configure parameters
5. Execute the action

### Action Workflow Example

```
   Notable Event Created
          │
          ▼
   ┌──────────────────┐
   │ Analyst Reviews  │
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │ Acknowledge      │ ◄─── DarkStrata: Acknowledge Alert
   │ Alert            │
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │ Investigate &    │ ◄─── DarkStrata: Get Alert Details
   │ Enrich           │
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │ Close Alert      │ ◄─── DarkStrata: Close Alert
   └──────────────────┘
```

---

## SOAR Integration

The TA includes sample playbooks and documentation for integrating with SOAR platforms.

### Supported Platforms

- **Splunk SOAR (Phantom)** - Python playbooks included
- **XSOAR (Demisto)** - HTTP integration guide
- **Swimlane** - REST API connector documentation
- **Generic REST** - Any platform supporting REST APIs

### Splunk SOAR Setup

1. **Configure DarkStrata Asset**:
   - App: HTTP
   - Base URL: `https://api.darkstrata.io/v1`
   - Authentication: Bearer Token (your API key)

2. **Import Playbooks** from `soar/playbooks/`:
   - `credential_exposure_triage.py` - Automated triage workflow
   - `auto_acknowledge.py` - Auto-acknowledge low-priority alerts
   - `alert_enrichment.py` - Enrich events with threat intel

### Sample Playbooks

#### Credential Exposure Triage

```
Trigger: Container with DarkStrata alert
    │
    ├─► Get Alert Details from API
    │
    ├─► Severity Assessment
    │     ├─► CRITICAL/HIGH → Escalate to Security Team
    │     ├─► MEDIUM → Standard Triage Queue
    │     └─► LOW → Schedule Auto-Acknowledge
    │
    └─► Create Enrichment Artifact
```

#### Alert Enrichment

```
Trigger: Notable event from ES
    │
    ├─► Extract emails/domains from event
    │
    ├─► Query DarkStrata Threat Intel
    │     ├─► Email Intel Lookup
    │     └─► Domain Intel Lookup
    │
    └─► Create Threat Intel Artifacts
          └─► Update container severity if high-risk
```

### API Endpoints for SOAR

| Action | Method | Endpoint | Body |
|--------|--------|----------|------|
| List Alerts | GET | `/alerts` | - |
| Get Alert | GET | `/alerts/{id}` | - |
| Acknowledge | POST | `/alerts/{id}/acknowledge` | - |
| Update Status | PATCH | `/alerts/{id}` | `{"status": "CLOSED"}` |
| Get Indicators | GET | `/stix/indicators?format=splunk` | - |

### Error Handling in Playbooks

```python
# Recommended retry logic
import time

def api_request_with_retry(url, max_retries=3):
    for attempt in range(max_retries):
        response = requests.get(url, headers=headers)
        if response.status_code == 429:  # Rate limited
            wait_time = (2 ** attempt) * 1
            time.sleep(wait_time)
            continue
        if response.status_code == 200:
            return response.json()
        response.raise_for_status()
    raise Exception("Max retries exceeded")
```

For detailed SOAR documentation, see [soar/README.md](soar/README.md).

---

## Performance Tuning

The TA includes configurable performance settings for large-scale deployments.

### Configuration Settings

Navigate to **Configuration** > **Performance** in the TA settings.

| Setting | Default | Range | Description |
|---------|---------|-------|-------------|
| **Batch Size** | 100 | 10-500 | Records per API request |
| **Request Timeout** | 30s | 10-300s | Individual request timeout |
| **Max Retries** | 3 | 0-5 | Retry attempts with exponential backoff |
| **Rate Limit** | 0 (unlimited) | 0-600 | Max requests per minute |
| **Connection Pooling** | Enabled | - | Reuse HTTP connections |
| **Max Connections** | 5 | 1-20 | Concurrent connections |

### Tuning Guidelines

#### High-Volume Environments (>100k events/day)

```
Batch Size: 500
Request Timeout: 60s
Rate Limit: 0 (unlimited if allowed by API plan)
Max Connections: 10
```

#### Shared/Constrained Environments

```
Batch Size: 50
Request Timeout: 30s
Rate Limit: 60
Max Connections: 3
```

#### Network-Challenged Environments

```
Batch Size: 25
Request Timeout: 120s
Max Retries: 5
Connection Pooling: Disabled (if connection issues)
```

### Monitoring Performance

#### Collection Throughput
```spl
index=_internal sourcetype=splunkd component=ModularInputs darkstrata
| rex "collected (?<count>\d+) events"
| timechart span=1h sum(count) as events_collected
```

#### API Response Times
```spl
index=_internal sourcetype=splunkd component=ModularInputs darkstrata
| rex "request completed in (?<duration_ms>\d+)ms"
| timechart span=1h avg(duration_ms) as avg_response_ms, p95(duration_ms) as p95_ms
```

#### Rate Limit Hits
```spl
index=_internal sourcetype=splunkd darkstrata "rate limit"
| timechart span=1h count as rate_limit_hits
```

### Memory Optimisation

For very large batch sizes, monitor Splunk search head memory:

```spl
| rest /services/server/status/resource-usage/splunk-processes
| where process_type="search"
| table process, mem_used
```

Reduce batch size if memory consumption is excessive.

### Best Practices

1. **Start conservative**: Begin with default settings, tune based on observed performance
2. **Monitor error rates**: High error rates may indicate too-aggressive settings
3. **Coordinate with API limits**: Check your DarkStrata plan for API rate limits
4. **Use off-peak collection**: Schedule heavy collection during low-activity periods
5. **Enable connection pooling**: Significantly reduces connection overhead

---

## Search Macros Reference

### Base Searches

| Macro | Definition | Description |
|-------|------------|-------------|
| `darkstrata_observed_data` | `sourcetype="darkstrata:stix:observed-data"` | All observed-data events |
| `darkstrata_alerts` | `sourcetype="darkstrata:stix:alert"` | All alert bundles |

### Field Extraction

| Macro | Description |
|-------|-------------|
| `darkstrata_extract_fields` | Extract `user`, `user_type`, `dest` from objects |
| `darkstrata_extract_labels` | Parse labels into `source_type`, `flow_direction`, `severity` |
| `darkstrata_full_extract` | Complete extraction pipeline |
| `darkstrata_threat_weight` | Calculate threat weight (0-100) from severity |

### Filters

| Macro | Description |
|-------|-------------|
| `darkstrata_high_severity` | Filter critical/high severity only |
| `darkstrata_malware_source` | Filter `source:malware` only |
| `darkstrata_breach_source` | Filter `source:breach` only |
| `darkstrata_inbound_flow` | Filter `flow:inbound` only |
| `darkstrata_outbound_flow` | Filter `flow:outbound` only |

### Lookups

| Macro | Arguments | Description |
|-------|-----------|-------------|
| `darkstrata_email_lookup(field)` | Email field name | Look up email in threat intel |
| `darkstrata_domain_lookup(field)` | Domain field name | Look up domain in threat intel |
| `darkstrata_user_lookup(field)` | User field name | Look up user in threat intel |

### Usage Examples

```spl
# Dashboard: Recent high-severity exposures
`darkstrata_observed_data`
| `darkstrata_high_severity`
| `darkstrata_full_extract`
| table _time, user, dest, source_type, severity
| head 100

# Report: Exposures by source type
`darkstrata_observed_data`
| `darkstrata_extract_labels`
| stats count by source_type, severity
| sort -count

# Alert: Malware credentials in last hour
`darkstrata_observed_data` earliest=-1h
| `darkstrata_malware_source`
| `darkstrata_extract_fields`
| dedup user
| table _time, user, dest

# Enrichment: Check if authentication user is compromised
index=auth_logs sourcetype=linux_secure
| `darkstrata_user_lookup(user)`
| where isnotnull(threat_key)
| table _time, user, src, threat_description, threat_weight

# Statistics summary
`darkstrata_summary_stats`
```

---

## Troubleshooting

### Common Issues

#### No data appearing

1. **Check input status**:
   ```spl
   | rest /services/data/inputs/darkstrata_indicators
   | table title, disabled, interval
   ```

2. **Check for errors**:
   ```spl
   index=_internal sourcetype=splunkd component=ModularInputs
     (darkstrata_indicators OR darkstrata_alerts) log_level=ERROR
   | table _time, message
   ```

3. **Verify API connectivity** (from Splunk server):
   ```bash
   curl -s -o /dev/null -w "%{http_code}" \
     -H "Authorization: Bearer YOUR_API_KEY" \
     "https://api.darkstrata.io/v1/stix/indicators?format=splunk&limit=1"
   ```

#### Authentication errors (401)

- Verify API key is correct and not expired
- Check API key has `siem:read` permission
- Regenerate API key if needed

#### Permission errors (403)

- API key exists but lacks required scope
- Add `siem:read` permission to API key in DarkStrata dashboard

#### Connection timeout

- Check firewall allows outbound HTTPS to `api.darkstrata.io`
- Configure proxy if required
- Increase network timeout (default 30s)

#### Checkpoint issues

View checkpoint state:
```spl
| inputlookup ta_darkstrata_checkpoints
| table _key, last_sync, last_run, event_count
```

Reset checkpoint (force full resync):
```spl
| inputlookup ta_darkstrata_checkpoints
| where _key="darkstrata_indicators_YOUR_INPUT_NAME"
| outputlookup ta_darkstrata_checkpoints append=f
```

### Diagnostic Searches

#### Input health check
```spl
index=_internal sourcetype=splunkd component=ModularInputs darkstrata
| timechart span=1h count by log_level
```

#### Data collection rate
```spl
index=* sourcetype="darkstrata:*" earliest=-24h
| timechart span=1h count by sourcetype
```

#### Error summary
```spl
index=_internal sourcetype=splunkd darkstrata log_level=ERROR
| stats count by message
| sort -count
```

#### API response times
```spl
index=_internal sourcetype=splunkd component=ModularInputs darkstrata
| rex "request.*(?<duration>\d+)ms"
| timechart avg(duration) as avg_response_ms
```

### Debug Mode

Enable debug logging temporarily:

1. Navigate to **Configuration** > **Logging**
2. Set **Log Level** to `DEBUG`
3. Reproduce the issue
4. Check logs:
   ```spl
   index=_internal sourcetype=splunkd darkstrata log_level=DEBUG
   | table _time, message
   ```
5. Reset to `INFO` after troubleshooting

---

## Security Considerations

### API Key Security

- API keys are stored encrypted in Splunk's credential store
- Keys are never logged or exposed in search results
- Use dedicated API keys with minimal required permissions
- Rotate API keys according to your security policy

### Network Security

- All API communication uses HTTPS/TLS 1.2+
- Certificate validation is enforced
- Proxy authentication passwords are encrypted

### Data Privacy

- **Email hashing**: Enable `hash_emails` to SHA-256 hash email addresses
- **Index access**: Restrict access to DarkStrata indexes via Splunk roles
- **PII handling**: Consider data retention policies for credential exposure data

### Splunk Permissions

Recommended role configuration:

| Role | Permissions |
|------|-------------|
| Admin | Full configuration access |
| Security Analyst | Search DarkStrata indexes, run saved searches |
| SOC Tier 1 | View notable events, read-only dashboards |

### Audit Logging

Monitor TA configuration changes:
```spl
index=_audit action=edit* path="*ta_darkstrata*"
| table _time, user, action, path
```

---

## Upgrading

### Before Upgrading

1. Note your current version:
   ```spl
   | rest /services/apps/local/TA-darkstrata
   | table label, version
   ```

2. Export custom configurations (if any):
   - Custom saved searches
   - Modified correlation searches
   - Custom macros

3. Review the [CHANGELOG](CHANGELOG.md) for breaking changes

### Upgrade Process

#### Splunkbase Upgrade

1. Navigate to **Apps** > **Manage Apps**
2. Find **DarkStrata Technology Add-on**
3. Click **Update** if available

#### Manual Upgrade

```bash
# Backup existing app
cp -r $SPLUNK_HOME/etc/apps/TA-darkstrata $SPLUNK_HOME/etc/apps/TA-darkstrata.backup

# Extract new version
tar -xzf TA-darkstrata-x.x.x.tar.gz -C $SPLUNK_HOME/etc/apps/

# Restart Splunk
$SPLUNK_HOME/bin/splunk restart
```

### After Upgrading

1. Verify inputs are running:
   ```spl
   | rest /services/data/inputs/darkstrata_indicators
   ```

2. Check for new features in **Configuration**

3. Review updated correlation searches

4. Re-enable any customisations

---

## Development

### Building from Source

```bash
cd splunk-ta

# Install build dependencies
pip install -e ".[build]"

# Build TA package
ucc-gen build --source package

# Output: output/TA-darkstrata/
```

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=package/bin --cov-report=html

# Run specific test
pytest tests/test_api_client.py -v
```

### Code Quality

```bash
# Lint
ruff check package/bin tests

# Format
ruff format package/bin tests

# Type check
mypy package/bin
```

### AppInspect Validation

```bash
# Install AppInspect
pip install splunk-appinspect

# Validate for Splunk Cloud
splunk-appinspect inspect output/TA-darkstrata \
  --mode precert \
  --included-tags cloud
```

### Creating a Release

```bash
# Build and package
ucc-gen build --source package
cd output
tar -czvf TA-darkstrata-1.0.0.tar.gz TA-darkstrata

# Calculate checksum
sha256sum TA-darkstrata-1.0.0.tar.gz > TA-darkstrata-1.0.0.tar.gz.sha256
```

---

## Support

### Documentation

- **DarkStrata Docs**: [https://darkstrata.io/docs/integrations/splunk](https://darkstrata.io/docs/integrations/splunk)
- **STIX API Reference**: [https://darkstrata.io/docs/api/stix](https://darkstrata.io/docs/api/stix)

### Getting Help

- **GitHub Issues**: [https://github.com/drb/darkstrata-sdks/issues](https://github.com/drb/darkstrata-sdks/issues)
- **Email Support**: support@darkstrata.io
- **Slack Community**: [https://darkstrata.io/slack](https://darkstrata.io/slack)

### Reporting Bugs

When reporting issues, please include:

1. TA version (`| rest /services/apps/local/TA-darkstrata | table version`)
2. Splunk version (`| rest /services/server/info | table version`)
3. Error messages from `index=_internal`
4. Steps to reproduce

---

## Licence

Apache License 2.0 - see [LICENCE](../../LICENSE) for details.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.
