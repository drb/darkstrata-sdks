# DarkStrata SOAR Integration Guide

This guide covers integration with Security Orchestration, Automation, and Response (SOAR) platforms.

## Supported Platforms

- **Splunk SOAR (Phantom)** - Native integration via REST API actions
- **XSOAR (Demisto)** - Custom integration via HTTP integration
- **Swimlane** - REST API connector
- **Other SOAR platforms** - Any platform supporting REST API calls

## Splunk SOAR (Phantom) Integration

### Prerequisites

1. Splunk SOAR instance with admin access
2. DarkStrata API key with appropriate permissions
3. Network connectivity between SOAR and DarkStrata API

### Setup Using HTTP App

The simplest integration uses Splunk SOAR's built-in HTTP app:

1. Navigate to **Apps** > **HTTP**
2. Configure an asset with the DarkStrata API endpoint

**Asset Configuration:**
```
Name: darkstrata_api
Base URL: https://api.darkstrata.io/v1
Headers:
  Authorization: Bearer YOUR_API_KEY
  Content-Type: application/json
  Accept: application/json
```

### Available Actions

| Action | HTTP Method | Endpoint | Description |
|--------|-------------|----------|-------------|
| List Alerts | GET | `/alerts` | Get list of credential exposure alerts |
| Get Alert | GET | `/alerts/{id}` | Get alert details |
| Acknowledge Alert | POST | `/alerts/{id}/acknowledge` | Acknowledge an alert |
| Update Alert Status | PATCH | `/alerts/{id}` | Change alert status |
| Get Indicators | GET | `/stix/indicators` | Get STIX indicators |

### Sample Playbooks

See the `playbooks/` directory for sample SOAR playbooks:

- `credential_exposure_triage.json` - Automated triage of credential exposures
- `alert_enrichment.json` - Enrich notable events with DarkStrata data
- `auto_acknowledge.json` - Auto-acknowledge low-severity alerts

## Custom SOAR Connector

For platforms requiring a custom connector, use the DarkStrata REST API directly.

### API Authentication

All API requests require Bearer token authentication:

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
     -H "Accept: application/json" \
     https://api.darkstrata.io/v1/alerts
```

### Common API Endpoints

#### List Alerts
```
GET /v1/alerts
Parameters:
  - status: ACTIVE, UNDER_INVESTIGATION, CLOSED
  - severity: LOW, MEDIUM, HIGH, CRITICAL
  - since: ISO8601 timestamp
  - limit: Number of results (max 100)
```

#### Get Alert Details
```
GET /v1/alerts/{alert_id}
```

#### Acknowledge Alert
```
POST /v1/alerts/{alert_id}/acknowledge
```

#### Update Alert Status
```
PATCH /v1/alerts/{alert_id}
Body: {"status": "CLOSED"}
```

#### Get STIX Indicators
```
GET /v1/stix/indicators?format=splunk
Parameters:
  - since: ISO8601 timestamp
  - limit: Number of results
  - confidence: Minimum confidence threshold (0-100)
```

### Error Handling

| HTTP Status | Meaning | Action |
|-------------|---------|--------|
| 200 | Success | Process response |
| 400 | Bad Request | Check parameters |
| 401 | Unauthorised | Check API key |
| 403 | Forbidden | Check permissions |
| 404 | Not Found | Verify resource exists |
| 429 | Rate Limited | Implement backoff |
| 500 | Server Error | Retry with backoff |

### Rate Limiting

The DarkStrata API implements rate limiting. SOAR playbooks should:

1. Check for 429 responses
2. Implement exponential backoff
3. Use batch operations where possible

Example backoff logic:
```python
import time

def api_request_with_retry(url, max_retries=3):
    for attempt in range(max_retries):
        response = requests.get(url, headers=headers)
        if response.status_code == 429:
            wait_time = (2 ** attempt) * 1  # Exponential backoff
            time.sleep(wait_time)
            continue
        return response
    raise Exception("Max retries exceeded")
```

## XSOAR (Demisto) Integration

### Setup

1. Navigate to **Settings** > **Integrations**
2. Search for **HTTP** integration
3. Create a new instance

**Instance Configuration:**
```yaml
Name: DarkStrata
Server URL: https://api.darkstrata.io/v1
Authentication Type: Bearer Token
API Key: YOUR_API_KEY
```

### Sample Commands

Create commands in your integration:

```yaml
- name: darkstrata-list-alerts
  description: List DarkStrata alerts
  execution: true
  arguments:
  - name: status
    description: Filter by status
    default: false
    isArray: false
  outputs:
  - contextPath: DarkStrata.Alert.id
    description: Alert ID
    type: String
```

## Best Practices

### Security

1. **Store API keys securely** - Use SOAR's credential vault
2. **Use least privilege** - Request only necessary API permissions
3. **Audit API usage** - Monitor API calls in DarkStrata dashboard
4. **Rotate keys regularly** - Implement key rotation procedures

### Performance

1. **Use incremental sync** - Pass `since` parameter to avoid re-fetching data
2. **Batch operations** - Fetch multiple records per request
3. **Cache where appropriate** - Cache alert details to reduce API calls
4. **Implement rate limiting** - Respect API rate limits

### Automation

1. **Start with manual workflows** - Test before automating
2. **Add approval gates** - Require human approval for critical actions
3. **Log all actions** - Maintain audit trail
4. **Handle failures gracefully** - Implement error handling and alerts

## Troubleshooting

### Connection Issues

```bash
# Test API connectivity
curl -v -H "Authorization: Bearer YOUR_API_KEY" \
     https://api.darkstrata.io/v1/alerts?limit=1
```

### Authentication Failures

- Verify API key is correct and active
- Check key has required permissions
- Ensure key hasn't expired

### Rate Limiting

If experiencing rate limits:
1. Reduce polling frequency
2. Implement exponential backoff
3. Use webhook-based triggers instead of polling

## Support

For integration support:
- Documentation: https://docs.darkstrata.io
- API Reference: https://api.darkstrata.io/docs
- Support: support@darkstrata.io
