"""
DarkStrata Credential Exposure Triage Playbook

This playbook automates the initial triage of credential exposure alerts:
1. Extracts alert details from the container
2. Queries DarkStrata API for full alert information
3. Enriches the container with threat intelligence
4. Determines severity and assigns appropriate analyst

Compatible with Splunk SOAR (Phantom) 5.x+
"""


def on_start(container):
    """
    Entry point for the playbook.

    Args:
        container: The Phantom container object
    """
    phantom.debug("Starting DarkStrata credential exposure triage")

    # Get alert ID from container
    alert_id = container.get("source_data_identifier")

    if not alert_id:
        phantom.debug("No alert ID found in container, checking artifacts")
        # Try to get from artifacts
        success, message, artifacts = phantom.get_artifacts(container_id=container["id"])
        for artifact in artifacts:
            if artifact.get("name") == "DarkStrata Alert":
                alert_id = artifact.get("cef", {}).get("alert_id")
                break

    if not alert_id:
        phantom.error("No alert ID found, cannot proceed with triage")
        return

    # Get alert details from DarkStrata
    get_alert_details(alert_id, container)


def get_alert_details(alert_id, container):
    """
    Query DarkStrata API for full alert details.
    """
    phantom.debug(f"Fetching details for alert: {alert_id}")

    # Build URL
    url = f"/alerts/{alert_id}"

    # Call HTTP action
    phantom.act(
        action="get data",
        parameters=[{
            "location": url,
            "verify_certificate": True,
        }],
        assets=["darkstrata_api"],
        callback=process_alert_details,
        name="get_alert_details",
        parent_action=None,
    )


def process_alert_details(action=None, success=None, container=None, results=None, **kwargs):
    """
    Process the alert details response and enrich the container.
    """
    phantom.debug("Processing alert details response")

    if not success:
        phantom.error("Failed to fetch alert details")
        return

    # Extract response data
    response_data = phantom.collect2(
        container=container,
        datapath=["get_alert_details:action_result.data.*"],
    )

    if not response_data:
        phantom.debug("No data in response")
        return

    alert_data = response_data[0][0] if response_data[0] else {}

    # Create enrichment artifact
    create_enrichment_artifact(container, alert_data)

    # Determine severity and next actions
    severity = alert_data.get("severity", "MEDIUM")
    source_type = alert_data.get("source_type", "UNKNOWN")

    phantom.debug(f"Alert severity: {severity}, source: {source_type}")

    # Set container severity
    severity_map = {
        "CRITICAL": "high",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }
    phantom.set_severity(
        container=container,
        severity=severity_map.get(severity, "medium"),
    )

    # Route based on severity and source
    if severity in ["CRITICAL", "HIGH"] or source_type == "MALWARE":
        # High priority - escalate immediately
        escalate_alert(container, alert_data)
    elif source_type == "THIRD_PARTY":
        # Third-party breach - standard triage
        standard_triage(container, alert_data)
    else:
        # Low priority - auto-acknowledge after delay
        auto_acknowledge(container, alert_data)


def create_enrichment_artifact(container, alert_data):
    """
    Create an artifact with enriched alert data.
    """
    cef_data = {
        "alert_id": alert_data.get("id"),
        "severity": alert_data.get("severity"),
        "status": alert_data.get("status"),
        "source_type": alert_data.get("source_type"),
        "source_name": alert_data.get("source_name"),
        "exposed_credentials_count": alert_data.get("exposed_credentials_count", 0),
        "affected_domains": ", ".join(alert_data.get("affected_domains", [])),
        "first_seen": alert_data.get("first_seen"),
        "last_seen": alert_data.get("last_seen"),
        "threat_actor": alert_data.get("threat_actor"),
        "malware_family": alert_data.get("malware_family"),
    }

    phantom.add_artifact(
        container=container,
        raw_data=alert_data,
        cef_data=cef_data,
        label="alert",
        name="DarkStrata Alert Enrichment",
        severity="medium",
        artifact_type="network",
    )


def escalate_alert(container, alert_data):
    """
    Escalate high-severity alerts to security team.
    """
    phantom.debug("Escalating high-severity alert")

    # Add comment
    phantom.add_note(
        container=container,
        content=f"HIGH PRIORITY: This alert has been escalated due to "
                f"severity ({alert_data.get('severity')}) or source type "
                f"({alert_data.get('source_type')}). "
                f"Affected credentials: {alert_data.get('exposed_credentials_count', 0)}",
        note_format="markdown",
        note_type="general",
        title="Alert Escalated",
    )

    # Assign to security team
    phantom.set_owner(
        container=container,
        role="Security Analyst",
    )

    # Create task
    phantom.add_workbook_task(
        container=container,
        name="Investigate Credential Exposure",
        description=f"Review exposed credentials and assess impact. "
                    f"Source: {alert_data.get('source_name')}",
    )


def standard_triage(container, alert_data):
    """
    Standard triage process for medium-priority alerts.
    """
    phantom.debug("Starting standard triage")

    # Add note
    phantom.add_note(
        container=container,
        content=f"Standard triage initiated for third-party breach alert. "
                f"Source: {alert_data.get('source_name')}",
        note_format="markdown",
        note_type="general",
        title="Triage Started",
    )


def auto_acknowledge(container, alert_data):
    """
    Auto-acknowledge low-priority alerts after review period.
    """
    phantom.debug("Scheduling auto-acknowledgement for low-priority alert")

    # Add note
    phantom.add_note(
        container=container,
        content=f"Low-priority alert will be auto-acknowledged in 24 hours "
                f"if no action is taken. Review if needed.",
        note_format="markdown",
        note_type="general",
        title="Auto-Acknowledge Scheduled",
    )

    # In a real playbook, you would schedule a delayed action here
    # using Splunk SOAR's scheduling capabilities
