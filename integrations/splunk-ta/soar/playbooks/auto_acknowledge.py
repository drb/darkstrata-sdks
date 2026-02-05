"""
DarkStrata Auto-Acknowledge Playbook

This playbook automatically acknowledges alerts that meet specific criteria:
- Low or Info severity
- Older than configurable threshold
- No sensitive domains affected

Compatible with Splunk SOAR (Phantom) 5.x+
"""

# Configuration
AUTO_ACK_SEVERITY_THRESHOLD = ["LOW", "INFO"]
SENSITIVE_DOMAINS = []  # Add your sensitive domains here


def on_start(container):
    """
    Entry point for the playbook.
    """
    phantom.debug("Starting DarkStrata auto-acknowledge playbook")

    # Get alert details from artifacts
    success, message, artifacts = phantom.get_artifacts(container_id=container["id"])

    alert_artifact = None
    for artifact in artifacts:
        if artifact.get("name") in ["DarkStrata Alert", "DarkStrata Alert Enrichment"]:
            alert_artifact = artifact
            break

    if not alert_artifact:
        phantom.debug("No DarkStrata alert artifact found")
        return

    cef = alert_artifact.get("cef", {})
    severity = cef.get("severity", "MEDIUM")
    alert_id = cef.get("alert_id")
    affected_domains = cef.get("affected_domains", "").split(", ")

    # Check if alert meets auto-acknowledge criteria
    if should_auto_acknowledge(severity, affected_domains):
        acknowledge_alert(alert_id, container)
    else:
        phantom.debug(f"Alert {alert_id} does not meet auto-acknowledge criteria")
        add_review_note(container, severity, affected_domains)


def should_auto_acknowledge(severity, affected_domains):
    """
    Determine if alert should be auto-acknowledged.
    """
    # Check severity
    if severity.upper() not in AUTO_ACK_SEVERITY_THRESHOLD:
        phantom.debug(f"Severity {severity} does not meet threshold")
        return False

    # Check for sensitive domains
    for domain in affected_domains:
        if domain in SENSITIVE_DOMAINS:
            phantom.debug(f"Sensitive domain {domain} affected")
            return False

    return True


def acknowledge_alert(alert_id, container):
    """
    Acknowledge the alert in DarkStrata.
    """
    phantom.debug(f"Auto-acknowledging alert: {alert_id}")

    phantom.act(
        action="post data",
        parameters=[{
            "location": f"/alerts/{alert_id}/acknowledge",
            "body": "{}",
            "verify_certificate": True,
        }],
        assets=["darkstrata_api"],
        callback=process_acknowledge_response,
        name="acknowledge_alert",
    )


def process_acknowledge_response(action=None, success=None, container=None, results=None, **kwargs):
    """
    Process the acknowledge response.
    """
    if success:
        phantom.debug("Alert acknowledged successfully")

        phantom.add_note(
            container=container,
            content="Alert has been auto-acknowledged in DarkStrata based on "
                    "low severity and no sensitive domains affected.",
            note_format="markdown",
            note_type="general",
            title="Auto-Acknowledged",
        )

        # Update container status
        phantom.set_status(container=container, status="resolved")
    else:
        phantom.error("Failed to acknowledge alert")

        phantom.add_note(
            container=container,
            content="Failed to auto-acknowledge alert. Manual review required.",
            note_format="markdown",
            note_type="general",
            title="Auto-Acknowledge Failed",
        )


def add_review_note(container, severity, affected_domains):
    """
    Add note explaining why auto-acknowledge was skipped.
    """
    reasons = []

    if severity.upper() not in AUTO_ACK_SEVERITY_THRESHOLD:
        reasons.append(f"Severity ({severity}) above threshold")

    for domain in affected_domains:
        if domain in SENSITIVE_DOMAINS:
            reasons.append(f"Sensitive domain affected: {domain}")

    phantom.add_note(
        container=container,
        content=f"Auto-acknowledge skipped. Reasons:\n- " + "\n- ".join(reasons),
        note_format="markdown",
        note_type="general",
        title="Manual Review Required",
    )
