"""
DarkStrata Alert Enrichment Playbook

This playbook enriches Splunk ES notable events with DarkStrata threat intelligence:
1. Extracts email addresses and domains from the notable event
2. Queries DarkStrata for matching threat intelligence
3. Adds enrichment artifacts to the container
4. Updates the notable event with threat context

Compatible with Splunk SOAR (Phantom) 5.x+
"""


def on_start(container):
    """
    Entry point for the playbook.
    """
    phantom.debug("Starting DarkStrata alert enrichment playbook")

    # Get artifacts from container
    success, message, artifacts = phantom.get_artifacts(container_id=container["id"])

    # Extract email addresses and domains to enrich
    emails_to_check = set()
    domains_to_check = set()

    for artifact in artifacts:
        cef = artifact.get("cef", {})

        # Extract emails
        for field in ["src_user", "dest_user", "user", "email"]:
            value = cef.get(field)
            if value and "@" in value:
                emails_to_check.add(value.lower())
                # Also extract domain
                domain = value.split("@")[1]
                domains_to_check.add(domain.lower())

        # Extract domains
        for field in ["domain", "dest_domain", "src_domain"]:
            value = cef.get(field)
            if value:
                domains_to_check.add(value.lower())

    phantom.debug(f"Emails to check: {emails_to_check}")
    phantom.debug(f"Domains to check: {domains_to_check}")

    # Query DarkStrata for threat intel
    if emails_to_check:
        query_email_intel(list(emails_to_check), container)

    if domains_to_check:
        query_domain_intel(list(domains_to_check), container)


def query_email_intel(emails, container):
    """
    Query DarkStrata for email-based threat intelligence.
    """
    phantom.debug(f"Querying threat intel for {len(emails)} emails")

    # Query the indicators endpoint for email matches
    # In practice, you might need to query each email separately or use a batch endpoint
    for email in emails[:10]:  # Limit to 10 to avoid overwhelming the API
        phantom.act(
            action="get data",
            parameters=[{
                "location": f"/stix/indicators?format=splunk&email={email}",
                "verify_certificate": True,
            }],
            assets=["darkstrata_api"],
            callback=process_email_intel,
            name=f"email_intel_{email.replace('@', '_at_')}",
        )


def query_domain_intel(domains, container):
    """
    Query DarkStrata for domain-based threat intelligence.
    """
    phantom.debug(f"Querying threat intel for {len(domains)} domains")

    for domain in domains[:10]:  # Limit to 10
        phantom.act(
            action="get data",
            parameters=[{
                "location": f"/stix/indicators?format=splunk&domain={domain}",
                "verify_certificate": True,
            }],
            assets=["darkstrata_api"],
            callback=process_domain_intel,
            name=f"domain_intel_{domain.replace('.', '_')}",
        )


def process_email_intel(action=None, success=None, container=None, results=None, **kwargs):
    """
    Process email threat intelligence response.
    """
    if not success:
        phantom.debug("Email intel query failed")
        return

    # Extract response data
    response_data = phantom.collect2(
        container=container,
        datapath=[f"{action}:action_result.data.*"],
    )

    if not response_data or not response_data[0]:
        phantom.debug("No threat intel found for email")
        return

    indicators = response_data[0]
    phantom.debug(f"Found {len(indicators)} indicators for email")

    # Create artifact for each indicator
    for indicator in indicators[:5]:  # Limit artifacts
        create_threat_artifact(container, indicator, "email")


def process_domain_intel(action=None, success=None, container=None, results=None, **kwargs):
    """
    Process domain threat intelligence response.
    """
    if not success:
        phantom.debug("Domain intel query failed")
        return

    # Extract response data
    response_data = phantom.collect2(
        container=container,
        datapath=[f"{action}:action_result.data.*"],
    )

    if not response_data or not response_data[0]:
        phantom.debug("No threat intel found for domain")
        return

    indicators = response_data[0]
    phantom.debug(f"Found {len(indicators)} indicators for domain")

    # Create artifact for each indicator
    for indicator in indicators[:5]:  # Limit artifacts
        create_threat_artifact(container, indicator, "domain")


def create_threat_artifact(container, indicator, intel_type):
    """
    Create a threat intelligence artifact.
    """
    cef_data = {
        "indicator_type": intel_type,
        "threat_key": indicator.get("threat_key"),
        "confidence": indicator.get("confidence"),
        "severity": indicator.get("severity"),
        "source_type": indicator.get("source_type"),
        "source_name": indicator.get("source_name"),
        "first_seen": indicator.get("first_seen"),
        "last_seen": indicator.get("last_seen"),
        "description": indicator.get("description"),
    }

    # Add specific fields based on type
    if intel_type == "email":
        cef_data["email"] = indicator.get("email")
        cef_data["email_domain"] = indicator.get("email", "").split("@")[1] if "@" in indicator.get("email", "") else None
    elif intel_type == "domain":
        cef_data["domain"] = indicator.get("domain")

    phantom.add_artifact(
        container=container,
        raw_data=indicator,
        cef_data=cef_data,
        label="threat_intel",
        name=f"DarkStrata {intel_type.title()} Threat Intel",
        severity=map_severity(indicator.get("severity", "MEDIUM")),
        artifact_type="threat_intel",
    )

    # Update container severity if threat found
    if indicator.get("severity") in ["HIGH", "CRITICAL"]:
        phantom.set_severity(container=container, severity="high")

        phantom.add_note(
            container=container,
            content=f"**HIGH-SEVERITY THREAT DETECTED**\n\n"
                    f"DarkStrata has identified a {intel_type} indicator with "
                    f"{indicator.get('severity')} severity.\n\n"
                    f"Source: {indicator.get('source_name')}\n"
                    f"First Seen: {indicator.get('first_seen')}\n"
                    f"Description: {indicator.get('description')}",
            note_format="markdown",
            note_type="general",
            title="Threat Intelligence Match",
        )


def map_severity(severity):
    """
    Map DarkStrata severity to Phantom severity.
    """
    mapping = {
        "CRITICAL": "high",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "low",
    }
    return mapping.get(severity.upper(), "medium")
