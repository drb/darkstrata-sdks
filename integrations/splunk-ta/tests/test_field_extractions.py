"""
Tests for field extraction regex validation.

Validates that transforms.conf REGEX patterns and props.conf field extractions
work correctly against sample STIX observed-data JSON.
"""

from __future__ import annotations

import configparser
import json
import re
from pathlib import Path

import pytest

# Path to the package directory
PACKAGE_DIR = Path(__file__).parent.parent / "package"
DEFAULT_DIR = PACKAGE_DIR / "default"


def parse_conf(conf_path: Path) -> configparser.ConfigParser:
    """Parse a Splunk .conf file."""
    parser = configparser.ConfigParser(
        interpolation=None,
        strict=False,
        comment_prefixes=("#",),
        inline_comment_prefixes=None,
        allow_no_value=True,
    )
    parser.optionxform = str
    content = conf_path.read_text().replace("\\\n", " ")
    parser.read_string(content)
    return parser


@pytest.fixture
def transforms_conf() -> configparser.ConfigParser:
    return parse_conf(DEFAULT_DIR / "transforms.conf")


@pytest.fixture
def sample_observed_data_json() -> str:
    """Sample STIX observed-data JSON as it would appear in Splunk raw events."""
    data = {
        "type": "observed-data",
        "id": "observed-data--test-id",
        "created": "2024-01-15T10:00:00.000Z",
        "modified": "2024-01-15T10:00:00.000Z",
        "first_observed": "2024-01-14T08:00:00.000Z",
        "last_observed": "2024-01-15T10:00:00.000Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "user-account",
                "account_login": "user@example.com",
                "account_type": "email",
            },
            "1": {"type": "domain-name", "value": "slack.com"},
        },
        "labels": [
            "darkstrata",
            "credential-exposure",
            "source:malware",
            "flow:outbound",
            "severity-high",
        ],
    }
    return json.dumps(data)


@pytest.fixture
def sample_breach_json() -> str:
    """Sample STIX observed-data JSON with breach source and inbound flow."""
    data = {
        "type": "observed-data",
        "id": "observed-data--breach-id",
        "objects": {
            "0": {
                "type": "user-account",
                "account_login": "admin@corp.com",
                "account_type": "email",
            },
            "1": {"type": "domain-name", "value": "github.com"},
        },
        "labels": [
            "darkstrata",
            "credential-exposure",
            "source:breach",
            "flow:inbound",
            "severity-critical",
        ],
    }
    return json.dumps(data)


class TestExtractUserAccount:
    """Test darkstrata_extract_user_account regex."""

    def test_extracts_email_from_observed_data(
        self,
        transforms_conf: configparser.ConfigParser,
        sample_observed_data_json: str,
    ) -> None:
        regex = transforms_conf.get("darkstrata_extract_user_account", "REGEX")
        match = re.search(regex, sample_observed_data_json)
        assert match is not None
        assert match.group(1) == "user@example.com"

    def test_extracts_different_email(
        self,
        transforms_conf: configparser.ConfigParser,
        sample_breach_json: str,
    ) -> None:
        regex = transforms_conf.get("darkstrata_extract_user_account", "REGEX")
        match = re.search(regex, sample_breach_json)
        assert match is not None
        assert match.group(1) == "admin@corp.com"

    def test_no_match_on_unrelated_json(self, transforms_conf: configparser.ConfigParser) -> None:
        regex = transforms_conf.get("darkstrata_extract_user_account", "REGEX")
        unrelated = '{"type": "network-traffic", "src_port": 443}'
        match = re.search(regex, unrelated)
        assert match is None


class TestExtractDomain:
    """Test darkstrata_extract_domain regex."""

    def test_extracts_domain_from_observed_data(
        self,
        transforms_conf: configparser.ConfigParser,
        sample_observed_data_json: str,
    ) -> None:
        regex = transforms_conf.get("darkstrata_extract_domain", "REGEX")
        match = re.search(regex, sample_observed_data_json, re.DOTALL)
        assert match is not None
        assert match.group(1) == "slack.com"

    def test_extracts_different_domain(
        self,
        transforms_conf: configparser.ConfigParser,
        sample_breach_json: str,
    ) -> None:
        regex = transforms_conf.get("darkstrata_extract_domain", "REGEX")
        match = re.search(regex, sample_breach_json, re.DOTALL)
        assert match is not None
        assert match.group(1) == "github.com"

    def test_no_match_without_domain_type(self, transforms_conf: configparser.ConfigParser) -> None:
        regex = transforms_conf.get("darkstrata_extract_domain", "REGEX")
        no_domain = '{"type": "user-account", "value": "notadomain"}'
        match = re.search(regex, no_domain, re.DOTALL)
        assert match is None


class TestExtractSource:
    """Test darkstrata_extract_source regex."""

    def test_extracts_malware_source(
        self,
        transforms_conf: configparser.ConfigParser,
        sample_observed_data_json: str,
    ) -> None:
        regex = transforms_conf.get("darkstrata_extract_source", "REGEX")
        match = re.search(regex, sample_observed_data_json)
        assert match is not None
        assert match.group(1) == "malware"

    def test_extracts_breach_source(
        self,
        transforms_conf: configparser.ConfigParser,
        sample_breach_json: str,
    ) -> None:
        regex = transforms_conf.get("darkstrata_extract_source", "REGEX")
        match = re.search(regex, sample_breach_json)
        assert match is not None
        assert match.group(1) == "breach"

    def test_no_match_on_unknown_source(self, transforms_conf: configparser.ConfigParser) -> None:
        regex = transforms_conf.get("darkstrata_extract_source", "REGEX")
        unknown = '"source:phishing"'
        match = re.search(regex, unknown)
        assert match is None


class TestExtractFlow:
    """Test darkstrata_extract_flow regex."""

    def test_extracts_outbound_flow(
        self,
        transforms_conf: configparser.ConfigParser,
        sample_observed_data_json: str,
    ) -> None:
        regex = transforms_conf.get("darkstrata_extract_flow", "REGEX")
        match = re.search(regex, sample_observed_data_json)
        assert match is not None
        assert match.group(1) == "outbound"

    def test_extracts_inbound_flow(
        self,
        transforms_conf: configparser.ConfigParser,
        sample_breach_json: str,
    ) -> None:
        regex = transforms_conf.get("darkstrata_extract_flow", "REGEX")
        match = re.search(regex, sample_breach_json)
        assert match is not None
        assert match.group(1) == "inbound"

    def test_no_match_on_unknown_flow(self, transforms_conf: configparser.ConfigParser) -> None:
        regex = transforms_conf.get("darkstrata_extract_flow", "REGEX")
        unknown = '"flow:lateral"'
        match = re.search(regex, unknown)
        assert match is None


class TestExtractSeverity:
    """Test darkstrata_extract_severity regex."""

    def test_extracts_high_severity(
        self,
        transforms_conf: configparser.ConfigParser,
        sample_observed_data_json: str,
    ) -> None:
        regex = transforms_conf.get("darkstrata_extract_severity", "REGEX")
        match = re.search(regex, sample_observed_data_json)
        assert match is not None
        assert match.group(1) == "high"

    def test_extracts_critical_severity(
        self,
        transforms_conf: configparser.ConfigParser,
        sample_breach_json: str,
    ) -> None:
        regex = transforms_conf.get("darkstrata_extract_severity", "REGEX")
        match = re.search(regex, sample_breach_json)
        assert match is not None
        assert match.group(1) == "critical"

    @pytest.mark.parametrize("level", ["info", "low", "medium", "high", "critical"])
    def test_matches_all_severity_levels(self, transforms_conf: configparser.ConfigParser, level: str) -> None:
        regex = transforms_conf.get("darkstrata_extract_severity", "REGEX")
        test_data = f'"severity-{level}"'
        match = re.search(regex, test_data)
        assert match is not None
        assert match.group(1) == level

    def test_no_match_on_invalid_severity(self, transforms_conf: configparser.ConfigParser) -> None:
        regex = transforms_conf.get("darkstrata_extract_severity", "REGEX")
        invalid = '"severity-extreme"'
        match = re.search(regex, invalid)
        assert match is None


class TestNegativeCases:
    """Verify regexes don't match malformed or unrelated data."""

    def test_user_regex_no_match_on_empty_json(self, transforms_conf: configparser.ConfigParser) -> None:
        regex = transforms_conf.get("darkstrata_extract_user_account", "REGEX")
        assert re.search(regex, "{}") is None

    def test_domain_regex_no_match_on_plain_text(self, transforms_conf: configparser.ConfigParser) -> None:
        regex = transforms_conf.get("darkstrata_extract_domain", "REGEX")
        assert re.search(regex, "this is plain text", re.DOTALL) is None

    def test_source_regex_no_match_on_partial(self, transforms_conf: configparser.ConfigParser) -> None:
        regex = transforms_conf.get("darkstrata_extract_source", "REGEX")
        assert re.search(regex, '"source:ma"') is None

    def test_flow_regex_no_match_on_empty_value(self, transforms_conf: configparser.ConfigParser) -> None:
        regex = transforms_conf.get("darkstrata_extract_flow", "REGEX")
        assert re.search(regex, '"flow:"') is None


class TestCIMFieldCoverage:
    """Verify extracted fields cover required CIM data model fields."""

    def test_authentication_model_fields(self, transforms_conf: configparser.ConfigParser) -> None:
        """Verify the TA extracts fields needed for CIM Authentication data model.

        Required CIM Authentication fields: user, app, action, authentication_method, dest.
        The TA provides user via REGEX and dest via REGEX (domain). The remaining fields
        (app, action, authentication_method) are set via EVAL/FIELDALIAS in props.conf.
        """
        # Check that transforms provide the core fields via REGEX
        regex_stanzas = [s for s in transforms_conf.sections() if transforms_conf.has_option(s, "REGEX")]
        format_fields = set()
        for stanza in regex_stanzas:
            fmt = transforms_conf.get(stanza, "FORMAT")
            # FORMAT is field_name::$1
            field_name = fmt.split("::")[0]
            format_fields.add(field_name)

        # user comes from darkstrata_extract_user_account (FORMAT = user::$1)
        assert "user" in format_fields, "Missing CIM field 'user' from transforms"

    def test_threat_intelligence_model_fields(self, transforms_conf: configparser.ConfigParser) -> None:
        """Verify the TA extracts fields for CIM Threat_Intelligence data model.

        Key fields: threat_source, severity, dest_domain.
        """
        regex_stanzas = [s for s in transforms_conf.sections() if transforms_conf.has_option(s, "REGEX")]
        format_fields = set()
        for stanza in regex_stanzas:
            fmt = transforms_conf.get(stanza, "FORMAT")
            field_name = fmt.split("::")[0]
            format_fields.add(field_name)

        assert "threat_source" in format_fields, "Missing CIM field 'threat_source' from transforms"
        assert "severity" in format_fields, "Missing CIM field 'severity' from transforms"
        assert "dest_domain" in format_fields, "Missing CIM field 'dest_domain' from transforms"
