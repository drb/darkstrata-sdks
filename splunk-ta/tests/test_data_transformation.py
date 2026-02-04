"""
Tests for data transformation and event creation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest

if TYPE_CHECKING:
    pass


class TestTimestampParsing:
    """Tests for timestamp parsing functionality."""

    @pytest.fixture(autouse=True)
    def setup(self, mock_splunk_libs: dict[str, MagicMock]) -> None:
        """Set up test fixtures."""
        # Import after mocking
        from darkstrata_inputs import DarkStrataIndicatorsInput

        # Create a mock instance to test the method
        self.input_class = DarkStrataIndicatorsInput
        self.input_class._input_definition = MagicMock()
        self.input_class._input_definition.metadata = {"session_key": "test"}

    def test_parse_iso8601_timestamp_with_z(self) -> None:
        """Test parsing ISO 8601 timestamp with Z suffix."""
        # We need to test the function directly
        from darkstrata_inputs import DarkStrataIndicatorsInput

        instance = object.__new__(DarkStrataIndicatorsInput)

        timestamp = "2024-01-15T10:30:00.000Z"
        result = instance._parse_timestamp(timestamp)

        assert result is not None
        # Convert back to datetime to verify
        dt = datetime.fromtimestamp(result, tz=timezone.utc)
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15
        assert dt.hour == 10
        assert dt.minute == 30

    def test_parse_iso8601_timestamp_with_offset(self) -> None:
        """Test parsing ISO 8601 timestamp with timezone offset."""
        from darkstrata_inputs import DarkStrataIndicatorsInput

        instance = object.__new__(DarkStrataIndicatorsInput)

        timestamp = "2024-01-15T10:30:00.000+00:00"
        result = instance._parse_timestamp(timestamp)

        assert result is not None

    def test_parse_timestamp_none(self) -> None:
        """Test parsing None timestamp."""
        from darkstrata_inputs import DarkStrataIndicatorsInput

        instance = object.__new__(DarkStrataIndicatorsInput)

        result = instance._parse_timestamp(None)
        assert result is None

    def test_parse_invalid_timestamp(self) -> None:
        """Test parsing invalid timestamp format."""
        from darkstrata_inputs import DarkStrataIndicatorsInput

        instance = object.__new__(DarkStrataIndicatorsInput)

        result = instance._parse_timestamp("not-a-timestamp")
        assert result is None


class TestObservedDataExtraction:
    """Tests for extracting fields from observed-data objects."""

    @pytest.fixture
    def observed_data_event(self) -> dict[str, Any]:
        """Sample observed-data event."""
        return {
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
            ],
        }

    def test_extract_user_account(self, observed_data_event: dict[str, Any]) -> None:
        """Test extracting user account from observed-data."""
        user_account = observed_data_event["objects"]["0"]

        assert user_account["type"] == "user-account"
        assert user_account["account_login"] == "user@example.com"
        assert user_account["account_type"] == "email"

    def test_extract_domain(self, observed_data_event: dict[str, Any]) -> None:
        """Test extracting domain from observed-data."""
        domain = observed_data_event["objects"]["1"]

        assert domain["type"] == "domain-name"
        assert domain["value"] == "slack.com"

    def test_extract_source_from_labels(self, observed_data_event: dict[str, Any]) -> None:
        """Test extracting source type from labels."""
        labels = observed_data_event["labels"]

        source = None
        for label in labels:
            if label.startswith("source:"):
                source = label.split(":")[1]
                break

        assert source == "malware"

    def test_extract_flow_from_labels(self, observed_data_event: dict[str, Any]) -> None:
        """Test extracting flow direction from labels."""
        labels = observed_data_event["labels"]

        flow = None
        for label in labels:
            if label.startswith("flow:"):
                flow = label.split(":")[1]
                break

        assert flow == "outbound"


class TestAlertBundleExtraction:
    """Tests for extracting fields from alert bundles."""

    def test_extract_report_from_bundle(
        self, sample_stix_bundle: dict[str, Any]
    ) -> None:
        """Test extracting report object from bundle."""
        report = None
        for obj in sample_stix_bundle["objects"]:
            if obj.get("type") == "report":
                report = obj
                break

        assert report is not None
        assert "Credential Exposure Alert" in report["name"]
        assert "severity-high" in report["labels"]

    def test_extract_indicators_from_bundle(
        self, sample_stix_bundle: dict[str, Any]
    ) -> None:
        """Test extracting observed-data objects from bundle."""
        indicators = [
            obj
            for obj in sample_stix_bundle["objects"]
            if obj.get("type") == "observed-data"
        ]

        assert len(indicators) == 2
        assert all(ind["type"] == "observed-data" for ind in indicators)

    def test_extract_severity_from_labels(
        self, sample_stix_bundle: dict[str, Any]
    ) -> None:
        """Test extracting severity from report labels."""
        report = next(
            obj for obj in sample_stix_bundle["objects"] if obj.get("type") == "report"
        )

        severity = None
        for label in report.get("labels", []):
            if label.startswith("severity-"):
                severity = label.split("-")[1]
                break

        assert severity == "high"

    def test_count_indicators_in_bundle(
        self, sample_stix_bundle: dict[str, Any]
    ) -> None:
        """Test counting indicators in a bundle."""
        indicator_count = sum(
            1
            for obj in sample_stix_bundle["objects"]
            if obj.get("type") in ("observed-data", "indicator")
        )

        assert indicator_count == 2


class TestHashedEmailFormat:
    """Tests for hashed email format handling."""

    @pytest.fixture
    def hashed_email_event(self) -> dict[str, Any]:
        """Sample event with hashed email."""
        return {
            "type": "observed-data",
            "id": "observed-data--hashed",
            "objects": {
                "0": {
                    "type": "user-account",
                    "account_login": "sha256:abc123def456",
                    "account_type": "email",
                },
                "1": {"type": "domain-name", "value": "slack.com"},
            },
            "labels": ["darkstrata", "credential-exposure"],
        }

    def test_detect_hashed_email(self, hashed_email_event: dict[str, Any]) -> None:
        """Test detecting hashed email format."""
        account_login = hashed_email_event["objects"]["0"]["account_login"]

        is_hashed = account_login.startswith("sha256:")

        assert is_hashed is True

    def test_extract_hash_value(self, hashed_email_event: dict[str, Any]) -> None:
        """Test extracting hash value from hashed email."""
        account_login = hashed_email_event["objects"]["0"]["account_login"]

        if account_login.startswith("sha256:"):
            hash_value = account_login.split(":")[1]
            assert hash_value == "abc123def456"
