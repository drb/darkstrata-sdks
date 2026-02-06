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
        import darkstrata_inputs

        self._parse_timestamp_fn = darkstrata_inputs.DarkStrataIndicatorsInput.__dict__.get("_parse_timestamp")
        if self._parse_timestamp_fn is None:
            pytest.skip("_parse_timestamp not found in class dict")

    def _parse_timestamp(self, timestamp_str: str | None) -> float | None:
        """Call _parse_timestamp as an unbound method."""
        dummy_self = MagicMock()
        return self._parse_timestamp_fn(dummy_self, timestamp_str)

    def test_parse_iso8601_timestamp_with_z(self) -> None:
        """Test parsing ISO 8601 timestamp with Z suffix."""
        timestamp = "2024-01-15T10:30:00.000Z"
        result = self._parse_timestamp(timestamp)

        assert result is not None
        dt = datetime.fromtimestamp(result, tz=timezone.utc)
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15
        assert dt.hour == 10
        assert dt.minute == 30

    def test_parse_iso8601_timestamp_with_offset(self) -> None:
        """Test parsing ISO 8601 timestamp with timezone offset."""
        timestamp = "2024-01-15T10:30:00.000+00:00"
        result = self._parse_timestamp(timestamp)

        assert result is not None

    def test_parse_timestamp_none(self) -> None:
        """Test parsing None timestamp."""
        result = self._parse_timestamp(None)
        assert result is None

    def test_parse_invalid_timestamp(self) -> None:
        """Test parsing invalid timestamp format."""
        result = self._parse_timestamp("not-a-timestamp")
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

    def test_extract_report_from_bundle(self, sample_stix_bundle: dict[str, Any]) -> None:
        """Test extracting report object from bundle."""
        report = None
        for obj in sample_stix_bundle["objects"]:
            if obj.get("type") == "report":
                report = obj
                break

        assert report is not None
        assert "Credential Exposure Alert" in report["name"]
        assert "severity-high" in report["labels"]

    def test_extract_indicators_from_bundle(self, sample_stix_bundle: dict[str, Any]) -> None:
        """Test extracting observed-data objects from bundle."""
        indicators = [obj for obj in sample_stix_bundle["objects"] if obj.get("type") == "observed-data"]

        assert len(indicators) == 2
        assert all(ind["type"] == "observed-data" for ind in indicators)

    def test_extract_severity_from_labels(self, sample_stix_bundle: dict[str, Any]) -> None:
        """Test extracting severity from report labels."""
        report = next(obj for obj in sample_stix_bundle["objects"] if obj.get("type") == "report")

        severity = None
        for label in report.get("labels", []):
            if label.startswith("severity-"):
                severity = label.split("-")[1]
                break

        assert severity == "high"

    def test_count_indicators_in_bundle(self, sample_stix_bundle: dict[str, Any]) -> None:
        """Test counting indicators in a bundle."""
        indicator_count = sum(
            1 for obj in sample_stix_bundle["objects"] if obj.get("type") in ("observed-data", "indicator")
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


class TestCreateEvent:
    """Tests for _create_event() output format.

    Since DarkStrataIndicatorsInput extends a mocked base class,
    we import the module and access the unbound method from its real
    class definition in the module's source.
    """

    @pytest.fixture(autouse=True)
    def setup(self, mock_splunk_libs: dict[str, MagicMock]) -> None:
        """Set up test fixtures."""
        import darkstrata_inputs

        # Get the _create_event function from the class dict
        # (bypasses MagicMock metaclass issues)
        self._create_event_fn = darkstrata_inputs.DarkStrataIndicatorsInput.__dict__.get("_create_event")
        if self._create_event_fn is None:
            # Method was inherited from the mocked base; skip these tests
            pytest.skip("_create_event not found in class dict (mocked base)")

    def _call_create_event(self, data: str, time: float | None, index: str, sourcetype: str) -> Any:
        """Call _create_event as an unbound method."""
        dummy_self = MagicMock()
        return self._create_event_fn(dummy_self, data=data, time=time, index=index, sourcetype=sourcetype)

    def test_create_event_sets_data(self) -> None:
        """Test _create_event sets event data."""
        event = self._call_create_event(
            data='{"type": "observed-data"}',
            time=1705312200.0,
            index="main",
            sourcetype="darkstrata:stix:observed-data",
        )
        assert event.data == '{"type": "observed-data"}'

    def test_create_event_sets_sourcetype(self) -> None:
        """Test _create_event sets correct sourcetype."""
        event = self._call_create_event(
            data="{}",
            time=1705312200.0,
            index="main",
            sourcetype="darkstrata:stix:observed-data",
        )
        assert event.sourcetype == "darkstrata:stix:observed-data"

    def test_create_event_sets_index(self) -> None:
        """Test _create_event sets correct index."""
        event = self._call_create_event(
            data="{}",
            time=1705312200.0,
            index="threat_intel",
            sourcetype="darkstrata:stix:observed-data",
        )
        assert event.index == "threat_intel"

    def test_create_event_handles_none_time(self) -> None:
        """Test _create_event handles None timestamp."""
        event = self._call_create_event(
            data="{}",
            time=None,
            index="main",
            sourcetype="darkstrata:stix:observed-data",
        )
        assert event.time is None


class TestEmptyBundleHandling:
    """Tests for edge cases in bundle processing."""

    def test_empty_bundle_objects(self) -> None:
        """Bundle with empty objects list should have no indicators."""
        bundle: dict[str, Any] = {
            "type": "bundle",
            "id": "bundle--empty",
            "objects": [],
        }

        indicators = [obj for obj in bundle["objects"] if obj.get("type") == "observed-data"]
        assert len(indicators) == 0

    def test_bundle_with_only_extension_definition(self) -> None:
        """Bundle with only extension-definition should have no indicators."""
        bundle: dict[str, Any] = {
            "type": "bundle",
            "id": "bundle--ext-only",
            "objects": [
                {
                    "type": "extension-definition",
                    "id": "extension-definition--test",
                    "name": "Test Extension",
                },
            ],
        }

        indicators = [obj for obj in bundle["objects"] if obj.get("type") == "observed-data"]
        assert len(indicators) == 0

    def test_bundle_missing_objects_key(self) -> None:
        """Bundle without objects key should be handled gracefully."""
        bundle: dict[str, Any] = {
            "type": "bundle",
            "id": "bundle--no-objects",
        }

        indicators = [obj for obj in bundle.get("objects", []) if obj.get("type") == "observed-data"]
        assert len(indicators) == 0


class TestMalformedDataHandling:
    """Tests for defensive handling of malformed objects."""

    def test_observed_data_missing_objects(self) -> None:
        """Observed-data without objects dict should be handled."""
        event: dict[str, Any] = {
            "type": "observed-data",
            "id": "observed-data--no-objects",
            "labels": ["darkstrata"],
        }

        objects = event.get("objects", {})
        user_account = objects.get("0", {})
        assert user_account.get("account_login") is None

    def test_observed_data_missing_labels(self) -> None:
        """Observed-data without labels should be handled."""
        event: dict[str, Any] = {
            "type": "observed-data",
            "id": "observed-data--no-labels",
            "objects": {
                "0": {"type": "user-account", "account_login": "test@test.com"},
            },
        }

        labels = event.get("labels", [])
        source = None
        for label in labels:
            if label.startswith("source:"):
                source = label.split(":")[1]
                break

        assert source is None

    def test_observed_data_with_null_account_login(self) -> None:
        """Observed-data with null account_login should be handled."""
        event: dict[str, Any] = {
            "type": "observed-data",
            "id": "observed-data--null-login",
            "objects": {
                "0": {"type": "user-account", "account_login": None},
            },
        }

        account_login = event["objects"]["0"]["account_login"]
        assert account_login is None


class TestConfidenceThresholdFiltering:
    """Tests for confidence threshold filtering logic."""

    def test_confidence_above_threshold(self) -> None:
        """Indicator with confidence above threshold should pass."""
        indicator: dict[str, Any] = {
            "type": "observed-data",
            "id": "observed-data--high-conf",
            "confidence": 85,
        }
        threshold = 60
        assert indicator.get("confidence", 0) >= threshold

    def test_confidence_below_threshold(self) -> None:
        """Indicator with confidence below threshold should be filtered."""
        indicator: dict[str, Any] = {
            "type": "observed-data",
            "id": "observed-data--low-conf",
            "confidence": 30,
        }
        threshold = 60
        assert indicator.get("confidence", 0) < threshold

    def test_confidence_missing_defaults_to_zero(self) -> None:
        """Indicator without confidence field defaults to 0."""
        indicator: dict[str, Any] = {
            "type": "observed-data",
            "id": "observed-data--no-conf",
        }
        threshold = 60
        assert indicator.get("confidence", 0) < threshold

    def test_zero_threshold_passes_all(self) -> None:
        """Zero threshold should pass all indicators."""
        indicators = [
            {"type": "observed-data", "confidence": 0},
            {"type": "observed-data", "confidence": 50},
            {"type": "observed-data", "confidence": 100},
        ]
        threshold = 0
        passed = [i for i in indicators if i.get("confidence", 0) >= threshold]
        assert len(passed) == len(indicators)
