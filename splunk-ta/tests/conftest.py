"""
Pytest configuration and fixtures for DarkStrata Splunk TA tests.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# Add package/bin to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "package" / "bin"))


@pytest.fixture
def mock_splunk_libs(monkeypatch: pytest.MonkeyPatch) -> dict[str, MagicMock]:
    """Mock Splunk libraries that aren't available during testing."""
    mocks: dict[str, MagicMock] = {}

    # Mock import_declare_test (UCC generated)
    mocks["import_declare_test"] = MagicMock()
    monkeypatch.setitem(sys.modules, "import_declare_test", mocks["import_declare_test"])

    # Mock solnlib
    mocks["solnlib"] = MagicMock()
    mocks["solnlib.conf_manager"] = MagicMock()
    mocks["solnlib.log"] = MagicMock()
    mocks["solnlib.modular_input"] = MagicMock()
    mocks["solnlib.modular_input.checkpointer"] = MagicMock()

    monkeypatch.setitem(sys.modules, "solnlib", mocks["solnlib"])
    monkeypatch.setitem(sys.modules, "solnlib.conf_manager", mocks["solnlib.conf_manager"])
    monkeypatch.setitem(sys.modules, "solnlib.log", mocks["solnlib.log"])
    monkeypatch.setitem(sys.modules, "solnlib.modular_input", mocks["solnlib.modular_input"])
    monkeypatch.setitem(sys.modules, "solnlib.modular_input.checkpointer", mocks["solnlib.modular_input.checkpointer"])

    # Mock splunktaucclib
    mocks["splunktaucclib"] = MagicMock()
    mocks["splunktaucclib.rest_handler"] = MagicMock()
    mocks["splunktaucclib.rest_handler.endpoint"] = MagicMock()
    mocks["splunktaucclib.rest_handler.endpoint.validator"] = MagicMock()
    mocks["splunktaucclib.modinput_wrapper"] = MagicMock()
    mocks["splunktaucclib.modinput_wrapper.base_modinput"] = MagicMock()

    monkeypatch.setitem(sys.modules, "splunktaucclib", mocks["splunktaucclib"])
    monkeypatch.setitem(sys.modules, "splunktaucclib.rest_handler", mocks["splunktaucclib.rest_handler"])
    monkeypatch.setitem(sys.modules, "splunktaucclib.rest_handler.endpoint", mocks["splunktaucclib.rest_handler.endpoint"])
    monkeypatch.setitem(sys.modules, "splunktaucclib.rest_handler.endpoint.validator", mocks["splunktaucclib.rest_handler.endpoint.validator"])
    monkeypatch.setitem(sys.modules, "splunktaucclib.modinput_wrapper", mocks["splunktaucclib.modinput_wrapper"])
    monkeypatch.setitem(sys.modules, "splunktaucclib.modinput_wrapper.base_modinput", mocks["splunktaucclib.modinput_wrapper.base_modinput"])

    # Mock splunklib
    mocks["splunklib"] = MagicMock()
    mocks["splunklib.modularinput"] = MagicMock()
    monkeypatch.setitem(sys.modules, "splunklib", mocks["splunklib"])
    monkeypatch.setitem(sys.modules, "splunklib.modularinput", mocks["splunklib.modularinput"])

    return mocks


@pytest.fixture
def sample_stix_bundle() -> dict[str, Any]:
    """Sample STIX bundle as returned by /stix/alerts endpoint."""
    return {
        "type": "bundle",
        "id": "bundle--12345678-1234-1234-1234-123456789012",
        "objects": [
            {
                "type": "extension-definition",
                "id": "extension-definition--d6132570-7659-4922-9fc4-420e4f8cba63",
                "name": "DarkStrata Credential Exposure Extension",
            },
            {
                "type": "report",
                "id": "report--alert-uuid",
                "name": "Credential Exposure Alert - 5 compromised credentials",
                "description": "DarkStrata detected 5 compromised credentials",
                "published": "2024-01-15T10:30:00.000Z",
                "labels": ["darkstrata", "credential-exposure", "severity-high"],
                "object_refs": ["observed-data--match-1", "observed-data--match-2"],
            },
            {
                "type": "observed-data",
                "id": "observed-data--match-1",
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
            },
            {
                "type": "observed-data",
                "id": "observed-data--match-2",
                "created": "2024-01-15T09:00:00.000Z",
                "modified": "2024-01-15T09:00:00.000Z",
                "first_observed": "2024-01-13T12:00:00.000Z",
                "last_observed": "2024-01-15T09:00:00.000Z",
                "number_observed": 1,
                "objects": {
                    "0": {
                        "type": "user-account",
                        "account_login": "admin@example.com",
                        "account_type": "email",
                    },
                    "1": {"type": "domain-name", "value": "github.com"},
                },
                "labels": [
                    "darkstrata",
                    "credential-exposure",
                    "source:breach",
                    "flow:inbound",
                ],
            },
        ],
    }


@pytest.fixture
def sample_indicators_bundle() -> dict[str, Any]:
    """Sample STIX bundle as returned by /stix/indicators endpoint."""
    return {
        "type": "bundle",
        "id": "bundle--indicators-uuid",
        "objects": [
            {
                "type": "extension-definition",
                "id": "extension-definition--d6132570-7659-4922-9fc4-420e4f8cba63",
                "name": "DarkStrata Credential Exposure Extension",
            },
            {
                "type": "observed-data",
                "id": "observed-data--indicator-1",
                "created": "2024-01-15T10:00:00.000Z",
                "modified": "2024-01-15T10:00:00.000Z",
                "first_observed": "2024-01-14T08:00:00.000Z",
                "last_observed": "2024-01-15T10:00:00.000Z",
                "number_observed": 1,
                "objects": {
                    "0": {
                        "type": "user-account",
                        "account_login": "test@example.com",
                        "account_type": "email",
                    },
                    "1": {"type": "domain-name", "value": "dropbox.com"},
                },
                "labels": [
                    "darkstrata",
                    "credential-exposure",
                    "source:malware",
                    "flow:outbound",
                ],
            },
            {
                "type": "observed-data",
                "id": "observed-data--indicator-2",
                "created": "2024-01-15T11:00:00.000Z",
                "modified": "2024-01-15T11:00:00.000Z",
                "first_observed": "2024-01-15T06:00:00.000Z",
                "last_observed": "2024-01-15T11:00:00.000Z",
                "number_observed": 1,
                "objects": {
                    "0": {
                        "type": "user-account",
                        "account_login": "dev@example.com",
                        "account_type": "email",
                    },
                    "1": {"type": "domain-name", "value": "aws.amazon.com"},
                },
                "labels": [
                    "darkstrata",
                    "credential-exposure",
                    "source:malware",
                    "flow:outbound",
                ],
            },
        ],
    }


@pytest.fixture
def api_base_url() -> str:
    """DarkStrata API base URL for tests."""
    return "https://api.darkstrata.io/v1"


@pytest.fixture
def api_key() -> str:
    """Test API key."""
    return "test-api-key-12345"
