"""
Tests for the DarkStrata API credential validator (darkstrata_api_validator.py).

The validator runs when an account is saved in the Splunk UI; it performs a
test request against the DarkStrata API and surfaces a human-readable message
on failure. These tests cover the input-validation branches and every HTTP
error path without touching the network (requests is patched via `responses`).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import requests
import responses

sys.path.insert(0, str(Path(__file__).parent.parent / "package" / "bin"))

from darkstrata_api_validator import DarkStrataAPIValidator  # noqa: E402

API_BASE = "https://api.darkstrata.io/v1"
INDICATORS_URL = f"{API_BASE}/stix/indicators"


class RecordingValidator(DarkStrataAPIValidator):
    """Validator subclass that records put_msg() calls for assertions."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def put_msg(self, msg: str) -> None:
        self.messages.append(msg)


@pytest.fixture
def validator() -> RecordingValidator:
    return RecordingValidator()


# --- input validation (no network) -----------------------------------------


def test_missing_base_url_fails(validator: RecordingValidator) -> None:
    assert validator.validate("api-key", {"api_base_url": ""}) is False
    assert "API Base URL is required" in validator.messages[0]


def test_missing_api_key_fails(validator: RecordingValidator) -> None:
    assert validator.validate("", {"api_base_url": API_BASE}) is False
    assert "API Key is required" in validator.messages[0]


def test_non_https_base_url_rejected(validator: RecordingValidator) -> None:
    assert validator.validate("api-key", {"api_base_url": "http://api.darkstrata.io"}) is False
    assert "must use HTTPS" in validator.messages[0]


def test_trailing_slash_is_stripped(validator: RecordingValidator) -> None:
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, INDICATORS_URL, json={"type": "bundle"}, status=200)
        assert validator.validate("api-key", {"api_base_url": API_BASE + "/"}) is True


# --- successful validation ---------------------------------------------------


@responses.activate
def test_valid_credentials_pass(validator: RecordingValidator) -> None:
    responses.add(responses.GET, INDICATORS_URL, json={"type": "bundle"}, status=200)
    assert validator.validate("good-key", {"api_base_url": API_BASE}) is True
    assert validator.messages == []
    # The validator must send the API key and a recognisable User-Agent.
    sent = responses.calls[0].request
    assert sent.headers["x-api-key"] == "good-key"
    assert "TA-DarkStrata" in sent.headers["User-Agent"]


# --- HTTP error branches -----------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected_fragment"),
    [
        (401, "authentication failed"),
        (403, "siem:read"),
        (404, "endpoint not found"),
        (500, "API returned error: 500"),
    ],
)
@responses.activate
def test_http_error_messages(validator: RecordingValidator, status: int, expected_fragment: str) -> None:
    responses.add(responses.GET, INDICATORS_URL, json={"error": "x"}, status=status)
    assert validator.validate("key", {"api_base_url": API_BASE}) is False
    assert any(expected_fragment.lower() in m.lower() for m in validator.messages)


@responses.activate
def test_connection_error_message(validator: RecordingValidator) -> None:
    responses.add(responses.GET, INDICATORS_URL, body=requests.exceptions.ConnectionError("boom"))
    assert validator.validate("key", {"api_base_url": API_BASE}) is False
    assert "Connection failed" in validator.messages[0]


@responses.activate
def test_timeout_message(validator: RecordingValidator) -> None:
    responses.add(responses.GET, INDICATORS_URL, body=requests.exceptions.Timeout("slow"))
    assert validator.validate("key", {"api_base_url": API_BASE}) is False
    assert "timed out" in validator.messages[0]


@responses.activate
def test_generic_request_exception_message(validator: RecordingValidator) -> None:
    responses.add(responses.GET, INDICATORS_URL, body=requests.exceptions.RequestException("nope"))
    assert validator.validate("key", {"api_base_url": API_BASE}) is False
    assert "Request failed" in validator.messages[0]


def test_unexpected_exception_is_caught(validator: RecordingValidator, monkeypatch: pytest.MonkeyPatch) -> None:
    # A non-requests error (e.g. programming bug) must still be reported, not raised.
    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("unexpected")

    monkeypatch.setattr("darkstrata_api_validator.requests.get", boom)
    assert validator.validate("key", {"api_base_url": API_BASE}) is False
    assert "Unexpected error" in validator.messages[0]


def test_module_exports_validator_alias() -> None:
    # UCC resolves the validator via the module-level lowercase alias.
    from darkstrata_api_validator import darkstrata_api_validator

    assert darkstrata_api_validator is DarkStrataAPIValidator
