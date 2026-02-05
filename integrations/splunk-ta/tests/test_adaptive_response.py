"""
Unit tests for DarkStrata Adaptive Response actions.

Tests cover:
- Action base class functionality
- Acknowledge alert action
- Close alert action
- Reopen alert action
- Get alert details action
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import responses

# We need to mock the Splunk imports before importing our modules
import sys

# Mock Splunk modules
sys.modules["import_declare_test"] = MagicMock()
sys.modules["solnlib"] = MagicMock()
sys.modules["solnlib.conf_manager"] = MagicMock()
sys.modules["solnlib.log"] = MagicMock()

# Now import our modules
from darkstrata_action_base import (
    DarkStrataActionBase,
    DarkStrataActionError,
    parse_payload,
    write_result,
)


class ConcreteAction(DarkStrataActionBase):
    """Concrete implementation for testing the abstract base class."""

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"test": "success"}


class TestDarkStrataActionError:
    """Tests for DarkStrataActionError exception."""

    def test_error_without_status_code(self):
        """Test error without status code."""
        error = DarkStrataActionError("Test error")
        assert str(error) == "Test error"
        assert error.status_code is None

    def test_error_with_status_code(self):
        """Test error with status code."""
        error = DarkStrataActionError("Auth failed", status_code=401)
        assert str(error) == "Auth failed"
        assert error.status_code == 401


class TestDarkStrataActionBase:
    """Tests for DarkStrataActionBase class."""

    @pytest.fixture
    def action(self):
        """Create a concrete action instance for testing."""
        return ConcreteAction(session_key="test_session_key")

    @responses.activate
    def test_make_api_request_success(self, action):
        """Test successful API request."""
        responses.add(
            responses.GET,
            "https://api.darkstrata.io/v1/alerts/test123",
            json={"id": "test123", "status": "ACTIVE"},
            status=200,
        )

        config = {
            "api_base_url": "https://api.darkstrata.io/v1",
            "api_key": "test_key",
            "proxy_settings": None,
        }

        result = action.make_api_request(config, "GET", "/alerts/test123")

        assert result["id"] == "test123"
        assert result["status"] == "ACTIVE"

    @responses.activate
    def test_make_api_request_401(self, action):
        """Test API request with 401 response."""
        responses.add(
            responses.GET,
            "https://api.darkstrata.io/v1/alerts/test123",
            json={"error": "Unauthorised"},
            status=401,
        )

        config = {
            "api_base_url": "https://api.darkstrata.io/v1",
            "api_key": "invalid_key",
            "proxy_settings": None,
        }

        with pytest.raises(DarkStrataActionError) as exc_info:
            action.make_api_request(config, "GET", "/alerts/test123")

        assert exc_info.value.status_code == 401
        assert "Authentication failed" in str(exc_info.value)

    @responses.activate
    def test_make_api_request_403(self, action):
        """Test API request with 403 response."""
        responses.add(
            responses.GET,
            "https://api.darkstrata.io/v1/alerts/test123",
            json={"error": "Forbidden"},
            status=403,
        )

        config = {
            "api_base_url": "https://api.darkstrata.io/v1",
            "api_key": "test_key",
            "proxy_settings": None,
        }

        with pytest.raises(DarkStrataActionError) as exc_info:
            action.make_api_request(config, "GET", "/alerts/test123")

        assert exc_info.value.status_code == 403
        assert "Access denied" in str(exc_info.value)

    @responses.activate
    def test_make_api_request_404(self, action):
        """Test API request with 404 response."""
        responses.add(
            responses.GET,
            "https://api.darkstrata.io/v1/alerts/nonexistent",
            json={"error": "Not found"},
            status=404,
        )

        config = {
            "api_base_url": "https://api.darkstrata.io/v1",
            "api_key": "test_key",
            "proxy_settings": None,
        }

        with pytest.raises(DarkStrataActionError) as exc_info:
            action.make_api_request(config, "GET", "/alerts/nonexistent")

        assert exc_info.value.status_code == 404
        assert "not found" in str(exc_info.value).lower()

    @responses.activate
    def test_make_api_request_post(self, action):
        """Test POST API request."""
        responses.add(
            responses.POST,
            "https://api.darkstrata.io/v1/alerts/test123/acknowledge",
            json={"id": "test123", "status": "UNDER_INVESTIGATION"},
            status=200,
        )

        config = {
            "api_base_url": "https://api.darkstrata.io/v1",
            "api_key": "test_key",
            "proxy_settings": None,
        }

        result = action.make_api_request(
            config, "POST", "/alerts/test123/acknowledge"
        )

        assert result["status"] == "UNDER_INVESTIGATION"

    @responses.activate
    def test_make_api_request_patch(self, action):
        """Test PATCH API request."""
        responses.add(
            responses.PATCH,
            "https://api.darkstrata.io/v1/alerts/test123",
            json={"id": "test123", "status": "CLOSED"},
            status=200,
        )

        config = {
            "api_base_url": "https://api.darkstrata.io/v1",
            "api_key": "test_key",
            "proxy_settings": None,
        }

        result = action.make_api_request(
            config, "PATCH", "/alerts/test123", data={"status": "CLOSED"}
        )

        assert result["status"] == "CLOSED"

    @responses.activate
    def test_make_api_request_with_proxy(self, action):
        """Test API request with proxy configuration."""
        responses.add(
            responses.GET,
            "https://api.darkstrata.io/v1/alerts/test123",
            json={"id": "test123"},
            status=200,
        )

        config = {
            "api_base_url": "https://api.darkstrata.io/v1",
            "api_key": "test_key",
            "proxy_settings": {
                "proxy_enabled": True,
                "proxy_type": "http",
                "proxy_url": "proxy.example.com",
                "proxy_port": "8080",
                "proxy_username": "",
                "proxy_password": "",
            },
        }

        # Note: responses library doesn't actually test proxy routing,
        # but we verify the request completes without error
        result = action.make_api_request(config, "GET", "/alerts/test123")
        assert result["id"] == "test123"

    def test_run_success(self, action):
        """Test successful action run."""
        payload = {
            "configuration": {"param1": "value1"},
            "session_key": "test_key",
        }

        result = action.run(payload)

        assert result["success"] is True
        assert result["result"] == {"test": "success"}

    def test_run_with_error(self, action):
        """Test action run with error."""
        # Override execute to raise an error
        action.execute = MagicMock(
            side_effect=DarkStrataActionError("Test error", status_code=400)
        )

        payload = {"configuration": {}}

        result = action.run(payload)

        assert result["success"] is False
        assert "Test error" in result["message"]
        assert result["status_code"] == 400


class TestAcknowledgeAlertAction:
    """Tests for AcknowledgeAlertAction."""

    @pytest.fixture
    def mock_account_config(self):
        """Mock account configuration."""
        return {
            "api_base_url": "https://api.darkstrata.io/v1",
            "api_key": "test_key",
            "proxy_settings": None,
        }

    @responses.activate
    def test_acknowledge_alert_success(self, mock_account_config):
        """Test successful alert acknowledgement."""
        from darkstrata_acknowledge_alert import AcknowledgeAlertAction

        responses.add(
            responses.POST,
            "https://api.darkstrata.io/v1/alerts/alert123/acknowledge",
            json={
                "id": "alert123",
                "status": "UNDER_INVESTIGATION",
                "acknowledged_at": "2024-01-15T10:00:00Z",
                "acknowledged_by_user": {"email": "test@example.com"},
            },
            status=200,
        )

        action = AcknowledgeAlertAction(session_key="test_key")
        action.get_account_config = MagicMock(return_value=mock_account_config)

        result = action.execute({
            "account": "test_account",
            "alert_id": "alert123",
        })

        assert result["alert_id"] == "alert123"
        assert result["status"] == "UNDER_INVESTIGATION"
        assert result["acknowledged_by"] == "test@example.com"

    def test_acknowledge_alert_missing_account(self):
        """Test acknowledge with missing account."""
        from darkstrata_acknowledge_alert import AcknowledgeAlertAction

        action = AcknowledgeAlertAction(session_key="test_key")

        with pytest.raises(DarkStrataActionError) as exc_info:
            action.execute({"alert_id": "alert123"})

        assert "Account name is required" in str(exc_info.value)

    def test_acknowledge_alert_missing_alert_id(self):
        """Test acknowledge with missing alert ID."""
        from darkstrata_acknowledge_alert import AcknowledgeAlertAction

        action = AcknowledgeAlertAction(session_key="test_key")

        with pytest.raises(DarkStrataActionError) as exc_info:
            action.execute({"account": "test_account"})

        assert "Alert ID is required" in str(exc_info.value)


class TestCloseAlertAction:
    """Tests for CloseAlertAction."""

    @pytest.fixture
    def mock_account_config(self):
        """Mock account configuration."""
        return {
            "api_base_url": "https://api.darkstrata.io/v1",
            "api_key": "test_key",
            "proxy_settings": None,
        }

    @responses.activate
    def test_close_alert_success(self, mock_account_config):
        """Test successful alert closure."""
        from darkstrata_close_alert import CloseAlertAction

        responses.add(
            responses.PATCH,
            "https://api.darkstrata.io/v1/alerts/alert123",
            json={
                "id": "alert123",
                "status": "CLOSED",
                "closed_at": "2024-01-15T12:00:00Z",
                "closed_by_user": {"email": "test@example.com"},
            },
            status=200,
        )

        action = CloseAlertAction(session_key="test_key")
        action.get_account_config = MagicMock(return_value=mock_account_config)

        result = action.execute({
            "account": "test_account",
            "alert_id": "alert123",
        })

        assert result["alert_id"] == "alert123"
        assert result["status"] == "CLOSED"
        assert result["closed_by"] == "test@example.com"


class TestReopenAlertAction:
    """Tests for ReopenAlertAction."""

    @pytest.fixture
    def mock_account_config(self):
        """Mock account configuration."""
        return {
            "api_base_url": "https://api.darkstrata.io/v1",
            "api_key": "test_key",
            "proxy_settings": None,
        }

    @responses.activate
    def test_reopen_alert_success(self, mock_account_config):
        """Test successful alert reopening."""
        from darkstrata_reopen_alert import ReopenAlertAction

        responses.add(
            responses.PATCH,
            "https://api.darkstrata.io/v1/alerts/alert123",
            json={
                "id": "alert123",
                "status": "ACTIVE",
                "updated_at": "2024-01-15T14:00:00Z",
            },
            status=200,
        )

        action = ReopenAlertAction(session_key="test_key")
        action.get_account_config = MagicMock(return_value=mock_account_config)

        result = action.execute({
            "account": "test_account",
            "alert_id": "alert123",
        })

        assert result["alert_id"] == "alert123"
        assert result["status"] == "ACTIVE"


class TestGetAlertDetailsAction:
    """Tests for GetAlertDetailsAction."""

    @pytest.fixture
    def mock_account_config(self):
        """Mock account configuration."""
        return {
            "api_base_url": "https://api.darkstrata.io/v1",
            "api_key": "test_key",
            "proxy_settings": None,
        }

    @responses.activate
    def test_get_alert_details_success(self, mock_account_config):
        """Test successful alert details retrieval."""
        from darkstrata_get_alert_details import GetAlertDetailsAction

        responses.add(
            responses.GET,
            "https://api.darkstrata.io/v1/alerts/alert123",
            json={
                "id": "alert123",
                "status": "ACTIVE",
                "severity": "HIGH",
                "title": "Test Alert",
                "description": "Test description",
                "exposed_credentials_count": 5,
                "affected_domains": ["example.com"],
                "source_type": "MALWARE",
                "source_name": "Test Malware",
                "created_at": "2024-01-15T08:00:00Z",
            },
            status=200,
        )

        action = GetAlertDetailsAction(session_key="test_key")
        action.get_account_config = MagicMock(return_value=mock_account_config)

        result = action.execute({
            "account": "test_account",
            "alert_id": "alert123",
        })

        assert result["alert_id"] == "alert123"
        assert result["severity"] == "HIGH"
        assert result["source_type"] == "MALWARE"
        assert result["exposed_credentials_count"] == 5


class TestPayloadParsing:
    """Tests for payload parsing utilities."""

    def test_parse_payload_no_args(self):
        """Test parsing with no command line args."""
        with patch.object(sys, "argv", ["script.py"]):
            result = parse_payload()
            assert result == {}

    def test_write_result(self, capsys):
        """Test writing result to stdout."""
        write_result({"success": True, "message": "Test"})
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["success"] is True
        assert output["message"] == "Test"
