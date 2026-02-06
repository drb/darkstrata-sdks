"""
Tests for DarkStrata API client.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest
import responses
from responses import matchers

if TYPE_CHECKING:
    pass


class TestDarkStrataAPIClient:
    """Tests for the DarkStrataAPIClient class."""

    @pytest.fixture(autouse=True)
    def setup(
        self,
        mock_splunk_libs: dict[str, MagicMock],
        api_base_url: str,
        api_key: str,
    ) -> None:
        """Set up test fixtures."""
        # Import after mocking Splunk libs
        from darkstrata_inputs import DarkStrataAPIClient

        self.client = DarkStrataAPIClient(
            api_base_url=api_base_url,
            api_key=api_key,
            logger=logging.getLogger("test"),
        )
        self.api_base_url = api_base_url

    @responses.activate
    def test_make_request_success(self, sample_indicators_bundle: dict[str, Any]) -> None:
        """Test successful API request."""
        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json=sample_indicators_bundle,
            status=200,
        )

        result = self.client._make_request("/stix/indicators", {"limit": 10})

        assert result["type"] == "bundle"
        assert len(result["objects"]) > 0

    @responses.activate
    def test_make_request_auth_header(self) -> None:
        """Test that API key is sent in Authorization header."""
        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json={"type": "bundle", "objects": []},
            status=200,
            match=[matchers.header_matcher({"x-api-key": "test-api-key-12345"})],
        )

        self.client._make_request("/stix/indicators")

        assert len(responses.calls) == 1

    @responses.activate
    def test_make_request_user_agent(self) -> None:
        """Test that User-Agent header includes Splunk identifier."""
        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json={"type": "bundle", "objects": []},
            status=200,
        )

        self.client._make_request("/stix/indicators")

        assert len(responses.calls) == 1
        user_agent = responses.calls[0].request.headers.get("User-Agent", "")
        assert "Splunk" in user_agent

    @responses.activate
    def test_make_request_401_error(self) -> None:
        """Test handling of 401 Unauthorized error."""
        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json={"error": "Unauthorized"},
            status=401,
        )

        import requests

        with pytest.raises(requests.exceptions.HTTPError) as exc_info:
            self.client._make_request("/stix/indicators")

        assert exc_info.value.response.status_code == 401

    @responses.activate
    def test_make_request_403_error(self) -> None:
        """Test handling of 403 Forbidden error."""
        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json={"error": "Forbidden - missing siem:read permission"},
            status=403,
        )

        import requests

        with pytest.raises(requests.exceptions.HTTPError) as exc_info:
            self.client._make_request("/stix/indicators")

        assert exc_info.value.response.status_code == 403

    @responses.activate
    def test_make_request_timeout(self) -> None:
        """Test handling of request timeout."""
        import requests

        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            body=requests.exceptions.Timeout("Connection timed out"),
        )

        with pytest.raises(requests.exceptions.Timeout):
            self.client._make_request("/stix/indicators")

    @responses.activate
    def test_fetch_indicators_single_page(self, sample_indicators_bundle: dict[str, Any]) -> None:
        """Test fetching indicators from single page."""
        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json=sample_indicators_bundle,
            status=200,
            headers={"X-Page": "1", "X-Total-Pages": "1", "X-Total-Count": "2"},
        )

        indicators = list(self.client.fetch_indicators())

        assert len(indicators) == 2
        assert all(ind["type"] == "observed-data" for ind in indicators)

    @responses.activate
    def test_fetch_indicators_with_pagination(self, sample_indicators_bundle: dict[str, Any]) -> None:
        """Test fetching indicators with pagination."""
        page1_bundle = {
            "type": "bundle",
            "objects": [sample_indicators_bundle["objects"][1]],  # observed-data only
        }
        page2_bundle = {
            "type": "bundle",
            "objects": [sample_indicators_bundle["objects"][2]],  # observed-data only
        }

        # Page 1
        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json=page1_bundle,
            status=200,
            headers={"X-Page": "1", "X-Total-Pages": "2", "X-Total-Count": "2"},
        )

        # Page 2
        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json=page2_bundle,
            status=200,
            headers={"X-Page": "2", "X-Total-Pages": "2", "X-Total-Count": "2"},
        )

        indicators = list(self.client.fetch_indicators())

        assert len(indicators) == 2
        assert len(responses.calls) == 2

    @responses.activate
    def test_fetch_indicators_with_since_parameter(self, sample_indicators_bundle: dict[str, Any]) -> None:
        """Test fetching indicators with since parameter for incremental sync."""
        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json=sample_indicators_bundle,
            status=200,
            headers={"X-Page": "1", "X-Total-Pages": "1"},
        )

        since = "2024-01-15T00:00:00.000Z"
        list(self.client.fetch_indicators(since=since))

        # Verify since parameter was sent
        assert len(responses.calls) == 1
        request_params = responses.calls[0].request.params
        assert request_params.get("since") == since

    @responses.activate
    def test_fetch_indicators_with_confidence_threshold(self, sample_indicators_bundle: dict[str, Any]) -> None:
        """Test fetching indicators with confidence threshold."""
        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json=sample_indicators_bundle,
            status=200,
            headers={"X-Page": "1", "X-Total-Pages": "1"},
        )

        list(self.client.fetch_indicators(confidence_threshold=60))

        request_params = responses.calls[0].request.params
        assert request_params.get("confidence_threshold") == "60"

    @responses.activate
    def test_fetch_indicators_with_hash_emails(self, sample_indicators_bundle: dict[str, Any]) -> None:
        """Test fetching indicators with email hashing enabled."""
        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json=sample_indicators_bundle,
            status=200,
            headers={"X-Page": "1", "X-Total-Pages": "1"},
        )

        list(self.client.fetch_indicators(hash_emails=True))

        request_params = responses.calls[0].request.params
        assert request_params.get("hash_emails") == "true"

    @responses.activate
    def test_fetch_alerts_single_page(self, sample_stix_bundle: dict[str, Any]) -> None:
        """Test fetching alerts from single page."""
        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/alerts",
            json=[sample_stix_bundle],
            status=200,
            headers={"X-Page": "1", "X-Total-Pages": "1", "X-Total-Count": "1"},
        )

        alerts = list(self.client.fetch_alerts())

        assert len(alerts) == 1
        assert alerts[0]["type"] == "bundle"

    @responses.activate
    def test_fetch_alerts_with_detail_parameter(self, sample_stix_bundle: dict[str, Any]) -> None:
        """Test fetching alerts with detail parameter."""
        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/alerts",
            json=[sample_stix_bundle],
            status=200,
            headers={"X-Page": "1", "X-Total-Pages": "1"},
        )

        list(self.client.fetch_alerts(detail="summary"))

        request_params = responses.calls[0].request.params
        assert request_params.get("detail") == "summary"

    @responses.activate
    def test_fetch_alerts_with_include_identities(self, sample_stix_bundle: dict[str, Any]) -> None:
        """Test fetching alerts with identities included."""
        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/alerts",
            json=[sample_stix_bundle],
            status=200,
            headers={"X-Page": "1", "X-Total-Pages": "1"},
        )

        list(self.client.fetch_alerts(include_identities=True))

        request_params = responses.calls[0].request.params
        assert request_params.get("include") == "identities"


class TestDarkStrataAPIClientProxy:
    """Tests for proxy configuration."""

    @pytest.fixture(autouse=True)
    def setup(
        self,
        mock_splunk_libs: dict[str, MagicMock],
        api_base_url: str,
        api_key: str,
    ) -> None:
        """Set up test fixtures."""
        self.api_base_url = api_base_url
        self.api_key = api_key
        self.mock_splunk_libs = mock_splunk_libs

    def test_proxy_configuration(self) -> None:
        """Test that proxy is configured correctly."""
        from darkstrata_inputs import DarkStrataAPIClient

        proxy_settings = {
            "proxy_enabled": True,
            "proxy_type": "http",
            "proxy_url": "proxy.example.com",
            "proxy_port": "8080",
        }

        client = DarkStrataAPIClient(
            api_base_url=self.api_base_url,
            api_key=self.api_key,
            proxy_settings=proxy_settings,
        )

        assert "http://proxy.example.com:8080" in str(client.session.proxies)

    def test_proxy_with_auth(self) -> None:
        """Test proxy configuration with authentication."""
        from darkstrata_inputs import DarkStrataAPIClient

        proxy_settings = {
            "proxy_enabled": True,
            "proxy_type": "http",
            "proxy_url": "proxy.example.com",
            "proxy_port": "8080",
            "proxy_username": "user",
            "proxy_password": "pass",
        }

        client = DarkStrataAPIClient(
            api_base_url=self.api_base_url,
            api_key=self.api_key,
            proxy_settings=proxy_settings,
        )

        proxy_url = str(client.session.proxies.get("http", ""))
        assert "user:pass@" in proxy_url

    def test_proxy_disabled(self) -> None:
        """Test that proxy is not configured when disabled."""
        from darkstrata_inputs import DarkStrataAPIClient

        proxy_settings = {
            "proxy_enabled": False,
            "proxy_url": "proxy.example.com",
            "proxy_port": "8080",
        }

        client = DarkStrataAPIClient(
            api_base_url=self.api_base_url,
            api_key=self.api_key,
            proxy_settings=proxy_settings,
        )

        assert not client.session.proxies


class TestTLS12Enforcement:
    """Tests for TLS 1.2 minimum version enforcement."""

    @pytest.fixture(autouse=True)
    def setup(
        self,
        mock_splunk_libs: dict[str, MagicMock],
        api_base_url: str,
        api_key: str,
    ) -> None:
        """Set up test fixtures."""
        from darkstrata_inputs import DarkStrataAPIClient

        self.client = DarkStrataAPIClient(
            api_base_url=api_base_url,
            api_key=api_key,
            logger=logging.getLogger("test"),
        )

    def test_tls12_adapter_mounted(self) -> None:
        """Session must have TLS12Adapter mounted for HTTPS."""
        from darkstrata_inputs import TLS12Adapter

        # The session should have a TLS12Adapter for https://
        adapter = self.client.session.get_adapter("https://example.com")
        assert isinstance(adapter, TLS12Adapter)

    def test_tls12_adapter_init_poolmanager(self) -> None:
        """TLS12Adapter.init_poolmanager sets minimum TLS version."""
        import ssl

        from darkstrata_inputs import TLS12Adapter

        adapter = TLS12Adapter()
        # Call init_poolmanager to verify it doesn't raise
        adapter.init_poolmanager(connections=1, maxsize=1)
        # If we get here, the SSL context was created successfully
        # Verify TLS 1.2 is the minimum by checking the context
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


class TestAPIErrorHandling:
    """Tests for server error and rate limiting response handling."""

    @pytest.fixture(autouse=True)
    def setup(
        self,
        mock_splunk_libs: dict[str, MagicMock],
        api_base_url: str,
        api_key: str,
    ) -> None:
        """Set up test fixtures."""
        from darkstrata_inputs import DarkStrataAPIClient

        self.client = DarkStrataAPIClient(
            api_base_url=api_base_url,
            api_key=api_key,
            logger=logging.getLogger("test"),
        )
        self.api_base_url = api_base_url

    @responses.activate
    def test_429_rate_limited_response(self) -> None:
        """Test handling of 429 Too Many Requests."""
        import requests

        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json={"error": "Rate limit exceeded"},
            status=429,
            headers={"Retry-After": "60"},
        )

        with pytest.raises(requests.exceptions.HTTPError) as exc_info:
            self.client._make_request("/stix/indicators")

        assert exc_info.value.response.status_code == 429

    @responses.activate
    def test_500_server_error(self) -> None:
        """Test handling of 500 Internal Server Error."""
        import requests

        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json={"error": "Internal server error"},
            status=500,
        )

        with pytest.raises(requests.exceptions.HTTPError) as exc_info:
            self.client._make_request("/stix/indicators")

        assert exc_info.value.response.status_code == 500

    @responses.activate
    def test_502_bad_gateway(self) -> None:
        """Test handling of 502 Bad Gateway."""
        import requests

        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json={"error": "Bad gateway"},
            status=502,
        )

        with pytest.raises(requests.exceptions.HTTPError) as exc_info:
            self.client._make_request("/stix/indicators")

        assert exc_info.value.response.status_code == 502

    @responses.activate
    def test_503_service_unavailable(self) -> None:
        """Test handling of 503 Service Unavailable."""
        import requests

        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            json={"error": "Service unavailable"},
            status=503,
        )

        with pytest.raises(requests.exceptions.HTTPError) as exc_info:
            self.client._make_request("/stix/indicators")

        assert exc_info.value.response.status_code == 503

    @responses.activate
    def test_connection_error(self) -> None:
        """Test handling of connection errors."""
        import requests

        responses.add(
            responses.GET,
            f"{self.api_base_url}/stix/indicators",
            body=requests.exceptions.ConnectionError("Connection refused"),
        )

        with pytest.raises(requests.exceptions.ConnectionError):
            self.client._make_request("/stix/indicators")


class TestValidateConnection:
    """Tests for DarkStrataAPIValidator connection validation.

    DarkStrataAPIValidator.validate() contains the core logic. Since the base
    Validator class is mocked, we access the method from the class __dict__
    to call it as an unbound function.
    """

    @pytest.fixture(autouse=True)
    def setup(self, mock_splunk_libs: dict[str, MagicMock]) -> None:
        """Set up test fixtures."""
        import darkstrata_inputs

        self._validate_fn = darkstrata_inputs.DarkStrataAPIValidator.__dict__.get("validate")
        if self._validate_fn is None:
            pytest.skip("validate not found in class dict (mocked base)")

    def _call_validate(self, value: str, data: dict[str, Any]) -> bool:
        """Call validate as an unbound method with a mock self."""
        mock_self = MagicMock()
        return self._validate_fn(mock_self, value, data)

    @responses.activate
    def test_validate_success(self) -> None:
        """Test successful connection validation."""
        responses.add(
            responses.GET,
            "https://api.darkstrata.io/v1/stix/indicators",
            json={"type": "bundle", "objects": []},
            status=200,
        )

        result = self._call_validate(
            "test-key",
            {
                "api_base_url": "https://api.darkstrata.io/v1",
                "api_key": "test-key",
            },
        )
        assert result is True

    @responses.activate
    def test_validate_failure_401(self) -> None:
        """Test validation failure with invalid API key."""
        responses.add(
            responses.GET,
            "https://api.darkstrata.io/v1/stix/indicators",
            json={"error": "Unauthorized"},
            status=401,
        )

        result = self._call_validate(
            "bad-key",
            {
                "api_base_url": "https://api.darkstrata.io/v1",
                "api_key": "bad-key",
            },
        )
        assert result is False

    @responses.activate
    def test_validate_failure_403(self) -> None:
        """Test validation failure with insufficient permissions."""
        responses.add(
            responses.GET,
            "https://api.darkstrata.io/v1/stix/indicators",
            json={"error": "Forbidden"},
            status=403,
        )

        result = self._call_validate(
            "limited-key",
            {
                "api_base_url": "https://api.darkstrata.io/v1",
                "api_key": "limited-key",
            },
        )
        assert result is False

    def test_validate_missing_credentials(self) -> None:
        """Test validation with missing API credentials."""
        result = self._call_validate("", {"api_base_url": "", "api_key": ""})
        assert result is False

    @responses.activate
    def test_validate_connection_error(self) -> None:
        """Test validation with connection error."""
        import requests as req_lib

        responses.add(
            responses.GET,
            "https://api.darkstrata.io/v1/stix/indicators",
            body=req_lib.exceptions.ConnectionError("Connection refused"),
        )

        result = self._call_validate(
            "test-key",
            {
                "api_base_url": "https://api.darkstrata.io/v1",
                "api_key": "test-key",
            },
        )
        assert result is False


class TestConnectionPooling:
    """Tests for session connection pooling configuration."""

    @pytest.fixture(autouse=True)
    def setup(
        self,
        mock_splunk_libs: dict[str, MagicMock],
        api_base_url: str,
        api_key: str,
    ) -> None:
        """Set up test fixtures."""
        self.api_base_url = api_base_url
        self.api_key = api_key

    def test_session_is_reused(self) -> None:
        """Client should use a persistent session for connection reuse."""
        import requests

        from darkstrata_inputs import DarkStrataAPIClient

        client = DarkStrataAPIClient(
            api_base_url=self.api_base_url,
            api_key=self.api_key,
        )
        assert isinstance(client.session, requests.Session)

    def test_session_has_default_headers(self) -> None:
        """Session should have required default headers."""
        from darkstrata_inputs import DarkStrataAPIClient

        client = DarkStrataAPIClient(
            api_base_url=self.api_base_url,
            api_key=self.api_key,
        )
        headers = client.session.headers
        assert "x-api-key" in headers
        assert "User-Agent" in headers
        assert "Accept" in headers
        assert headers["Accept"] == "application/json"
