"""
Supplementary tests for the adaptive-response base class and action wrappers.

Covers the credential-loading path (`get_account_config`), the transport error
branches of `make_api_request` (including the TLS-verified session), and the
required-parameter validation in each action's `execute()`.
"""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests
import responses

# Splunk libs are mocked at module import time (mirrors test_adaptive_response).
sys.modules.setdefault("import_declare_test", MagicMock())
sys.modules.setdefault("solnlib", MagicMock())
sys.modules.setdefault("solnlib.conf_manager", MagicMock())
sys.modules.setdefault("solnlib.log", MagicMock())

import darkstrata_action_base as base_mod  # noqa: E402
from darkstrata_action_base import (  # noqa: E402
    DarkStrataActionBase,
    DarkStrataActionError,
    TLS12Adapter,
)

API_BASE = "https://api.darkstrata.io/v1"


class ConcreteAction(DarkStrataActionBase):
    def execute(self, params: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover - unused
        return {}


# --- fake conf manager -------------------------------------------------------


class _FakeConfObj:
    def __init__(self, record: Any) -> None:
        self._record = record

    def get(self, name: str, only_current_app: bool = False) -> Any:
        return self._record


def _fake_conf_manager(account_record: Any, proxy_record: Any, raises: bool = False):
    class _FakeConfManager:
        def __init__(self, session_key: str, app: str, realm: str | None = None) -> None:
            if raises:
                raise RuntimeError("no conf")

        def get_conf(self, name: str) -> _FakeConfObj:
            if name == "ta_darkstrata_account":
                return _FakeConfObj(account_record)
            return _FakeConfObj(proxy_record)

    return _FakeConfManager


@pytest.fixture
def action() -> ConcreteAction:
    return ConcreteAction(session_key="sk")


# --- get_account_config ------------------------------------------------------


def test_get_account_config_success(action: ConcreteAction, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        base_mod,
        "conf_manager",
        MagicMock(ConfManager=_fake_conf_manager({"api_base_url": API_BASE + "/", "api_key": "k"}, {})),
    )
    config = action.get_account_config("acct")
    assert config["api_base_url"] == API_BASE  # trailing slash stripped
    assert config["api_key"] == "k"
    assert config["proxy_settings"] is None


def test_get_account_config_is_cached(action: ConcreteAction, monkeypatch: pytest.MonkeyPatch) -> None:
    cfm = MagicMock(ConfManager=_fake_conf_manager({"api_base_url": API_BASE, "api_key": "k"}, {}))
    monkeypatch.setattr(base_mod, "conf_manager", cfm)
    first = action.get_account_config("acct")
    # Swap the conf manager out; a cached lookup must not rebuild from it.
    monkeypatch.setattr(base_mod, "conf_manager", MagicMock(side_effect=AssertionError("should be cached")))
    assert action.get_account_config("acct") is first


def test_get_account_config_with_proxy(action: ConcreteAction, monkeypatch: pytest.MonkeyPatch) -> None:
    proxy = {"proxy_enabled": "1", "proxy_type": "https", "proxy_url": "p.example.com", "proxy_port": "8080"}
    monkeypatch.setattr(
        base_mod,
        "conf_manager",
        MagicMock(ConfManager=_fake_conf_manager({"api_base_url": API_BASE, "api_key": "k"}, proxy)),
    )
    config = action.get_account_config("acct")
    assert config["proxy_settings"]["proxy_enabled"] is True
    assert config["proxy_settings"]["proxy_url"] == "p.example.com"


def test_get_account_config_not_found_raises(action: ConcreteAction, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base_mod, "conf_manager", MagicMock(ConfManager=_fake_conf_manager(None, {})))
    with pytest.raises(DarkStrataActionError, match="not found"):
        action.get_account_config("missing")


def test_get_account_config_conf_error_raises(action: ConcreteAction, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base_mod, "conf_manager", MagicMock(ConfManager=_fake_conf_manager({}, {}, raises=True)))
    with pytest.raises(DarkStrataActionError, match="Failed to get account configuration"):
        action.get_account_config("acct")


# --- make_api_request transport / TLS ---------------------------------------


def _config() -> dict[str, Any]:
    return {"api_base_url": API_BASE, "api_key": "k", "proxy_settings": None}


def test_make_api_request_mounts_tls_adapter(action: ConcreteAction, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    real_session_cls = requests.Session

    class SpySession(real_session_cls):  # type: ignore[misc, valid-type]
        def mount(self, prefix: str, adapter: Any) -> None:
            captured[prefix] = adapter
            super().mount(prefix, adapter)

    monkeypatch.setattr(base_mod.requests, "Session", SpySession)
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, f"{API_BASE}/alerts/1", json={"id": "1"}, status=200)
        action.make_api_request(_config(), "GET", "/alerts/1")

    # HTTPS traffic must go through the TLS 1.2+ adapter, never verify=False.
    assert isinstance(captured["https://"], TLS12Adapter)


def test_make_api_request_unsupported_method(action: ConcreteAction) -> None:
    with pytest.raises(DarkStrataActionError, match="Unsupported HTTP method"):
        action.make_api_request(_config(), "OPTIONS", "/alerts/1")


@responses.activate
def test_make_api_request_500(action: ConcreteAction) -> None:
    responses.add(responses.GET, f"{API_BASE}/alerts/1", body="boom", status=500)
    with pytest.raises(DarkStrataActionError) as exc:
        action.make_api_request(_config(), "GET", "/alerts/1")
    assert exc.value.status_code == 500


@responses.activate
def test_make_api_request_timeout(action: ConcreteAction) -> None:
    responses.add(responses.GET, f"{API_BASE}/alerts/1", body=requests.exceptions.Timeout())
    with pytest.raises(DarkStrataActionError, match="timed out"):
        action.make_api_request(_config(), "GET", "/alerts/1")


@responses.activate
def test_make_api_request_connection_error(action: ConcreteAction) -> None:
    responses.add(responses.GET, f"{API_BASE}/alerts/1", body=requests.exceptions.ConnectionError())
    with pytest.raises(DarkStrataActionError, match="Request failed"):
        action.make_api_request(_config(), "GET", "/alerts/1")


@responses.activate
def test_make_api_request_put_and_delete(action: ConcreteAction) -> None:
    responses.add(responses.PUT, f"{API_BASE}/alerts/1", json={"id": "1"}, status=200)
    responses.add(responses.DELETE, f"{API_BASE}/alerts/1", body="", status=204)
    assert action.make_api_request(_config(), "PUT", "/alerts/1", data={"x": 1})["id"] == "1"
    assert action.make_api_request(_config(), "DELETE", "/alerts/1") == {}


# --- action wrapper validation ----------------------------------------------


@pytest.mark.parametrize(
    ("module", "cls_name"),
    [
        ("darkstrata_close_alert", "CloseAlertAction"),
        ("darkstrata_reopen_alert", "ReopenAlertAction"),
        ("darkstrata_get_alert_details", "GetAlertDetailsAction"),
    ],
)
def test_action_requires_account_and_alert_id(module: str, cls_name: str) -> None:
    mod = __import__(module)
    cls = getattr(mod, cls_name)
    action = cls(session_key="sk")
    with pytest.raises(DarkStrataActionError, match="Account name is required"):
        action.execute({"alert_id": "a1"})
    with pytest.raises(DarkStrataActionError, match="Alert ID is required"):
        action.execute({"account": "acct"})
