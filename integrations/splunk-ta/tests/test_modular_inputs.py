"""
Tests for the modular-input entry points (darkstrata_alerts.py,
darkstrata_indicators.py).

These modules subclass ``splunklib.modularinput.Script`` and call
``Scheme``/``Argument``/``Event``, none of which can be subclassed or
instantiated when mocked as bare ``MagicMock``. This module installs lightweight
real stub classes for ``splunklib.modularinput`` so the input classes import and
their ``stream_events`` flow can be exercised end-to-end with fake Splunk
plumbing (conf manager, checkpointer, API client, event writer).
"""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "package" / "bin"))


# --- real stub classes for splunklib.modularinput ---------------------------


class _Argument:
    def __init__(self, name: str, title: str | None = None, **kwargs: Any) -> None:
        self.name = name
        self.title = title
        self.kwargs = kwargs


class _Scheme:
    def __init__(self, title: str) -> None:
        self.title = title
        self.description: str | None = None
        self.use_external_validation: bool | None = None
        self.streaming_mode_xml: bool | None = None
        self.use_single_instance: bool | None = None
        self.arguments: list[_Argument] = []

    def add_argument(self, argument: _Argument) -> None:
        self.arguments.append(argument)


class _Event:
    def __init__(
        self,
        data: Any = None,
        time: Any = None,
        index: str | None = None,
        sourcetype: str | None = None,
        **kwargs: Any,
    ) -> None:
        self.data = data
        self.time = time
        self.index = index
        self.sourcetype = sourcetype


class _Script:
    def run(self, argv: list[str]) -> int:  # pragma: no cover - not exercised
        return 0


# --- fake Splunk plumbing ----------------------------------------------------


class _FakeConf:
    def __init__(self, name: str, account_config: dict[str, Any], proxy: dict[str, Any]) -> None:
        self._name = name
        self._account_config = account_config
        self._proxy = proxy

    def get(self, key: str, default: Any = None) -> Any:
        if self._name == "ta_darkstrata_account":
            return self._account_config
        if self._name == "ta_darkstrata_settings":
            return self._proxy
        return default


def _make_conf_manager(account_config: dict[str, Any], proxy: dict[str, Any] | None = None, raises: bool = False):
    class _FakeConfManager:
        def __init__(self, session_key: str, app: str, realm: str | None = None) -> None:
            if raises:
                raise RuntimeError("conf manager unavailable")

        def get_conf(self, name: str) -> _FakeConf:
            return _FakeConf(name, account_config, proxy or {})

    return _FakeConfManager


class _FakeCheckpointer:
    store: dict[str, dict[str, Any]] = {}

    def __init__(self, collection_name: str, session_key: str, app: str) -> None:
        pass

    def get(self, key: str) -> dict[str, Any] | None:
        return _FakeCheckpointer.store.get(key)

    def update(self, key: str, value: dict[str, Any]) -> None:
        _FakeCheckpointer.store[key] = value


class _FakeInputs:
    def __init__(self, name: str, item: dict[str, Any], session_key: str = "sk") -> None:
        self.inputs = {name: item}
        self.metadata = {"session_key": session_key}


@pytest.fixture
def smi_stub(monkeypatch: pytest.MonkeyPatch, mock_splunk_libs: dict[str, MagicMock]) -> types.ModuleType:
    """Install real stub classes for splunklib.modularinput and reset module cache."""
    # Skip the OpenSSL re-exec bootstrap at the top of the input modules.
    monkeypatch.setenv("_DARKSTRATA_SSL_BOOTSTRAPPED", "1")

    smi = types.ModuleType("splunklib.modularinput")
    smi.Argument = _Argument  # type: ignore[attr-defined]
    smi.Scheme = _Scheme  # type: ignore[attr-defined]
    smi.Event = _Event  # type: ignore[attr-defined]
    smi.Script = _Script  # type: ignore[attr-defined]

    splunklib_mod = types.ModuleType("splunklib")
    splunklib_mod.modularinput = smi  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "splunklib", splunklib_mod)
    monkeypatch.setitem(sys.modules, "splunklib.modularinput", smi)

    # Force fresh imports so the input classes bind to the real stubs above.
    for name in ("darkstrata_inputs", "darkstrata_alerts", "darkstrata_indicators"):
        monkeypatch.delitem(sys.modules, name, raising=False)

    _FakeCheckpointer.store = {}
    return smi


def _load(module_name: str):
    return importlib.import_module(module_name)


def _account() -> dict[str, Any]:
    return {"api_base_url": "https://api.darkstrata.io/v1", "api_key": "k"}


def _wire(monkeypatch: pytest.MonkeyPatch, mod: Any, conf_manager_cls: Any, client_factory: Any) -> None:
    monkeypatch.setattr(mod.conf_manager, "ConfManager", conf_manager_cls)
    monkeypatch.setattr(mod.checkpointer, "KVStoreCheckpointer", _FakeCheckpointer)
    monkeypatch.setattr(mod, "DarkStrataAPIClient", client_factory)


# --- scheme + helper coverage (both modules) --------------------------------


@pytest.mark.parametrize(
    ("module", "scheme_name", "expected_args"),
    [
        (
            "darkstrata_alerts",
            "darkstrata_alerts",
            {"name", "account", "detail", "confidence_threshold", "hash_emails"},
        ),
        ("darkstrata_indicators", "darkstrata_indicators", {"name", "account", "confidence_threshold", "hash_emails"}),
    ],
)
def test_get_scheme(smi_stub: Any, module: str, scheme_name: str, expected_args: set[str]) -> None:
    mod = _load(module)
    cls = mod.DarkStrataAlerts if module == "darkstrata_alerts" else mod.DarkStrataIndicators
    scheme = cls().get_scheme()
    assert scheme.title == scheme_name
    assert scheme.use_external_validation is True
    arg_names = {a.name for a in scheme.arguments}
    assert expected_args.issubset(arg_names)


@pytest.mark.parametrize("module", ["darkstrata_alerts", "darkstrata_indicators"])
def test_validate_input_is_noop(smi_stub: Any, module: str) -> None:
    mod = _load(module)
    cls = mod.DarkStrataAlerts if module == "darkstrata_alerts" else mod.DarkStrataIndicators
    assert cls().validate_input(object()) is None


@pytest.mark.parametrize("module", ["darkstrata_alerts", "darkstrata_indicators"])
def test_parse_timestamp(smi_stub: Any, module: str) -> None:
    mod = _load(module)
    assert mod._parse_timestamp(None) is None
    assert mod._parse_timestamp("not-a-date") is None
    assert mod._parse_timestamp("2024-01-15T10:30:00.000Z") == pytest.approx(1705314600.0, abs=1)


# --- stream_events: alerts ---------------------------------------------------


def _alert_bundle() -> dict[str, Any]:
    return {
        "type": "bundle",
        "objects": [
            {"type": "report", "id": "report--1", "published": "2024-01-15T10:30:00.000Z"},
            {
                "type": "observed-data",
                "id": "observed-data--1",
                "created": "2024-01-15T10:00:00.000Z",
                "modified": "2024-01-15T10:05:00.000Z",
            },
        ],
    }


def test_alerts_stream_events_happy_path(smi_stub: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("darkstrata_alerts")

    class FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

        def fetch_alerts(self, **kwargs: Any):
            yield _alert_bundle()

    _wire(monkeypatch, mod, _make_conf_manager(_account()), FakeClient)
    ew = MagicMock()
    inputs = _FakeInputs("darkstrata_alerts://test", {"account": "acct", "index": "main"})

    mod.DarkStrataAlerts().stream_events(inputs, ew)

    # One bundle event + one observed-data event written.
    assert ew.write_event.call_count == 2
    # Checkpoint advanced to the newest observed-data timestamp.
    ckpt = _FakeCheckpointer.store["darkstrata_alerts_darkstrata_alerts://test"]
    assert ckpt["last_sync"] == "2024-01-15T10:05:00.000Z"
    assert ckpt["event_count"] == 1


def test_alerts_stream_events_missing_config_skips(smi_stub: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("darkstrata_alerts")

    class FakeClient:  # pragma: no cover - must never be constructed
        def __init__(self, **kwargs: Any) -> None:
            raise AssertionError("client should not be built without credentials")

    _wire(monkeypatch, mod, _make_conf_manager({}), FakeClient)
    ew = MagicMock()
    inputs = _FakeInputs("darkstrata_alerts://x", {"account": "acct"})

    mod.DarkStrataAlerts().stream_events(inputs, ew)
    ew.write_event.assert_not_called()


def test_alerts_stream_events_conf_error_skips(smi_stub: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("darkstrata_alerts")
    _wire(monkeypatch, mod, _make_conf_manager(_account(), raises=True), MagicMock())
    ew = MagicMock()
    inputs = _FakeInputs("darkstrata_alerts://x", {"account": "acct"})

    mod.DarkStrataAlerts().stream_events(inputs, ew)
    ew.write_event.assert_not_called()


def test_alerts_stream_events_fetch_error_reraises(smi_stub: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("darkstrata_alerts")

    class FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def fetch_alerts(self, **kwargs: Any):
            raise RuntimeError("api down")
            yield  # pragma: no cover

    _wire(monkeypatch, mod, _make_conf_manager(_account()), FakeClient)
    inputs = _FakeInputs("darkstrata_alerts://x", {"account": "acct"})

    with pytest.raises(RuntimeError, match="api down"):
        mod.DarkStrataAlerts().stream_events(inputs, MagicMock())


# --- stream_events: indicators ----------------------------------------------


def _observed_data() -> dict[str, Any]:
    return {
        "type": "observed-data",
        "id": "observed-data--ind-1",
        "created": "2024-01-15T09:00:00.000Z",
        "modified": "2024-01-15T09:30:00.000Z",
    }


def test_indicators_stream_events_happy_path(smi_stub: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("darkstrata_indicators")

    class FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def fetch_indicators(self, **kwargs: Any):
            yield _observed_data()
            yield {"type": "observed-data", "id": "x", "created": "2024-01-15T08:00:00.000Z"}

    _wire(monkeypatch, mod, _make_conf_manager(_account()), FakeClient)
    ew = MagicMock()
    inputs = _FakeInputs("darkstrata_indicators://test", {"account": "acct", "index": "main"})

    mod.DarkStrataIndicators().stream_events(inputs, ew)

    assert ew.write_event.call_count == 2
    ckpt = _FakeCheckpointer.store["darkstrata_indicators_darkstrata_indicators://test"]
    assert ckpt["last_sync"] == "2024-01-15T09:30:00.000Z"
    assert ckpt["event_count"] == 2


def test_indicators_stream_events_fetch_error_reraises(smi_stub: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("darkstrata_indicators")

    class FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def fetch_indicators(self, **kwargs: Any):
            raise RuntimeError("boom")
            yield  # pragma: no cover

    _wire(monkeypatch, mod, _make_conf_manager(_account()), FakeClient)

    with pytest.raises(RuntimeError, match="boom"):
        mod.DarkStrataIndicators().stream_events(
            _FakeInputs("darkstrata_indicators://x", {"account": "acct"}), MagicMock()
        )
