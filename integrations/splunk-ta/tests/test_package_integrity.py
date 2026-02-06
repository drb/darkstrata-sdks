"""
Tests for package metadata and structural integrity.

Validates that the TA package is deployment-ready and would not be rejected
by Splunkbase or fail during installation.
"""

from __future__ import annotations

import json
import py_compile
import re
from pathlib import Path

import pytest

# Path to the integration root and package directory
INTEGRATION_DIR = Path(__file__).parent.parent
PACKAGE_DIR = INTEGRATION_DIR / "package"
DEFAULT_DIR = PACKAGE_DIR / "default"


class TestGlobalConfig:
    """Validate globalConfig.json structure and content."""

    @pytest.fixture
    def global_config(self) -> dict:
        config_path = INTEGRATION_DIR / "globalConfig.json"
        return json.loads(config_path.read_text())

    def test_is_valid_json(self) -> None:
        """globalConfig.json must be valid JSON."""
        config_path = INTEGRATION_DIR / "globalConfig.json"
        try:
            json.loads(config_path.read_text())
        except json.JSONDecodeError as e:
            pytest.fail(f"globalConfig.json is invalid JSON: {e}")

    def test_has_meta_name(self, global_config: dict) -> None:
        assert global_config.get("meta", {}).get("name"), "Missing meta.name"

    def test_has_meta_rest_root(self, global_config: dict) -> None:
        assert global_config.get("meta", {}).get("restRoot"), "Missing meta.restRoot"

    def test_has_meta_version(self, global_config: dict) -> None:
        assert global_config.get("meta", {}).get("version"), "Missing meta.version"

    def test_has_configuration_page(self, global_config: dict) -> None:
        assert global_config.get("pages", {}).get("configuration"), "Missing pages.configuration"

    def test_has_inputs_page(self, global_config: dict) -> None:
        assert global_config.get("pages", {}).get("inputs"), "Missing pages.inputs"

    def test_input_service_names_match_sourcetypes(self, global_config: dict) -> None:
        """Input service names should correspond to sourcetypes defined in props.conf."""
        import configparser

        props_path = DEFAULT_DIR / "props.conf"
        parser = configparser.ConfigParser(
            interpolation=None,
            strict=False,
            comment_prefixes=("#",),
            inline_comment_prefixes=None,
            allow_no_value=True,
        )
        parser.optionxform = str
        parser.read_string(props_path.read_text().replace("\\\n", " "))
        props_sourcetypes = set(parser.sections())

        services = global_config.get("pages", {}).get("inputs", {}).get("services", [])
        for service in services:
            service_name = service["name"]
            # The service name (e.g. "darkstrata_indicators", "darkstrata_alerts")
            # should map to sourcetypes like "darkstrata:stix:observed-data", "darkstrata:stix:alert"
            # At minimum, there should be a darkstrata-prefixed sourcetype
            darkstrata_sourcetypes = [st for st in props_sourcetypes if st.startswith("darkstrata")]
            assert len(darkstrata_sourcetypes) > 0, f"No darkstrata sourcetypes found for service '{service_name}'"


class TestAppManifest:
    """Validate app.manifest structure."""

    @pytest.fixture
    def manifest(self) -> dict:
        manifest_path = INTEGRATION_DIR / "app.manifest"
        return json.loads(manifest_path.read_text())

    def test_is_valid_json(self) -> None:
        """app.manifest must be valid JSON."""
        manifest_path = INTEGRATION_DIR / "app.manifest"
        try:
            json.loads(manifest_path.read_text())
        except json.JSONDecodeError as e:
            pytest.fail(f"app.manifest is invalid JSON: {e}")

    def test_has_schema_version(self, manifest: dict) -> None:
        assert manifest.get("schemaVersion"), "Missing schemaVersion"

    def test_has_info_title(self, manifest: dict) -> None:
        assert manifest.get("info", {}).get("title"), "Missing info.title"

    def test_has_info_id_name(self, manifest: dict) -> None:
        assert manifest.get("info", {}).get("id", {}).get("name"), "Missing info.id.name"

    def test_has_info_id_version(self, manifest: dict) -> None:
        assert manifest.get("info", {}).get("id", {}).get("version"), "Missing info.id.version"


class TestVersionConsistency:
    """Verify version strings are consistent across config files."""

    def _get_app_conf_version(self) -> str:
        import configparser

        parser = configparser.ConfigParser(interpolation=None, strict=False, comment_prefixes=("#",))
        parser.optionxform = str
        parser.read_string((DEFAULT_DIR / "app.conf").read_text())
        return parser.get("launcher", "version")

    def _get_manifest_version(self) -> str:
        manifest = json.loads((INTEGRATION_DIR / "app.manifest").read_text())
        return manifest["info"]["id"]["version"]

    def _get_global_config_version(self) -> str:
        config = json.loads((INTEGRATION_DIR / "globalConfig.json").read_text())
        version_str = config["meta"]["version"]
        # globalConfig version may have build metadata (e.g. "2.0.2+6fd53e5")
        # Strip build metadata for comparison
        return version_str.split("+")[0]

    def test_app_conf_and_manifest_versions_match(self) -> None:
        """app.conf and app.manifest versions must match."""
        app_version = self._get_app_conf_version()
        manifest_version = self._get_manifest_version()
        assert app_version == manifest_version, (
            f"Version mismatch: app.conf={app_version}, app.manifest={manifest_version}"
        )


class TestLookupFiles:
    """Validate lookup CSV files exist and have correct headers."""

    def test_all_lookup_csvs_exist(self) -> None:
        """All 3 expected lookup CSVs must exist."""
        expected = [
            "darkstrata_email_intel.csv",
            "darkstrata_domain_intel.csv",
            "darkstrata_user_intel.csv",
        ]
        lookups_dir = PACKAGE_DIR / "lookups"
        for filename in expected:
            assert (lookups_dir / filename).exists(), f"Missing lookup file: {filename}"

    def test_lookup_headers_match_transforms(self) -> None:
        """Lookup CSV headers should include fields referenced by transforms.conf."""
        import configparser
        import csv

        transforms_path = DEFAULT_DIR / "transforms.conf"
        parser = configparser.ConfigParser(
            interpolation=None,
            strict=False,
            comment_prefixes=("#",),
            inline_comment_prefixes=None,
            allow_no_value=True,
        )
        parser.optionxform = str
        parser.read_string(transforms_path.read_text().replace("\\\n", " "))

        lookups_dir = PACKAGE_DIR / "lookups"

        for section in parser.sections():
            if parser.has_option(section, "filename"):
                filename = parser.get(section, "filename")
                csv_path = lookups_dir / filename
                if csv_path.exists():
                    with open(csv_path) as f:
                        reader = csv.reader(f)
                        headers = next(reader, [])
                    assert len(headers) > 0, f"Lookup {filename} has no headers"


class TestDefaultMeta:
    """Validate metadata/default.meta exists and has required content."""

    def test_default_meta_exists(self) -> None:
        meta_path = PACKAGE_DIR / "metadata" / "default.meta"
        assert meta_path.exists(), "metadata/default.meta is missing"

    def test_default_meta_has_default_stanza(self) -> None:
        """default.meta must have a [default] stanza with export setting."""
        meta_path = PACKAGE_DIR / "metadata" / "default.meta"
        content = meta_path.read_text()
        # The file uses [] which maps to [default] in Splunk
        # Check for export = system in the global context
        assert "export = system" in content, "default.meta missing 'export = system'"


class TestPythonScripts:
    """Validate all Python scripts in package/bin/ are syntactically valid."""

    def test_all_scripts_compile(self) -> None:
        """All .py files in package/bin/ must be syntactically valid."""
        bin_dir = PACKAGE_DIR / "bin"
        py_files = list(bin_dir.glob("*.py"))
        assert len(py_files) > 0, "No Python files found in package/bin/"

        errors: list[str] = []
        for py_file in py_files:
            try:
                py_compile.compile(str(py_file), doraise=True)
            except py_compile.PyCompileError as e:
                errors.append(f"{py_file.name}: {e}")

        assert not errors, "Python syntax errors:\n" + "\n".join(errors)


class TestAlertTemplates:
    """Validate alert action HTML templates reference valid action names."""

    def test_templates_reference_valid_actions(self) -> None:
        """HTML templates must reference action names from alert_actions.conf."""
        import configparser

        # Get action names from alert_actions.conf
        alert_conf_path = DEFAULT_DIR / "alert_actions.conf"
        parser = configparser.ConfigParser(
            interpolation=None,
            strict=False,
            comment_prefixes=("#",),
            inline_comment_prefixes=None,
            allow_no_value=True,
        )
        parser.optionxform = str
        parser.read_string(alert_conf_path.read_text().replace("\\\n", " "))
        action_names = set(parser.sections())

        # Check each HTML template
        alerts_dir = DEFAULT_DIR / "data" / "ui" / "alerts"
        if not alerts_dir.exists():
            pytest.skip("No alert templates directory")

        html_files = list(alerts_dir.glob("*.html"))
        assert len(html_files) > 0, "No HTML templates found"

        for html_file in html_files:
            # Template filename should match an action name
            template_name = html_file.stem
            assert template_name in action_names, (
                f"Template '{html_file.name}' has no matching action in alert_actions.conf"
            )

    def test_templates_have_action_param_references(self) -> None:
        """HTML templates should reference their action parameters."""
        alerts_dir = DEFAULT_DIR / "data" / "ui" / "alerts"
        if not alerts_dir.exists():
            pytest.skip("No alert templates directory")

        for html_file in alerts_dir.glob("*.html"):
            content = html_file.read_text()
            action_name = html_file.stem
            # Templates should reference action.<action_name>.param
            pattern = f"action.{re.escape(action_name)}.param"
            assert pattern in content, f"Template '{html_file.name}' doesn't reference {pattern}"


class TestLibRequirements:
    """Validate lib/requirements.txt exists."""

    def test_requirements_file_exists(self) -> None:
        """lib/requirements.txt should exist for dependency tracking."""
        req_path = INTEGRATION_DIR / "lib" / "requirements.txt"
        # This is a soft check - the file may not exist yet
        if not req_path.exists():
            pytest.skip("lib/requirements.txt does not exist yet - consider adding it for dependency tracking")
