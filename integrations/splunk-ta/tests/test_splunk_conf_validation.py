"""
Tests for Splunk .conf file validation.

Validates all .conf files parse correctly and contain required sections/keys
that are critical for successful deployment.
"""

from __future__ import annotations

import configparser
import json
from pathlib import Path

import pytest

# Path to the package directory
PACKAGE_DIR = Path(__file__).parent.parent / "package"
DEFAULT_DIR = PACKAGE_DIR / "default"


class SplunkConfParser:
    """ConfigParser adapted for Splunk .conf file quirks."""

    @staticmethod
    def parse(conf_path: Path) -> configparser.ConfigParser:
        """Parse a Splunk .conf file, handling Splunk-specific syntax."""
        parser = configparser.ConfigParser(
            interpolation=None,
            strict=False,
            comment_prefixes=("#",),
            inline_comment_prefixes=None,
            allow_no_value=True,
        )
        parser.optionxform = str  # Preserve case

        # Read raw content and handle Splunk-specific patterns
        content = conf_path.read_text()

        # Handle line continuations (backslash-newline)
        content = content.replace("\\\n", " ")

        # Handle empty stanza [] in default.meta -> rename to [default]
        lines = content.splitlines()
        processed_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped == "[]":
                processed_lines.append("[default]")
            else:
                processed_lines.append(line)
        content = "\n".join(processed_lines)

        parser.read_string(content)
        return parser


class TestAllConfFilesParseable:
    """Verify all .conf files under package/default/ are valid INI."""

    def test_all_conf_files_parse(self) -> None:
        """All .conf files must parse without errors."""
        conf_files = list(DEFAULT_DIR.glob("*.conf"))
        assert len(conf_files) > 0, "No .conf files found in package/default/"

        errors: list[str] = []
        for conf_file in conf_files:
            try:
                SplunkConfParser.parse(conf_file)
            except configparser.Error as e:
                errors.append(f"{conf_file.name}: {e}")

        assert not errors, "Conf file parse errors:\n" + "\n".join(errors)


class TestAppConf:
    """Validate app.conf has required sections and keys."""

    @pytest.fixture
    def app_conf(self) -> configparser.ConfigParser:
        return SplunkConfParser.parse(DEFAULT_DIR / "app.conf")

    def test_install_section_exists(self, app_conf: configparser.ConfigParser) -> None:
        assert app_conf.has_section("install"), "app.conf missing [install] section"

    def test_ui_section_exists(self, app_conf: configparser.ConfigParser) -> None:
        assert app_conf.has_section("ui"), "app.conf missing [ui] section"

    def test_launcher_section_exists(self, app_conf: configparser.ConfigParser) -> None:
        assert app_conf.has_section("launcher"), "app.conf missing [launcher] section"

    def test_package_section_exists(self, app_conf: configparser.ConfigParser) -> None:
        assert app_conf.has_section("package"), "app.conf missing [package] section"

    def test_package_has_id(self, app_conf: configparser.ConfigParser) -> None:
        assert app_conf.has_option("package", "id"), "app.conf [package] missing 'id'"

    def test_launcher_has_version(self, app_conf: configparser.ConfigParser) -> None:
        assert app_conf.has_option("launcher", "version"), "app.conf [launcher] missing 'version'"

    def test_ui_has_label(self, app_conf: configparser.ConfigParser) -> None:
        assert app_conf.has_option("ui", "label"), "app.conf [ui] missing 'label'"


class TestPropsConf:
    """Validate props.conf stanzas have required time parsing keys."""

    @pytest.fixture
    def props_conf(self) -> configparser.ConfigParser:
        return SplunkConfParser.parse(DEFAULT_DIR / "props.conf")

    def test_stanzas_reference_valid_sourcetypes(self, props_conf: configparser.ConfigParser) -> None:
        """All stanzas should be valid sourcetype names."""
        for section in props_conf.sections():
            # Stanza names should be non-empty
            assert len(section) > 0, "Empty stanza name in props.conf"

    def test_stanzas_have_time_parsing_keys(self, props_conf: configparser.ConfigParser) -> None:
        """Sourcetype stanzas should have TIME_FORMAT for time parsing."""
        for section in props_conf.sections():
            assert props_conf.has_option(section, "TIME_FORMAT"), f"props.conf [{section}] missing TIME_FORMAT"

    def test_stanzas_have_line_breaking(self, props_conf: configparser.ConfigParser) -> None:
        """Sourcetype stanzas should define SHOULD_LINEMERGE."""
        for section in props_conf.sections():
            assert props_conf.has_option(section, "SHOULD_LINEMERGE"), (
                f"props.conf [{section}] missing SHOULD_LINEMERGE"
            )


class TestTransformsConf:
    """Validate transforms.conf lookup stanzas reference existing files."""

    @pytest.fixture
    def transforms_conf(self) -> configparser.ConfigParser:
        return SplunkConfParser.parse(DEFAULT_DIR / "transforms.conf")

    def test_lookup_filenames_exist(self, transforms_conf: configparser.ConfigParser) -> None:
        """Lookup stanzas must reference files that exist in package/lookups/."""
        lookups_dir = PACKAGE_DIR / "lookups"
        for section in transforms_conf.sections():
            if transforms_conf.has_option(section, "filename"):
                filename = transforms_conf.get(section, "filename")
                lookup_file = lookups_dir / filename
                assert lookup_file.exists(), f"transforms.conf [{section}] references missing lookup: {filename}"

    def test_regex_stanzas_have_format(self, transforms_conf: configparser.ConfigParser) -> None:
        """REGEX stanzas must have a FORMAT key."""
        for section in transforms_conf.sections():
            if transforms_conf.has_option(section, "REGEX"):
                assert transforms_conf.has_option(section, "FORMAT"), (
                    f"transforms.conf [{section}] has REGEX but no FORMAT"
                )


class TestCollectionsConf:
    """Validate collections.conf stanzas."""

    @pytest.fixture
    def collections_conf(self) -> configparser.ConfigParser:
        return SplunkConfParser.parse(DEFAULT_DIR / "collections.conf")

    def test_enforced_type_collections_have_fields(self, collections_conf: configparser.ConfigParser) -> None:
        """Collections with enforceTypes=true must have field.* entries."""
        for section in collections_conf.sections():
            if collections_conf.get(section, "enforceTypes", fallback="false") == "true":
                field_entries = [k for k in collections_conf.options(section) if k.startswith("field.")]
                assert len(field_entries) > 0, (
                    f"collections.conf [{section}] has enforceTypes=true but no field.* entries"
                )


class TestAlertActionsConf:
    """Validate alert_actions.conf stanzas."""

    @pytest.fixture
    def alert_actions_conf(self) -> configparser.ConfigParser:
        return SplunkConfParser.parse(DEFAULT_DIR / "alert_actions.conf")

    def test_cam_is_valid_json(self, alert_actions_conf: configparser.ConfigParser) -> None:
        """param._cam values must be valid JSON."""
        for section in alert_actions_conf.sections():
            if alert_actions_conf.has_option(section, "param._cam"):
                cam_value = alert_actions_conf.get(section, "param._cam")
                try:
                    json.loads(cam_value)
                except json.JSONDecodeError as e:
                    pytest.fail(f"alert_actions.conf [{section}] param._cam is invalid JSON: {e}")

    def test_required_keys_present(self, alert_actions_conf: configparser.ConfigParser) -> None:
        """Alert action stanzas must have required keys."""
        required_keys = ["is_custom", "label", "description", "payload_format"]
        for section in alert_actions_conf.sections():
            for key in required_keys:
                assert alert_actions_conf.has_option(section, key), (
                    f"alert_actions.conf [{section}] missing required key: {key}"
                )

    def test_cam_key_present(self, alert_actions_conf: configparser.ConfigParser) -> None:
        """Alert action stanzas must have param._cam."""
        for section in alert_actions_conf.sections():
            assert alert_actions_conf.has_option(section, "param._cam"), (
                f"alert_actions.conf [{section}] missing param._cam"
            )


class TestEventtypesConf:
    """Validate eventtypes.conf stanzas."""

    @pytest.fixture
    def eventtypes_conf(self) -> configparser.ConfigParser:
        return SplunkConfParser.parse(DEFAULT_DIR / "eventtypes.conf")

    def test_all_stanzas_have_search(self, eventtypes_conf: configparser.ConfigParser) -> None:
        """All event type stanzas must have non-empty search definitions."""
        for section in eventtypes_conf.sections():
            assert eventtypes_conf.has_option(section, "search"), f"eventtypes.conf [{section}] missing 'search' key"
            search_val = eventtypes_conf.get(section, "search").strip()
            assert len(search_val) > 0, f"eventtypes.conf [{section}] has empty search definition"


class TestTagsConf:
    """Validate tags.conf stanza names reference existing event types."""

    def test_tags_reference_existing_eventtypes(self) -> None:
        """Tags stanza names must reference event types in eventtypes.conf."""
        tags_conf = SplunkConfParser.parse(DEFAULT_DIR / "tags.conf")
        eventtypes_conf = SplunkConfParser.parse(DEFAULT_DIR / "eventtypes.conf")

        eventtype_names = set(eventtypes_conf.sections())

        for section in tags_conf.sections():
            # Tags stanza format: eventtype=<name>
            if section.startswith("eventtype="):
                eventtype_name = section.split("=", 1)[1]
                assert eventtype_name in eventtype_names, (
                    f"tags.conf references non-existent eventtype: {eventtype_name}"
                )


class TestMacrosConf:
    """Validate macros.conf stanzas."""

    @pytest.fixture
    def macros_conf(self) -> configparser.ConfigParser:
        return SplunkConfParser.parse(DEFAULT_DIR / "macros.conf")

    def test_all_macros_have_definition(self, macros_conf: configparser.ConfigParser) -> None:
        """All macro stanzas must have non-empty definition keys."""
        for section in macros_conf.sections():
            assert macros_conf.has_option(section, "definition"), f"macros.conf [{section}] missing 'definition' key"
            definition = macros_conf.get(section, "definition").strip()
            assert len(definition) > 0, f"macros.conf [{section}] has empty definition"


class TestSavedSearchesConf:
    """Validate savedsearches.conf stanzas."""

    @pytest.fixture
    def savedsearches_conf(self) -> configparser.ConfigParser:
        return SplunkConfParser.parse(DEFAULT_DIR / "savedsearches.conf")

    def test_all_searches_have_search_key(self, savedsearches_conf: configparser.ConfigParser) -> None:
        """All saved search stanzas must have non-empty search keys."""
        for section in savedsearches_conf.sections():
            assert savedsearches_conf.has_option(section, "search"), (
                f"savedsearches.conf [{section}] missing 'search' key"
            )
            search_val = savedsearches_conf.get(section, "search").strip()
            assert len(search_val) > 0, f"savedsearches.conf [{section}] has empty search"

    def test_search_quotes_balanced(self, savedsearches_conf: configparser.ConfigParser) -> None:
        """Search values should have balanced double quotes."""
        for section in savedsearches_conf.sections():
            if savedsearches_conf.has_option(section, "search"):
                search = savedsearches_conf.get(section, "search")
                quote_count = search.count('"')
                assert quote_count % 2 == 0, (
                    f"savedsearches.conf [{section}] has unbalanced quotes ({quote_count} double quotes)"
                )
