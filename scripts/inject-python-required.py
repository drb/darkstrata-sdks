#!/usr/bin/env python3
"""
Inject `python.required` into ucc-gen-generated conf files.

Usage: python3 scripts/inject-python-required.py <built-ta-dir>
       (e.g. integrations/splunk-ta/output/TA-darkstrata)

ucc-gen emits the deprecated `python.version = python3` in the generated
inputs.conf and restmap.conf. As of Splunk Enterprise 10.2 that option is
deprecated in favour of `python.required`, and AppInspect's cloud profile flags
its absence as a future failure. ucc-gen does not yet emit `python.required`, so
this post-build step adds it next to every existing `python.version` line.

The hand-authored alert_actions.conf already declares `python.required` directly
and is not generated, so it is left untouched.

Idempotent: re-running makes no further changes. AppInspect accepts the values
"3.9" and "3.13"; we declare both ("3.9,3.13") so the add-on stays compatible
with older Splunk (Python 3.9) while declaring forward compatibility with Python
3.13. Splunk uses the latest listed version that is available, and AppInspect
only treats the absence of the latest value (3.13) as a future failure.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PYTHON_REQUIRED_VALUE = "3.9,3.13"
TARGET_CONF_FILES = ("inputs.conf", "restmap.conf")

_STANZA_RE = re.compile(r"^\[.*\]\s*$")
_PY_VERSION_RE = re.compile(r"^python\.version\s*=")
_PY_REQUIRED_RE = re.compile(r"^python\.required\s*=")


def _patch_conf(path: Path) -> bool:
    """Add python.required after each python.version line in stanzas lacking it.

    Returns True if the file was modified.
    """
    lines = path.read_text().splitlines()

    # Identify, per stanza, whether python.required is already declared.
    stanza_has_required: dict[int, bool] = {}
    current = -1
    for line in lines:
        if _STANZA_RE.match(line):
            current += 1
            stanza_has_required[current] = False
        elif _PY_REQUIRED_RE.match(line):
            stanza_has_required[current] = True

    out: list[str] = []
    current = -1
    changed = False
    for line in lines:
        out.append(line)
        if _STANZA_RE.match(line):
            current += 1
        elif _PY_VERSION_RE.match(line) and not stanza_has_required.get(current, False):
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}python.required = {PYTHON_REQUIRED_VALUE}")
            changed = True

    if changed:
        path.write_text("\n".join(out) + "\n")
    return changed


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    ta_dir = Path(sys.argv[1])
    default_dir = ta_dir / "default"
    if not default_dir.is_dir():
        print(f"ERROR: {default_dir} not found - is this a built TA directory?")
        return 2

    any_patched = False
    for conf_name in TARGET_CONF_FILES:
        conf_path = default_dir / conf_name
        if not conf_path.is_file():
            continue
        if _patch_conf(conf_path):
            print(f"Injected python.required = {PYTHON_REQUIRED_VALUE} into {conf_path}")
            any_patched = True
        else:
            print(f"No change needed for {conf_path}")

    if not any_patched:
        print("No conf files required patching.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
