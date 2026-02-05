#!/usr/bin/env python3
"""
Check AppInspect validation results.

Usage: python3 scripts/check-appinspect.py <results-json-path>

Parses AppInspect JSON output and exits non-zero if there are failures or errors.
Used by both splunk-ta-ci.yml and splunk-ta-release.yml workflows.
"""

import json
import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/check-appinspect.py <results-json-path>", file=sys.stderr)
        sys.exit(2)

    results_path = sys.argv[1]

    with open(results_path, "r") as f:
        results = json.load(f)

    summary = results.get("summary", {})
    failures = summary.get("failure", 0)
    errors = summary.get("error", 0)
    warnings = summary.get("warning", 0)
    passed = summary.get("success", 0)
    skipped = summary.get("skipped", 0)

    print("AppInspect Results:")
    print(f"  Failures: {failures}")
    print(f"  Errors: {errors}")
    print(f"  Warnings: {warnings}")
    print(f"  Passed: {passed}")
    print(f"  Skipped: {skipped}")

    if failures > 0 or errors > 0:
        print("\nAppInspect validation failed!")
        for report in results.get("reports", []):
            for group in report.get("groups", []):
                for check in group.get("checks", []):
                    if check.get("result") in ("failure", "error"):
                        print(f"\n{check.get('name')}:")
                        for msg in check.get("messages", []):
                            print(f"  - {msg.get('message')}")
        sys.exit(1)
    else:
        print("\nAppInspect validation passed!")


if __name__ == "__main__":
    main()
