"""Fail CI on Semgrep rules with metadata.security_severity high/critical.
Fixture mode proves the policy without shipping vulnerabilities in production code.
"""
import json
import sys
from pathlib import Path


def check(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = []
    for hit in data.get("results", []):
        extra = hit.get("extra", {})
        sev = str(extra.get("metadata", {}).get("security_severity", "")).lower()
        if sev in ("high", "critical"):
            rows.append((hit.get("check_id", "unknown"), sev, hit.get("path", "")))
    for rule_id, severity, target in rows:
        print(f"BLOCKED {severity}: {rule_id} in {target}")
    print(f"Security gate: {len(rows)} high/critical finding(s)")
    return 1 if rows else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python scripts/critical_gate.py reports/semgrep.json")
        sys.exit(2)
    sys.exit(check(sys.argv[1]))
