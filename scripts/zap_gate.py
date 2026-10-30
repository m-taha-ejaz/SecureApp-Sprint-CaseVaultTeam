"""Fails CI if ZAP JSON records a high-severity alert on secured app.
ZAP baseline is mostly passive; this is defense in depth, not full DAST proof.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path


def count_high(path: str) -> int:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    alerts = [alert for site in document.get("site", []) for alert in site.get("alerts", [])]
    high = [a for a in alerts if str(a.get("riskcode", "0")) == "3" or
            str(a.get("riskdesc", "")).lower().startswith("high")]
    print(f"ZAP alerts: {len(alerts)}, high-severity alerts: {len(high)}")
    for alert in high:
        print(f"BLOCKED: {alert.get('name', 'unknown')} [{alert.get('riskdesc', '')}]")
    return len(high)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python scripts/zap_gate.py path/to/zap-after.json")
    sys.exit(1 if count_high(sys.argv[1]) else 0)
