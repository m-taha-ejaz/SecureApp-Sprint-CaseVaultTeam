"""Offline, controlled before/after proof for the five mandatory weaknesses.

Run from project root after `sh scripts/build_native.sh` and pip install.
Produces evidence/DEMO_RESULTS.txt. Only benign markers are used.
"""
from __future__ import annotations
import contextlib
import io
import re
import sqlite3
import subprocess
import tempfile
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from fastapi.testclient import TestClient
from lab.unsafe_examples import (command_injection_example, command_injection_fix,
                                  legacy_idor_lookup, legacy_csrf_accepts_action,
                                  legacy_clickjacking_headers)
from secureapp import create_app

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence"
EVIDENCE.mkdir(exist_ok=True)


def get_token(client, path):
    m = re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).text)
    assert m
    return m.group(1)


def register(client, who):
    r = client.post("/register", data={"username": who, "password": "DemonstrationPass123",
                                       "csrf_token": get_token(client, "/register")}, follow_redirects=False)
    assert r.status_code == 303


def run():
    lines = ["CYC386 CaseVault - Actual local execution evidence", "=" * 65,
             "No production exploit or external target involved."]
    def log(text):
        lines.append(text)
        print(text)

    # 1) Memory corruption: ASAN catches the legacy copy; secure C helper rejects it.
    with tempfile.TemporaryDirectory() as td:
        unsafe_bin = Path(td) / "legacy"
        cmd = ["cc", "-std=c11", "-fno-omit-frame-pointer", "-fsanitize=address", "-O0", "-g",
               str(ROOT / "lab/legacy_filename.c"), "-o", str(unsafe_bin)]
        subprocess.run(cmd, check=True, capture_output=True)
        payload = "A" * 96
        vulnerable = subprocess.run([str(unsafe_bin), payload], capture_output=True, text=True)
        secure = subprocess.run([str(ROOT / "bin/safe_filename"), payload], capture_output=True, text=True)
        assert vulnerable.returncode != 0 and secure.returncode != 0
        log(f"[1/5] BUFFER OVERFLOW: legacy ASAN exit={vulnerable.returncode} (detected); secure validator exit={secure.returncode} (rejected) PASS")
        (EVIDENCE / "BUFFER_ASAN_EXCERPT.txt").write_text(
            "Legacy execution:\n" + vulnerable.stderr[:2800] + "\nSecured validator:\n" + secure.stderr,
            encoding="utf-8")

    # 2) Command injection: only a harmless printed marker is permitted.
    supplied = "document.txt; printf 'LAB_INJECTION_MARKER\\n'"
    before = command_injection_example(supplied)
    after = command_injection_fix(supplied)
    assert "LAB_INJECTION_MARKER\n" in before and "LAB_INJECTION_MARKER\n" not in after
    log("[2/5] COMMAND INJECTION: vulnerable interpreted shell separator; secure passes literal argument PASS")

    # 3) Actual IDOR contrast with two user sessions on disposable database.
    with tempfile.TemporaryDirectory() as td:
        app = create_app(database=Path(td)/"db.sqlite", storage=Path(td)/"uploads",
                         validator=ROOT/"bin/safe_filename", testing=True)
        with TestClient(app) as alice:
            register(alice, "alice")
            token = get_token(alice, "/dashboard")
            r = alice.post("/files", data={"csrf_token": token},
                           files={"upload_file": ("owner.txt", b"ALICE SECRET")}, follow_redirects=False)
            assert r.status_code == 303
            with TestClient(app) as bob:
                register(bob, "bobuser")
                with app.state.db() as conn:
                    leaked_row = legacy_idor_lookup(conn, 1)
                blocked = bob.get("/files/1/download")
                assert leaked_row is not None and blocked.status_code == 404
                log(f"[3/5] IDOR: legacy ownerless lookup finds file 1; secure Bob GET /files/1/download = {blocked.status_code} PASS")

                # 4) CSRF: legacy permitted unauthenticated state change; secure rejects.
                rejected = bob.post("/logout")
                assert legacy_csrf_accepts_action(False) and rejected.status_code == 403
                log(f"[4/5] CSRF: legacy accepts missing token; secure POST /logout = {rejected.status_code} PASS")

                # 5) Clickjacking: legacy lacks frame defense; app returns both headers.
                headers = bob.get("/dashboard").headers
                assert "X-Frame-Options" not in legacy_clickjacking_headers()
                assert headers["x-frame-options"] == "DENY"
                assert "frame-ancestors 'none'" in headers["content-security-policy"]
                log("[5/5] CLICKJACKING: legacy has no restrictions; secure CSP frame-ancestors 'none' + X-Frame-Options DENY PASS")

    output = "\n".join(lines) + "\n"
    (EVIDENCE / "DEMO_RESULTS.txt").write_text(output, encoding="utf-8")
    log("Evidence written: evidence/DEMO_RESULTS.txt and evidence/BUFFER_ASAN_EXCERPT.txt")


if __name__ == "__main__":
    run()
