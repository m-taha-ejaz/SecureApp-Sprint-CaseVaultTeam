"""INTENTIONALLY VULNERABLE demonstration snippets. LOCAL TRAINING ONLY.

No network listener is started. The functions must never be imported by secureapp.
"""
import subprocess


def command_injection_example(user_filename: str) -> str:
    # CWE-78: user content becomes shell syntax. Innocuous marker only.
    result = subprocess.run(f"printf 'Checking: %s\\n' {user_filename}",
                            shell=True, capture_output=True, text=True)
    return result.stdout


def command_injection_fix(user_filename: str) -> str:
    # No shell: input is an argument, never interpreted as command syntax.
    result = subprocess.run(["printf", "Checking: %s\\n", user_filename],
                            shell=False, capture_output=True, text=True)
    return result.stdout


def legacy_idor_lookup(connection, file_id: int):
    # CWE-639: omits owner/share authorization; for isolated test database only.
    return connection.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()


def legacy_csrf_accepts_action(has_token: bool) -> bool:
    # CWE-352: sensitive operation succeeds without checking a CSRF token.
    return True


def legacy_clickjacking_headers() -> dict:
    # CWE-1021: no frame restriction set.
    return {"Content-Type": "text/html"}
