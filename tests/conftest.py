import re
import subprocess
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from secureapp import create_app

ROOT = Path(__file__).resolve().parent.parent

@pytest.fixture(scope="session")
def native_validator(tmp_path_factory):
    out = tmp_path_factory.mktemp("binary") / "safe_filename"
    subprocess.run(["cc", "-std=c11", "-D_DEFAULT_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(ROOT / "native/safe_filename.c"), "-o", str(out)], check=True)
    return out

@pytest.fixture
def app(tmp_path, native_validator):
    return create_app(database=tmp_path / "app.sqlite3", storage=tmp_path / "uploads",
                      validator=native_validator, testing=True)

@pytest.fixture
def client(app):
    with TestClient(app) as testclient:
        yield testclient


def csrf(client, path="/register"):
    page = client.get(path)
    found = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert found is not None, f"CSRF token missing in {path}"
    return found.group(1)


def create_user(client, username):
    token = csrf(client)
    return client.post("/register", data={"username": username, "password": "CorrectHorseBattery123", "csrf_token": token}, follow_redirects=False)


def login(client, username):
    token = csrf(client, "/login")
    return client.post("/login", data={"username": username, "password": "CorrectHorseBattery123", "csrf_token": token}, follow_redirects=False)


def upload(client, filename="sample.txt", body=b"Safe document"):
    token = csrf(client, "/dashboard")
    return client.post("/files", data={"csrf_token": token}, files={"upload_file": (filename, body, "text/plain")}, follow_redirects=False)
