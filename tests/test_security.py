import re
from .conftest import csrf, create_user, login, upload


def test_health_and_headers(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_registration_and_session_cookie(client):
    response = create_user(client, "alice")
    assert response.status_code == 303
    cookie = response.headers["set-cookie"]
    assert "httponly" in cookie.lower()
    assert "samesite=strict" in cookie.lower()
    assert "alice" in client.get("/dashboard").text


def test_invalid_registration_rejected(client):
    token = csrf(client)
    result = client.post("/register", data={"username": "a!", "password": "short", "csrf_token": token})
    assert "Username: 3-24" in result.text


def test_csrf_blocks_forged_registration(client):
    response = client.post("/register", data={"username": "mallory", "password": "Secret123456"})
    assert response.status_code == 403


def test_csrf_blocks_forged_upload(client):
    create_user(client, "alice")
    response = client.post("/files", files={"upload_file": ("a.txt", b"test")})
    assert response.status_code == 403


def test_csrf_blocks_mismatched_token(client):
    create_user(client, "alice")
    response = client.post("/logout", data={"csrf_token": "forged-token"})
    assert response.status_code == 403


def test_csrf_blocks_cross_origin_even_with_token(client):
    create_user(client, "alice")
    token = csrf(client, "/dashboard")
    response = client.post("/logout", data={"csrf_token": token}, headers={"Origin": "https://evil.example"})
    assert response.status_code == 403


def test_upload_and_download_owner(client):
    create_user(client, "alice")
    assert upload(client).status_code == 303
    response = client.get("/files/1/download")
    assert response.status_code == 200
    assert response.content == b"Safe document"
    assert response.headers["content-type"] == "application/octet-stream"


def test_idor_denied_to_other_user(client, app):
    create_user(client, "alice")
    upload(client, "secret.txt", b"ALICE PRIVATE")
    csrf_token = csrf(client, "/dashboard")
    client.post("/logout", data={"csrf_token": csrf_token})
    create_user(client, "bobuser")
    denied = client.get("/files/1/download")
    assert denied.status_code == 404
    assert b"ALICE PRIVATE" not in denied.content


def test_sharing_grants_only_explicit_access(client):
    create_user(client, "alice")
    upload(client, "report.txt", b"Shared intentionally")
    token = csrf(client, "/dashboard")
    client.post("/logout", data={"csrf_token": token})
    create_user(client, "bobuser")
    token = csrf(client, "/dashboard")
    client.post("/logout", data={"csrf_token": token})
    login(client, "alice")
    token = csrf(client, "/dashboard")
    shared = client.post("/files/1/share", data={"csrf_token": token, "target_username": "bobuser"}, follow_redirects=False)
    assert shared.status_code == 303
    token = csrf(client, "/dashboard")
    client.post("/logout", data={"csrf_token": token})
    login(client, "bobuser")
    result = client.get("/files/1/download")
    assert result.status_code == 200 and result.content == b"Shared intentionally"


def test_non_owner_cannot_share_or_delete(client):
    create_user(client, "alice")
    upload(client)
    client.post("/logout", data={"csrf_token": csrf(client, "/dashboard")})
    create_user(client, "bobuser")
    token = csrf(client, "/dashboard")
    assert client.post("/files/1/share", data={"csrf_token": token, "target_username": "alice"}).status_code == 404
    assert client.post("/files/1/delete", data={"csrf_token": token}).status_code == 404


def test_command_injection_filename_rejected(client):
    create_user(client, "alice")
    response = upload(client, "x;echo_BAD.txt")
    assert response.status_code == 400


def test_directory_traversal_filename_rejected(client):
    create_user(client, "alice")
    assert upload(client, "../../etc/passwd").status_code == 400


def test_native_buffer_limit_rejected(client):
    create_user(client, "alice")
    assert upload(client, "X" * 65 + ".txt").status_code == 400


def test_excessive_file_size_rejected(client):
    create_user(client, "alice")
    assert upload(client, "big.txt", b"X" * (2*1024*1024+1)).status_code == 413


def test_logout_requires_token(client):
    create_user(client, "alice")
    assert client.post("/logout").status_code == 403
    assert client.post("/logout", data={"csrf_token": csrf(client, "/dashboard")}, follow_redirects=False).status_code == 303


def test_clickjacking_protection_on_sensitive_dashboard(client):
    create_user(client, "alice")
    page = client.get("/dashboard")
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert page.headers["x-frame-options"] == "DENY"


def test_unauthed_download_not_permitted(client):
    result = client.get("/files/1/download")
    assert result.status_code == 401


def test_login_bad_credentials(client):
    create_user(client, "alice")
    token = csrf(client, "/dashboard")
    client.post("/logout", data={"csrf_token": token})
    result = client.post("/login", data={"username":"alice", "password":"wrongpassword", "csrf_token":csrf(client, "/login")})
    assert result.status_code == 200
    assert "Invalid login details" in result.text


def test_bad_username_sql_expression_rejected(client):
    token = csrf(client)
    response = client.post("/register", data={"username": "a' OR 1=1 --", "password": "a sufficiently long pass", "csrf_token": token})
    assert "Username: 3-24" in response.text


def test_download_forced_octet_stream_not_executable_html(client):
    create_user(client, "alice")
    assert upload(client, "index.html", b"<script>alert(1)</script>").status_code == 303
    response = client.get("/files/1/download")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/octet-stream"
    assert "attachment" in response.headers["content-disposition"]


def test_sensitive_pages_disable_caching(client):
    create_user(client, "alice")
    response = client.get("/dashboard")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_csrf_blocks_owner_delete_without_token(client):
    create_user(client, "alice")
    upload(client)
    assert client.post("/files/1/delete").status_code == 403
    assert client.get("/files/1/download").status_code == 200


def test_valid_owner_delete_revokes_access(client):
    create_user(client, "alice")
    upload(client)
    token = csrf(client, "/dashboard")
    assert client.post("/files/1/delete", data={"csrf_token": token}, follow_redirects=False).status_code == 303
    assert client.get("/files/1/download").status_code == 404
