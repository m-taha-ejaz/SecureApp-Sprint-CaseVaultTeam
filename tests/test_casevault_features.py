import hashlib
import sqlite3
from .conftest import csrf,create_user,login,upload


def test_sha256_digest_and_audit(client, app):
    create_user(client, "investigator1")
    assert upload(client,"incident_log.txt", b"CASEVAULT LAB LOG").status_code == 303
    page=client.get("/dashboard")
    assert hashlib.sha256(b"CASEVAULT LAB LOG").hexdigest()[:16] in page.text
    assert "UPLOAD" in page.text
    assert client.get("/files/1/download").status_code==200
    assert "DOWNLOAD" in client.get("/dashboard").text


def test_download_refuses_modified_file(client, app):
    create_user(client,"investigator1")
    upload(client,"incident_log.txt",b"genuine")
    with app.state.db() as conn:
        file=conn.execute("SELECT stored_name FROM files WHERE id=1").fetchone()
    (app.state.storage/file["stored_name"]).write_bytes(b"tampered")
    assert client.get("/files/1/download").status_code==409


def test_owner_can_revoke_access(client, app):
    create_user(client,"investigator1")
    upload(client,"incident_log.txt", b"private")
    client.post("/logout",data={"csrf_token":csrf(client,"/dashboard")})
    create_user(client,"analyst2")
    client.post("/logout",data={"csrf_token":csrf(client,"/dashboard")})
    login(client,"investigator1")
    token=csrf(client,"/dashboard")
    assert client.post("/files/1/share",data={"csrf_token":token,"target_username":"analyst2"},follow_redirects=False).status_code==303
    client.post("/logout",data={"csrf_token":csrf(client,"/dashboard")})
    login(client,"analyst2")
    assert client.get("/files/1/download").status_code==200
    client.post("/logout",data={"csrf_token":csrf(client,"/dashboard")})
    login(client,"investigator1")
    assert client.post("/files/1/revoke",data={"csrf_token":csrf(client,"/dashboard"),"target_username":"analyst2"},follow_redirects=False).status_code==303
    client.post("/logout",data={"csrf_token":csrf(client,"/dashboard")})
    login(client,"analyst2")
    assert client.get("/files/1/download").status_code==404


def test_nonowner_cannot_revoke(client):
    create_user(client,"investigator1")
    upload(client)
    client.post("/logout",data={"csrf_token":csrf(client,"/dashboard")})
    create_user(client,"analyst2")
    assert client.post("/files/1/revoke",data={"csrf_token":csrf(client,"/dashboard"),"target_username":"investigator1"}).status_code==404


def test_revoke_requires_csrf(client):
    create_user(client,"investigator1")
    upload(client)
    assert client.post("/files/1/revoke",data={"target_username":"analyst2"}).status_code==403
