"""CaseVault: security-first incident evidence exchange service.

The production app contains no deliberately vulnerable routes. Vulnerable
examples are isolated under lab/ for offline, controlled teaching exercises.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import subprocess
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent.parent
MAX_UPLOAD = 2 * 1024 * 1024
USERNAME = re.compile(r"^[a-zA-Z0-9_]{3,24}$")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    value = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256$310000${salt.hex()}${value.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256" or int(iterations) != 310_000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


def create_app(*, database: str | Path | None = None,
               storage: str | Path | None = None,
               validator: str | Path | None = None,
               secret: str | None = None,
               testing: bool = False) -> FastAPI:
    instance = BASE_DIR / "instance"
    db_path = Path(database) if database is not None else instance / "casevault.db"
    storage_path = Path(storage) if storage is not None else instance / "uploads"
    binary = Path(validator) if validator is not None else BASE_DIR / "bin" / "safe_filename"
    app_secret = secret or os.getenv("APP_SECRET", "")
    if not app_secret or app_secret == "REPLACE_WITH_RANDOM_SECRET":
        if testing:
            app_secret = "test-only-secret-never-deploy"
        else:
            raise RuntimeError("Set APP_SECRET to a long random secret in .env before starting")
    if not testing and not binary.is_file():
        raise RuntimeError("Native validator missing: run scripts/build_native.sh or Docker build")
    db_path.parent.mkdir(parents=True, exist_ok=True)
    storage_path.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def db() -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL,
            original_name TEXT NOT NULL, stored_name TEXT NOT NULL UNIQUE,
            byte_size INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS shares (
            file_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            PRIMARY KEY(file_id, user_id),
            FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER NOT NULL,
            file_id INTEGER,
            action TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(actor_id) REFERENCES users(id)
        );
        """)

    app = FastAPI(title="CaseVault", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db = db
    app.state.validator = binary
    app.state.storage = storage_path
    app.add_middleware(SessionMiddleware, secret_key=app_secret,
                       session_cookie="casevault_session",
                       same_site="strict", https_only=os.getenv("SESSION_SECURE", "false").lower() == "true",
                       max_age=60 * 60)
    app.mount("/static", StaticFiles(directory=BASE_DIR / "secureapp" / "static"), name="static")
    templates = Jinja2Templates(directory=BASE_DIR / "secureapp" / "templates")

    @app.middleware("http")
    async def protective_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def csrf_for(request: Request) -> str:
        if "csrf" not in request.session:
            request.session["csrf"] = secrets.token_urlsafe(32)
        return request.session["csrf"]

    def require_csrf(request: Request, sent: str | None) -> None:
        token = request.session.get("csrf", "")
        if not sent or not token or not hmac.compare_digest(token, sent):
            raise HTTPException(status_code=403, detail="CSRF validation failed")
        # Defense-in-depth; absent Origin is permitted for older clients, token still required.
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") != str(request.base_url).rstrip("/"):
            raise HTTPException(status_code=403, detail="Cross-origin request denied")

    def current_user(request: Request) -> sqlite3.Row | None:
        uid = request.session.get("uid")
        if not isinstance(uid, int):
            return None
        with db() as conn:
            return conn.execute("SELECT id, username FROM users WHERE id=?", (uid,)).fetchone()

    def login_required(request: Request) -> sqlite3.Row:
        user = current_user(request)
        if user is None:
            raise HTTPException(status_code=401, detail="Log in required")
        return user

    def render(request: Request, template: str, *, error: str = "", **context) -> HTMLResponse:
        return templates.TemplateResponse(request, template, {
            "user": current_user(request), "csrf": csrf_for(request), "error": error, **context
        })

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/")
    async def home(request: Request):
        return RedirectResponse("/dashboard" if current_user(request) else "/login", status_code=303)

    @app.get("/register", response_class=HTMLResponse)
    async def register_form(request: Request):
        return render(request, "register.html")

    @app.post("/register")
    async def register(request: Request, username: str = Form(""), password: str = Form(""), csrf_token: str = Form("")):
        require_csrf(request, csrf_token)
        if not USERNAME.fullmatch(username) or len(password) < 10 or len(password) > 128:
            return render(request, "register.html", error="Username: 3-24 letters/numbers/_; password: 10-128 characters.")
        with db() as conn:
            try:
                cursor = conn.execute("INSERT INTO users(username,password_hash) VALUES(?,?)", (username, hash_password(password)))
            except sqlite3.IntegrityError:
                return render(request, "register.html", error="Username already taken.")
        request.session.clear()
        request.session["uid"] = cursor.lastrowid
        csrf_for(request)
        return RedirectResponse("/dashboard", status_code=303)

    @app.get("/login", response_class=HTMLResponse)
    async def login_form(request: Request):
        return render(request, "login.html")

    @app.post("/login")
    async def login(request: Request, username: str = Form(""), password: str = Form(""), csrf_token: str = Form("")):
        require_csrf(request, csrf_token)
        with db() as conn:
            row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if row is None or not verify_password(password, row["password_hash"]):
            return render(request, "login.html", error="Invalid login details.")
        request.session.clear()
        request.session["uid"] = row["id"]
        csrf_for(request)
        return RedirectResponse("/dashboard", status_code=303)

    @app.post("/logout")
    async def logout(request: Request, csrf_token: str = Form("")):
        require_csrf(request, csrf_token)
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request):
        user = current_user(request)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        with db() as conn:
            owned = conn.execute("SELECT f.*,u.username AS owner FROM files f JOIN users u ON u.id=f.owner_id WHERE f.owner_id=? ORDER BY f.id DESC", (user["id"],)).fetchall()
            shared = conn.execute("SELECT f.*,u.username AS owner FROM files f JOIN users u ON u.id=f.owner_id JOIN shares s ON s.file_id=f.id WHERE s.user_id=? AND f.owner_id!=? ORDER BY f.id DESC", (user["id"], user["id"])).fetchall()
            audit = conn.execute("""SELECT action,file_id,details,occurred_at FROM audit_events
                WHERE actor_id=? ORDER BY id DESC LIMIT 12""", (user["id"],)).fetchall()
        return render(request, "dashboard.html", owned=owned, shared=shared, audit=audit)

    @app.post("/files")
    async def upload(request: Request, upload_file: UploadFile = File(...), csrf_token: str = Form("")):
        user = login_required(request)
        require_csrf(request, csrf_token)
        name = upload_file.filename or ""
        if not binary.exists():
            raise HTTPException(503, "Native validator unavailable")
        try:
            validation = subprocess.run([str(binary), name], shell=False, text=True,
                                        capture_output=True, timeout=3, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise HTTPException(503, "Filename validation service unavailable")
        if validation.returncode != 0:
            raise HTTPException(400, "Invalid filename: use letters, digits, dots, underscore or hyphen; max 64")
        payload = await upload_file.read(MAX_UPLOAD + 1)
        if len(payload) == 0 or len(payload) > MAX_UPLOAD:
            raise HTTPException(413, "File must be between 1 byte and 2 MiB")
        stored_name = uuid.uuid4().hex
        path = storage_path / stored_name
        with path.open("xb") as out:
            out.write(payload)
        try:
            with db() as conn:
                digest = hashlib.sha256(payload).hexdigest()
                cursor = conn.execute("INSERT INTO files(owner_id,original_name,stored_name,byte_size,sha256) VALUES(?,?,?,?,?)", (user["id"], name, stored_name, len(payload), digest))
                conn.execute("INSERT INTO audit_events(actor_id,file_id,action,details) VALUES(?,?,?,?)",
                             (user["id"], cursor.lastrowid, "UPLOAD", name))
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return RedirectResponse("/dashboard", status_code=303)

    @app.get("/files/{file_id}/download")
    async def download(request: Request, file_id: int):
        user = login_required(request)
        with db() as conn:
            row = conn.execute("""SELECT f.* FROM files f WHERE f.id=? AND
                (f.owner_id=? OR EXISTS (SELECT 1 FROM shares s WHERE s.file_id=f.id AND s.user_id=?))""",
                (file_id, user["id"], user["id"])).fetchone()
        if row is None:
            raise HTTPException(404, "File not found")
        path = storage_path / row["stored_name"]
        if not path.is_file():
            raise HTTPException(404, "Content unavailable")
        # Detect evidence corruption before serving bytes. Keep filename server-controlled.
        if hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:
            raise HTTPException(409, "Evidence integrity verification failed")
        with db() as conn:
            conn.execute("INSERT INTO audit_events(actor_id,file_id,action,details) VALUES(?,?,?,?)",
                         (user["id"], file_id, "DOWNLOAD", row["original_name"]))
        return FileResponse(path, filename=row["original_name"], media_type="application/octet-stream")

    @app.post("/files/{file_id}/share")
    async def share(request: Request, file_id: int, target_username: str = Form(""), csrf_token: str = Form("")):
        user = login_required(request)
        require_csrf(request, csrf_token)
        with db() as conn:
            owned = conn.execute("SELECT id FROM files WHERE id=? AND owner_id=?", (file_id, user["id"])).fetchone()
            recipient = conn.execute("SELECT id FROM users WHERE username=?", (target_username,)).fetchone()
            if owned is None:
                raise HTTPException(404, "File not found")
            if recipient is None or recipient["id"] == user["id"]:
                raise HTTPException(400, "Select a different, existing user")
            conn.execute("INSERT OR IGNORE INTO shares(file_id,user_id) VALUES(?,?)", (file_id, recipient["id"]))
            conn.execute("INSERT INTO audit_events(actor_id,file_id,action,details) VALUES(?,?,?,?)",
                         (user["id"], file_id, "SHARE", target_username))
        return RedirectResponse("/dashboard", status_code=303)

    @app.post("/files/{file_id}/revoke")
    async def revoke(request: Request, file_id: int, target_username: str = Form(""), csrf_token: str = Form("")):
        user = login_required(request)
        require_csrf(request, csrf_token)
        with db() as conn:
            owned = conn.execute("SELECT id FROM files WHERE id=? AND owner_id=?", (file_id, user["id"])).fetchone()
            if owned is None:
                raise HTTPException(404, "File not found")
            recipient = conn.execute("SELECT id FROM users WHERE username=?", (target_username,)).fetchone()
            if recipient is None:
                raise HTTPException(400, "Unknown user")
            conn.execute("DELETE FROM shares WHERE file_id=? AND user_id=?", (file_id, recipient["id"]))
            conn.execute("INSERT INTO audit_events(actor_id,file_id,action,details) VALUES(?,?,?,?)",
                         (user["id"], file_id, "REVOKE", target_username))
        return RedirectResponse("/dashboard", status_code=303)

    @app.post("/files/{file_id}/delete")
    async def delete(request: Request, file_id: int, csrf_token: str = Form("")):
        user = login_required(request)
        require_csrf(request, csrf_token)
        with db() as conn:
            owned = conn.execute("SELECT stored_name FROM files WHERE id=? AND owner_id=?", (file_id, user["id"])).fetchone()
            if owned is None:
                raise HTTPException(404, "File not found")
            conn.execute("INSERT INTO audit_events(actor_id,file_id,action,details) VALUES(?,?,?,?)",
                         (user["id"], file_id, "DELETE", owned["stored_name"]))
            conn.execute("DELETE FROM files WHERE id=? AND owner_id=?", (file_id, user["id"]))
        (storage_path / owned["stored_name"]).unlink(missing_ok=True)
        return RedirectResponse("/dashboard", status_code=303)

    return app
