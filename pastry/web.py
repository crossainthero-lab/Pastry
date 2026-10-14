"""FastAPI application: server-rendered shell, JSON API and security middleware."""

from __future__ import annotations

import base64
import hmac
import json
import secrets
import logging
import math
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import auth as authmod
from . import crypto, package
from .auth import AuthFile
from .config import Settings
from .db import SCHEMA_VERSION, Store
from . import release as releasemod
from .package import AFTER_OPEN_SECONDS, MAX_ABSOLUTE_SECONDS
from .ratelimit import SqlRateLimiter
from .release import ReleaseError, ReleaseService
from .sessions import Session, SessionStore
from .vault import Vault, VaultError

log = logging.getLogger("pastry")

HERE = Path(__file__).resolve().parent
MAX_IMPORT_CHARS = 20 * 1024 * 1024

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    # same-origin (not no-referrer): with no-referrer, browsers send "Origin: null" on
    # same-origin form posts, which the origin check would then refuse.
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}

NO_CACHE = {"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache", "Expires": "0"}

ERROR_STATUS = {
    "not_found": 404,
    "locked": 423,
    "not_locked": 409,
    "already_locked": 409,
    "conflict": 409,
    "bad_password": 403,  # 403, not 401: the JS treats 401 as an expired session
    "bad_passphrase": 400,
    "invalid": 422,
    "corrupt": 500,
}


# ----- request models ----------------------------------------------------


class NotAuthenticated(Exception):
    pass


class FieldIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    value: str = Field(default="", max_length=5000)
    secret: bool = False


class EntryIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(default="", max_length=2000)
    category: str = Field(default="", max_length=100)
    favourite: bool = False
    username: str = Field(default="", max_length=500)
    password: str = Field(default="", max_length=5000)
    notes: str = Field(default="", max_length=10000)
    fields: list[FieldIn] = Field(default_factory=list, max_length=200)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Entry name is required.")
        return value

    @field_validator("category")
    @classmethod
    def _category(cls, value: str) -> str:
        return value.strip()

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        value = value.strip()
        if value and not value.lower().startswith(("https://", "http://")):
            raise ValueError("URL must start with http:// or https://")
        return value


class CreateEntryIn(EntryIn):
    separate_password: str | None = None

    @field_validator("separate_password")
    @classmethod
    def _separate(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if len(value) < authmod.MIN_PASSWORD_LEN or len(value) > authmod.MAX_PASSWORD_LEN:
            raise ValueError(
                f"The separate password must be {authmod.MIN_PASSWORD_LEN} to "
                f"{authmod.MAX_PASSWORD_LEN} characters."
            )
        return value


class PasswordIn(BaseModel):
    password: str = Field(min_length=1, max_length=authmod.MAX_PASSWORD_LEN)


class NewPasswordIn(BaseModel):
    password: str = Field(min_length=authmod.MIN_PASSWORD_LEN, max_length=authmod.MAX_PASSWORD_LEN)


class SettingsIn(BaseModel):
    session_timeout_minutes: int = Field(ge=1, le=120)


class PassphraseIn(BaseModel):
    passphrase: str = Field(min_length=authmod.MIN_PASSWORD_LEN, max_length=authmod.MAX_PASSWORD_LEN)


class ImportIn(BaseModel):
    passphrase: str = Field(min_length=1, max_length=authmod.MAX_PASSWORD_LEN)
    data: str = Field(min_length=2, max_length=MAX_IMPORT_CHARS)


def _meta_of(body: EntryIn) -> dict:
    return {"name": body.name, "url": body.url, "category": body.category, "favourite": body.favourite}


def _content_of(body: EntryIn) -> dict:
    return {
        "username": body.username,
        "password": body.password,
        "notes": body.notes,
        "fields": [field.model_dump() for field in body.fields],
    }


class PasswordChangeIn(BaseModel):
    current: str = Field(min_length=1, max_length=authmod.MAX_PASSWORD_LEN)
    new: str = Field(min_length=authmod.MIN_PASSWORD_LEN, max_length=authmod.MAX_PASSWORD_LEN)


class PackageCreateIn(BaseModel):
    entry_ids: list[int] = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=12, max_length=256)
    allow_copy: bool = True
    policy: str = Field(max_length=20)  # after_open | absolute | one_time
    duration_minutes: int | None = Field(default=None, ge=1, le=43200)
    absolute_minutes: int | None = Field(default=None, ge=1, le=43200)


class ReleaseBody(BaseModel):
    capability: str = Field(min_length=43, max_length=43)
    nonce: str = Field(default="", max_length=128)
    proof: str = Field(default="", max_length=128)


class PackageExportIn(BaseModel):
    entry_ids: list[int] = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=12, max_length=256)
    allow_copy: bool = True
    access: str = Field(default="offline", max_length=20)
    expires_in_minutes: int | None = Field(default=None, ge=1, le=43200)


# ----- shared application state -------------------------------------------


class AuthCache:
    """Reloads config/auth.json only when the file changes (checked per request)."""

    def __init__(self, path: Path):
        self.path = path
        self._signature: tuple | None = None
        self._auth: AuthFile | None = None
        self._lock = threading.Lock()

    def get(self) -> AuthFile | None:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return None
        signature = (st.st_ino, st.st_mtime_ns, st.st_size)
        with self._lock:
            if signature != self._signature:
                try:
                    self._auth = authmod.read_auth(self.path)
                except authmod.AuthError:
                    self._auth = None
                self._signature = signature
            return self._auth


class AppContext:
    def __init__(self, settings: Settings, clock: Callable[[], float], wall_clock: Callable[[], float]):
        self.settings = settings
        self.wall_clock = wall_clock
        self._release: ReleaseService | None = None
        self.store = Store(settings.db_path)
        self.auth = AuthCache(settings.auth_path)
        self.cookie_name = "__Host-pastry_session" if settings.cookie_secure else "pastry_session"
        self._schema_ok = False

        idle_minutes = settings.session_timeout_minutes
        if settings.db_path.exists():
            try:
                idle_minutes = int(self.store.get_setting("session_timeout_minutes", str(idle_minutes)))
            except (sqlite3.Error, ValueError):
                pass
        self.sessions = SessionStore(
            idle_seconds=idle_minutes * 60,
            max_seconds=settings.session_max_hours * 3600,
            clock=clock,
        )
        # Persisted in SQLite so lockouts survive restarts. Wall-clock time is used for storage.
        self.login_limiter = SqlRateLimiter(
            self.store, settings.login_max_failures, 900, settings.login_lockout_minutes * 60, wall_clock,
        )
        self.entry_limiter = SqlRateLimiter(
            self.store, settings.entry_max_failures, 600, settings.entry_lockout_minutes * 60, wall_clock,
        )
        # Release API limits: failed proofs per capability, and request volume per client address.
        self.release_fail_limiter = SqlRateLimiter(self.store, 5, 900, 900, wall_clock)
        self.release_request_limiter = SqlRateLimiter(self.store, 30, 60, 60, wall_clock)

    def release_service(self) -> ReleaseService:
        """Created on first use, so installations without server-enforced packages never create release.key."""
        if self._release is None:
            kek = releasemod.load_or_create_kek(self.settings.release_key_path)
            self._release = ReleaseService(self.store, kek, self.wall_clock)
        return self._release

    def require_schema(self) -> None:
        """Refuse to serve a database that is not the current schema (for example before migration)."""
        if self._schema_ok:
            return
        if not self.settings.db_path.exists():
            raise HTTPException(503, "Pastry is not set up yet. Run: pastry setup")
        version = self.store.schema_version()
        if version != SCHEMA_VERSION:
            raise HTTPException(503, f"The vault is schema v{version}. Stop Pastry and run: pastry migrate")
        self._schema_ok = True

    def idle_seconds(self) -> float:
        return self.settings.entry_idle_minutes * 60

    def vault(self, session: Session) -> Vault:
        return Vault(self.store, session.dek, self.settings.kdf)


def _client_ip(request: Request) -> str:
    # Deliberately the socket peer only. X-Forwarded-For and similar headers are
    # client-controlled and are never trusted for rate limiting.
    return request.client.host if request.client else "unknown"


def _same_origin(request: Request, ctx: AppContext) -> bool:
    """Reject cross-site requests (Fetch Metadata and Origin checks)."""
    site = request.headers.get("sec-fetch-site")
    if site is not None and site not in ("same-origin", "none"):
        return False
    origin = request.headers.get("origin")
    if origin is None:
        return True
    if origin in ctx.settings.allowed_origins:
        return True
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    host = request.headers.get("host", "")
    return parsed.scheme in ("http", "https") and parsed.netloc.lower() == host.lower()


def _minutes_from(seconds: int) -> int:
    return max(1, math.ceil(seconds / 60))


def _latest_backup(settings: Settings) -> dict:
    files = sorted(settings.backup_dir.glob("pastry-backup-*.tar.gz")) if settings.backup_dir.exists() else []
    if not files:
        return {"latest": None, "count": 0}
    newest = files[-1]
    return {
        "latest": newest.name,
        "latest_at": datetime.fromtimestamp(newest.stat().st_mtime, timezone.utc).isoformat(timespec="seconds"),
        "count": len(files),
    }


# ----- application factory -------------------------------------------------


def create_app(
    settings: Settings,
    clock: Callable[[], float] = time.monotonic,
    wall_clock: Callable[[], float] = time.time,
) -> FastAPI:
    ctx = AppContext(settings, clock, wall_clock)
    templates = Jinja2Templates(directory=str(HERE / "templates"))

    app = FastAPI(title="Pastry", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.ctx = ctx
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

    @app.middleware("http")
    async def secure_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if settings.cookie_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        response.headers.update(NO_CACHE)
        return response

    # ----- error handling -----

    @app.exception_handler(NotAuthenticated)
    async def _not_authenticated(request: Request, exc: NotAuthenticated):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "Not signed in."}, status_code=401)
        return RedirectResponse("/login?reason=expired", status_code=303)

    @app.exception_handler(VaultError)
    async def _vault_error(request: Request, exc: VaultError):
        return JSONResponse({"detail": exc.message, "code": exc.code}, status_code=ERROR_STATUS.get(exc.code, 400))

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError):
        messages = [str(err.get("msg", "")) for err in exc.errors()][:3]
        detail = "; ".join(m.removeprefix("Value error, ") for m in messages if m) or "Invalid input."
        return JSONResponse({"detail": detail}, status_code=422)

    # ----- dependencies -----

    def current_session(request: Request, touch: bool = True) -> Session:
        ctx.require_schema()
        auth = ctx.auth.get()
        token = request.cookies.get(ctx.cookie_name)
        if auth is None or not token:
            raise NotAuthenticated()
        session = ctx.sessions.get(token, epoch=auth.session_epoch, touch=touch)
        if session is None:
            raise NotAuthenticated()
        return session

    def require_session(request: Request) -> Session:
        return current_session(request, touch=True)

    def require_write(request: Request) -> Session:
        if not _same_origin(request, ctx):
            raise HTTPException(403, "Cross-site request refused.")
        session = current_session(request, touch=True)
        supplied = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(supplied.encode(), session.csrf.encode()):
            raise HTTPException(403, "Missing or invalid CSRF token. Reload the page.")
        return session

    def entry_keys(session: Session, entry_id: int | None = None, touch: bool = False) -> dict[int, bytearray]:
        """Keys for entries still unlocked. Expires idle ones. `touch` marks entry_id as used now."""
        now = ctx.sessions.now()
        if entry_id is not None:
            key = session.key_for(entry_id, now, ctx.idle_seconds(), touch=touch)
            return {} if key is None else {entry_id: key}
        return session.keys_map(now, ctx.idle_seconds())

    # ----- pages -----

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        try:
            session = current_session(request)
        except NotAuthenticated:
            return RedirectResponse("/login", status_code=303)
        return templates.TemplateResponse(request, "app.html", {"csrf": session.csrf, "username": session.username})

    def _login_page(request: Request, status: int, error: str = "", notice: str = "", username: str = ""):
        return templates.TemplateResponse(
            request, "login.html", {"error": error, "notice": notice, "username": username}, status_code=status
        )

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, reason: str = Query(default="", max_length=20)):
        try:
            current_session(request)
            return RedirectResponse("/", status_code=303)
        except NotAuthenticated:
            pass
        notices = {
            "expired": "Your session ended after a period of inactivity.",
            "password": "Your password was changed. Sign in with the new password.",
        }
        notice = notices.get(reason, "")
        return _login_page(request, 200, notice=notice)

    @app.post("/login", response_class=HTMLResponse)
    def login(
        request: Request,
        username: str = Form(default="", max_length=200),
        password: str = Form(default="", max_length=512),
    ):
        if not _same_origin(request, ctx):
            return _login_page(request, 403, error="Request refused.")
        try:
            ctx.require_schema()
        except HTTPException as exc:
            return _login_page(request, 503, error=str(exc.detail))
        username = username.strip()
        ip_key = f"login-ip:{_client_ip(request)}"
        user_key = f"login-user:{username.lower()}"
        retry = max(ctx.login_limiter.blocked_for(ip_key), ctx.login_limiter.blocked_for(user_key))
        if retry:
            return _login_page(
                request, 429,
                error=f"Too many failed attempts. Try again in {_minutes_from(retry)} minute(s).",
                username=username,
            )

        auth = ctx.auth.get()
        if auth is None:
            return _login_page(request, 503, error="Pastry is not set up yet. Run: pastry setup")

        dek = authmod.try_unlock(auth, password)
        user_ok = hmac.compare_digest(username.encode(), auth.username.encode())
        if dek is None or not user_ok:
            crypto.wipe(dek)
            ctx.login_limiter.record_failure(ip_key)
            ctx.login_limiter.record_failure(user_key)
            return _login_page(request, 401, error="Invalid username or password.", username=username)

        ctx.login_limiter.reset(ip_key)
        ctx.login_limiter.reset(user_key)
        token, _ = ctx.sessions.create(auth.username, dek, auth.session_epoch)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(ctx.cookie_name, token, httponly=True, secure=settings.cookie_secure,
                            samesite="strict", path="/")
        return response

    # ----- session API -----

    @app.get("/api/session/status")
    def session_status(request: Request):
        """Does not extend the session, so the page can detect expiry."""
        current_session(request, touch=False)
        return {"ok": True}

    @app.post("/api/logout", status_code=204)
    def logout(request: Request, session: Session = Depends(require_write)):
        ctx.sessions.destroy(request.cookies.get(ctx.cookie_name))
        response = Response(status_code=204)
        response.delete_cookie(ctx.cookie_name, path="/", secure=settings.cookie_secure,
                               httponly=True, samesite="strict")
        return response

    @app.get("/api/sessions")
    def list_sessions(request: Request, session: Session = Depends(require_session)):
        return {"sessions": ctx.sessions.list(request.cookies.get(ctx.cookie_name))}

    @app.post("/api/sessions/revoke-others")
    def revoke_other_sessions(request: Request, session: Session = Depends(require_write)):
        removed = ctx.sessions.revoke_others(request.cookies.get(ctx.cookie_name))
        return {"revoked": removed}

    @app.delete("/api/sessions/{sid}")
    def revoke_session(sid: str, request: Request, session: Session = Depends(require_write)):
        if not sid.isalnum() or len(sid) != 16:
            raise HTTPException(422, "Invalid session id.")
        if sid == session.sid:
            # Revoking the current session is sign-out; the cookie is cleared as well.
            ctx.sessions.destroy(request.cookies.get(ctx.cookie_name))
            response = Response(status_code=204)
            response.delete_cookie(ctx.cookie_name, path="/", secure=settings.cookie_secure,
                                   httponly=True, samesite="strict")
            return response
        if not ctx.sessions.revoke_id(sid):
            raise HTTPException(404, "Session not found.")
        return Response(status_code=204)

    @app.post("/api/account/password", status_code=204)
    def change_account_password(body: PasswordChangeIn, request: Request, session: Session = Depends(require_write)):
        """Change the master password. Keeps the vault key, so all entries stay accessible.
        Bumps the session epoch, which signs out every session, including this one."""
        limiter_key = f"password-change:{session.username}"
        retry = ctx.login_limiter.blocked_for(limiter_key)
        if retry:
            raise HTTPException(429, f"Too many attempts. Wait {_minutes_from(retry)} minute(s).")
        try:
            authmod.change_password(settings.auth_path, body.current, body.new)
        except authmod.AuthError as exc:
            if "current password" in str(exc):
                ctx.login_limiter.record_failure(limiter_key)
                raise HTTPException(403, str(exc)) from exc
            raise HTTPException(422, str(exc)) from exc
        ctx.login_limiter.reset(limiter_key)
        ctx.sessions.destroy_all()
        response = Response(status_code=204)
        response.delete_cookie(ctx.cookie_name, path="/", secure=settings.cookie_secure,
                               httponly=True, samesite="strict")
        return response

    @app.get("/api/settings")
    def get_settings(session: Session = Depends(require_session)):
        return {
            "username": session.username,
            "session_timeout_minutes": _minutes_from(int(ctx.sessions.idle_seconds)),
            "entry_idle_minutes": settings.entry_idle_minutes,
            "backups": _latest_backup(settings),
        }

    @app.put("/api/settings")
    def put_settings(body: SettingsIn, session: Session = Depends(require_write)):
        ctx.store.set_setting("session_timeout_minutes", str(body.session_timeout_minutes))
        ctx.sessions.idle_seconds = body.session_timeout_minutes * 60
        return {"username": session.username, "session_timeout_minutes": body.session_timeout_minutes}

    # ----- entries API -----

    @app.get("/api/entries")
    def list_entries(q: str = Query(default="", max_length=200), session: Session = Depends(require_session)):
        return {"entries": ctx.vault(session).list(entry_keys(session), q)}

    @app.post("/api/entries", status_code=201)
    def create_entry(body: CreateEntryIn, session: Session = Depends(require_write)):
        new_id = ctx.vault(session).create(_meta_of(body), _content_of(body), body.separate_password)
        return {"id": new_id}

    @app.get("/api/entries/{entry_id}")
    def get_entry(entry_id: int, session: Session = Depends(require_session)):
        return ctx.vault(session).get(entry_id, entry_keys(session, entry_id, touch=True))

    @app.put("/api/entries/{entry_id}")
    def update_entry(entry_id: int, body: EntryIn, session: Session = Depends(require_write)):
        ctx.vault(session).update(entry_id, _meta_of(body), _content_of(body),
                                  entry_keys(session, entry_id, touch=True))
        return {"ok": True}

    @app.delete("/api/entries/{entry_id}", status_code=204)
    def delete_entry(entry_id: int, session: Session = Depends(require_write)):
        ctx.vault(session).delete(entry_id)
        session.drop_key(entry_id)
        return Response(status_code=204)

    @app.post("/api/entries/{entry_id}/unlock")
    def unlock_entry(entry_id: int, body: PasswordIn, session: Session = Depends(require_write)):
        limiter_key = f"entry:{entry_id}"
        retry = ctx.entry_limiter.blocked_for(limiter_key)
        if retry:
            raise HTTPException(429, f"Too many attempts. Wait {retry} seconds and try again.")
        try:
            key, _content = ctx.vault(session).unlock(entry_id, body.password)
        except VaultError as exc:
            if exc.code == "bad_password":
                ctx.entry_limiter.record_failure(limiter_key)
            raise
        ctx.entry_limiter.reset(limiter_key)
        session.put_key(entry_id, key, ctx.sessions.now())
        return ctx.vault(session).get(entry_id, entry_keys(session, entry_id, touch=True))

    @app.post("/api/entries/{entry_id}/lock", status_code=204)
    def lock_entry(entry_id: int, session: Session = Depends(require_write)):
        session.drop_key(entry_id)
        return Response(status_code=204)

    def _require_unlocked(session: Session, entry_id: int) -> bytearray:
        key = entry_keys(session, entry_id, touch=True).get(entry_id)
        if key is None:
            raise VaultError("locked", "Unlock this entry with its separate password first.")
        return key

    @app.post("/api/entries/{entry_id}/protect/enable", status_code=204)
    def enable_protection(entry_id: int, body: NewPasswordIn, session: Session = Depends(require_write)):
        ctx.vault(session).enable_protection(entry_id, body.password)
        session.drop_key(entry_id)
        return Response(status_code=204)

    @app.post("/api/entries/{entry_id}/protect/change", status_code=204)
    def change_protection(entry_id: int, body: NewPasswordIn, session: Session = Depends(require_write)):
        old_key = _require_unlocked(session, entry_id)
        new_key = ctx.vault(session).change_protection(entry_id, body.password, old_key)
        session.put_key(entry_id, new_key, ctx.sessions.now())
        return Response(status_code=204)

    @app.post("/api/entries/{entry_id}/protect/remove", status_code=204)
    def remove_protection(entry_id: int, session: Session = Depends(require_write)):
        key = _require_unlocked(session, entry_id)
        ctx.vault(session).remove_protection(entry_id, key)
        session.drop_key(entry_id)
        return Response(status_code=204)

    # ----- backup export / import -----

    @app.post("/api/export")
    def export_vault(body: PassphraseIn, session: Session = Depends(require_write)):
        document = ctx.vault(session).export(body.passphrase)
        filename = f"pastry-export-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.json"
        return JSONResponse(document, headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    @app.post("/api/import")
    def import_vault(body: ImportIn, session: Session = Depends(require_write)):
        try:
            document = json.loads(body.data)
        except ValueError as exc:
            raise VaultError("invalid", "The selected file is not valid JSON.") from exc
        return ctx.vault(session).import_(document, body.passphrase)


    @app.post("/api/packages/export")
    def export_package(body: PackageExportIn, session: Session = Depends(require_write)):
        """Build an offline `.pastry` package in memory and return it as a download.
        Nothing is written to disk and nothing is stored on the server."""
        if body.access != "offline":
            raise HTTPException(501, "Timed and one-time packages need the Pastry release service, "
                                     "which is not implemented in this version. Use an offline package.")
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=body.expires_in_minutes) if body.expires_in_minutes else None
        vault = ctx.vault(session)
        entries = []
        for entry_id in dict.fromkeys(body.entry_ids):  # de-duplicate, keep order
            item = vault.get(entry_id, entry_keys(session, entry_id, touch=True))
            if item.get("locked") and "username" not in item:
                raise VaultError("locked", f"Unlock \"{item['name']}\" before exporting it.")
            entries.append({
                "name": item["name"], "url": item["url"], "username": item["username"],
                "password": item["password"], "notes": item["notes"], "fields": item["fields"],
            })
        try:
            data = package.build_package(entries, body.password, body.name, allow_copy=body.allow_copy,
                                         expires_at=expires_at, kdf=settings.kdf, now=now)
        except package.PackageError as exc:
            raise HTTPException(422, str(exc)) from exc
        filename = package.safe_filename(body.name)
        return Response(content=data, media_type="application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    # ----- server-enforced packages: owner API -----

    def _gather_entries(session: Session, entry_ids: list[int]) -> list[dict]:
        vault = ctx.vault(session)
        entries = []
        for entry_id in dict.fromkeys(entry_ids):
            item = vault.get(entry_id, entry_keys(session, entry_id, touch=True))
            if item.get("locked") and "username" not in item:
                raise VaultError("locked", f"Unlock \"{item['name']}\" before exporting it.")
            entries.append({
                "name": item["name"], "url": item["url"], "username": item["username"],
                "password": item["password"], "notes": item["notes"], "fields": item["fields"],
            })
        return entries

    def _package_meta_aad(cap_hash: str) -> bytes:
        return b"pastry:package-meta:v1|" + cap_hash.encode("ascii")

    @app.post("/api/packages")
    def create_package(body: PackageCreateIn, session: Session = Depends(require_write)):
        """Create a server-enforced package. The release key stays on this server."""
        if not settings.public_url:
            raise HTTPException(422, "Set public_url in config/pastry.json to the HTTPS address recipients will use "
                                     "(for example your Tailscale Serve address) before creating timed packages.")
        now = ctx.wall_clock()
        if body.policy == "after_open":
            if body.duration_minutes is None or body.duration_minutes * 60 not in AFTER_OPEN_SECONDS:
                raise HTTPException(422, "Choose an opening window of 5 minutes, 15 minutes, 1 hour or 24 hours.")
            policy = {"type": "after_open", "seconds": body.duration_minutes * 60}
            duration, absolute = body.duration_minutes * 60, None
        elif body.policy == "absolute":
            if body.absolute_minutes is None or body.absolute_minutes * 60 > MAX_ABSOLUTE_SECONDS:
                raise HTTPException(422, "Choose an absolute deadline between 1 minute and 30 days.")
            absolute = now + body.absolute_minutes * 60
            policy = {"type": "absolute",
                      "expires_at": datetime.fromtimestamp(absolute, timezone.utc).isoformat(timespec="seconds")}
            duration = None
        elif body.policy == "one_time":
            policy, duration, absolute = {"type": "one_time"}, None, None
        else:
            raise HTTPException(422, "Unknown package policy.")

        entries = _gather_entries(session, body.entry_ids)
        svc = ctx.release_service()
        salt = crypto.new_salt()
        capability = secrets.token_bytes(32)
        k_r = secrets.token_bytes(32)
        k_pw, k_auth = package.derive_keys(body.password, salt, settings.kdf)
        crypto.wipe(k_pw)
        cap_hash = releasemod.cap_hash(capability)
        meta_blob = crypto.seal(session.dek, json.dumps({"name": body.name, "allow_copy": body.allow_copy},
                                                        separators=(",", ":")).encode(),
                                _package_meta_aad(cap_hash))
        from .release import NewPackage

        pkg = NewPackage(owner=session.username, capability=capability, policy=body.policy,
                         duration_seconds=duration, absolute_expires_at=absolute,
                         entry_count=len(entries), meta_blob=meta_blob, file_blob=b"",
                         k_r=k_r, k_auth=k_auth)
        package_id = svc.create(pkg, now)
        try:
            data = package.build_server_package(
                entries, body.name, allow_copy=body.allow_copy, policy=policy, release_url=settings.public_url,
                package_id=package_id, capability=capability, salt=salt, kdf=settings.kdf, k_r=k_r,
                now=datetime.fromtimestamp(now, timezone.utc),
            )
        except package.PackageError as exc:
            svc.delete(session.username, package_id)
            raise HTTPException(422, str(exc)) from exc
        finally:
            crypto.wipe(bytearray(k_r))
        svc.set_file(package_id, data, session.username)
        return Response(content=data, media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="{package.safe_filename(body.name)}"',
            "X-Pastry-Package-Id": str(package_id),
        })

    @app.get("/api/packages")
    def list_packages(session: Session = Depends(require_session)):
        svc = ctx.release_service()
        out = []
        for item in svc.list_for(session.username):
            meta = json.loads(crypto.open_sealed(session.dek, item.pop("meta_blob"),
                                                 _package_meta_aad(item.pop("cap_hash"))))
            item["name"] = meta["name"]
            item["allow_copy"] = meta["allow_copy"]
            out.append(item)
        return {"packages": out}

    @app.get("/api/packages/{package_id}/file")
    def download_package(package_id: int, session: Session = Depends(require_session)):
        data = ctx.release_service().get_file(session.username, package_id)
        return Response(content=data, media_type="application/octet-stream", headers={
            "Content-Disposition": 'attachment; filename="package.pastry"'})

    @app.post("/api/packages/{package_id}/revoke", status_code=204)
    def revoke_package(package_id: int, session: Session = Depends(require_write)):
        ctx.release_service().revoke(session.username, package_id)
        return Response(status_code=204)

    @app.delete("/api/packages/{package_id}", status_code=204)
    def delete_package(package_id: int, session: Session = Depends(require_write)):
        ctx.release_service().delete(session.username, package_id)
        return Response(status_code=204)

    # ----- server-enforced packages: public release API (no vault session) -----
    # These routes touch only the packages and release_nonces tables. They never read
    # vault entries, sessions or the vault key. See docs/CRYPTOGRAPHY-V12.md, section 10.

    def _release_guard(request: Request, capability_text: str):
        ctx.require_schema()
        client = f"rel-ip:{_client_ip(request)}"
        if ctx.release_request_limiter.blocked_for(client):
            raise HTTPException(429, "Too many requests. Wait a minute and try again.")
        ctx.release_request_limiter.record_failure(client)
        try:
            capability = releasemod.decode_capability(capability_text)
        except ReleaseError as exc:
            raise HTTPException(exc.status, exc.message) from exc
        cap_key = f"rel-cap:{releasemod.cap_hash(capability)}"
        if ctx.release_fail_limiter.blocked_for(cap_key):
            raise HTTPException(429, "Too many failed attempts for this package. Try again later.")
        return capability, cap_key

    def _release_error(exc: ReleaseError) -> JSONResponse:
        return JSONResponse({"detail": exc.message, "code": exc.code}, status_code=exc.status)

    @app.post("/release/v1/status")
    def release_status(body: ReleaseBody, request: Request):
        capability, _ = _release_guard(request, body.capability)
        try:
            return ctx.release_service().status(capability)
        except ReleaseError as exc:
            return _release_error(exc)

    @app.post("/release/v1/challenge")
    def release_challenge(body: ReleaseBody, request: Request):
        capability, _ = _release_guard(request, body.capability)
        try:
            return {"nonce": ctx.release_service().challenge(capability)}
        except ReleaseError as exc:
            return _release_error(exc)

    @app.post("/release/v1/redeem")
    def release_redeem(body: ReleaseBody, request: Request):
        capability, cap_key = _release_guard(request, body.capability)
        try:
            proof = base64.b64decode(body.proof, validate=True)
        except (ValueError, TypeError):
            return JSONResponse({"detail": "Malformed proof.", "code": "invalid"}, status_code=422)
        if len(proof) != 32 or not body.nonce:
            return JSONResponse({"detail": "Malformed proof.", "code": "invalid"}, status_code=422)
        try:
            return ctx.release_service().redeem(capability, body.nonce, proof)
        except ReleaseError as exc:
            if exc.code == "bad_password":
                ctx.release_fail_limiter.record_failure(cap_key)
            return _release_error(exc)


    return app
