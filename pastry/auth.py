"""Admin account and vault-key handling, stored in config/auth.json.

Model
-----
- The login password is verified against an Argon2id hash (password_hash).
- A random 256-bit vault data-encryption key (DEK) protects all entries.
- The DEK is stored only wrapped (AES-256-GCM) under a key-encryption key (KEK)
  derived from the master password with Argon2id and a random salt.
- Changing the master password derives a new KEK and re-wraps the SAME DEK.
  Entries are never re-encrypted, so they stay accessible.
- session_epoch increments on every credential change. Sessions created under an
  older epoch are rejected.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import crypto
from .crypto import CryptoError, KdfParams

AUTH_FORMAT = 1
DEK_AAD = b"pastry:vault-key:v1"
MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 256
MAX_USERNAME_LEN = 64


class AuthError(Exception):
    """A user-facing error from an admin operation."""


@dataclass
class AuthFile:
    username: str
    password_hash: str
    kek_salt: bytes
    kdf: KdfParams
    wrapped_dek: bytes
    session_epoch: int
    created_at: str
    updated_at: str

    def to_json(self) -> dict:
        return {
            "format": AUTH_FORMAT,
            "username": self.username,
            "password_hash": self.password_hash,
            "kdf": {"algorithm": "argon2id", **self.kdf.to_dict(), "salt": _b64(self.kek_salt)},
            "vault_key": {"algorithm": "aes-256-gcm", "wrapped": _b64(self.wrapped_dek)},
            "session_epoch": self.session_epoch,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_json(cls, data: dict) -> "AuthFile":
        if data.get("format") != AUTH_FORMAT:
            raise AuthError("Unsupported config/auth.json format.")
        kdf = data["kdf"]
        return cls(
            username=str(data["username"]),
            password_hash=str(data["password_hash"]),
            kek_salt=_unb64(kdf["salt"]),
            kdf=KdfParams.from_dict(kdf),
            wrapped_dek=_unb64(data["vault_key"]["wrapped"]),
            session_epoch=int(data["session_epoch"]),
            created_at=str(data["created_at"]),
            updated_at=str(data["updated_at"]),
        )


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_auth(path: Path) -> AuthFile:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return AuthFile.from_json(data)
    except FileNotFoundError as exc:
        raise AuthError("Pastry is not set up yet. Run: pastry setup") from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise AuthError(f"{path} is missing or malformed.") from exc


def write_auth(path: Path, auth: AuthFile) -> None:
    """Atomically replace auth.json with mode 0600 (temp file, fsync, rename)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + ".tmp")
    payload = (json.dumps(auth.to_json(), indent=2) + "\n").encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def permission_warnings(path: Path) -> list[str]:
    if not path.exists():
        return []
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        return [f"{path} is readable by other users (mode {oct(mode)}); run: chmod 600 {path}"]
    return []


def validate_username(value: str) -> str:
    username = value.strip()
    if not 1 <= len(username) <= MAX_USERNAME_LEN:
        raise AuthError(f"Username must be 1 to {MAX_USERNAME_LEN} characters.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in username):
        raise AuthError("Username must not contain control characters.")
    return username


def validate_password(value: str) -> str:
    if len(value) < MIN_PASSWORD_LEN:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    if len(value) > MAX_PASSWORD_LEN:
        raise AuthError(f"Password must be at most {MAX_PASSWORD_LEN} characters.")
    return value


def create_auth(path: Path, username: str, password: str, kdf: KdfParams) -> AuthFile:
    """First-run: generate the vault key and write config/auth.json."""
    username = validate_username(username)
    validate_password(password)
    dek = crypto.new_key()
    kek = None
    try:
        salt = crypto.new_salt()
        kek = crypto.derive_key(password, salt, kdf)
        wrapped = crypto.seal(kek, bytes(dek), DEK_AAD)
        auth = AuthFile(
            username=username,
            password_hash=crypto.hash_password(password, kdf),
            kek_salt=salt,
            kdf=kdf,
            wrapped_dek=wrapped,
            session_epoch=0,
            created_at=_now(),
            updated_at=_now(),
        )
    finally:
        crypto.wipe(kek)
        crypto.wipe(dek)
    write_auth(path, auth)
    return auth


def try_unlock(auth: AuthFile, password: str) -> bytearray | None:
    """Return the vault key if the password is correct, otherwise None.

    Caller owns the returned bytearray and must wipe it.
    """
    if not crypto.verify_password_hash(auth.password_hash, password):
        return None
    kek = crypto.derive_key(password, auth.kek_salt, auth.kdf)
    try:
        return bytearray(crypto.open_sealed(kek, auth.wrapped_dek, DEK_AAD))
    except CryptoError:
        return None
    finally:
        crypto.wipe(kek)


def _require_current(auth: AuthFile, password: str) -> bytearray:
    dek = try_unlock(auth, password)
    if dek is None:
        raise AuthError("The current password is incorrect.")
    return dek


def change_password(path: Path, current: str, new: str) -> AuthFile:
    """Rewrap the existing vault key under a key derived from the new password."""
    validate_password(new)
    auth = read_auth(path)
    dek = _require_current(auth, current)
    try:
        salt = crypto.new_salt()
        kek = crypto.derive_key(new, salt, auth.kdf)
        try:
            wrapped = crypto.seal(kek, bytes(dek), DEK_AAD)
        finally:
            crypto.wipe(kek)
        updated = AuthFile(
            username=auth.username,
            password_hash=crypto.hash_password(new, auth.kdf),
            kek_salt=salt,
            kdf=auth.kdf,
            wrapped_dek=wrapped,
            session_epoch=auth.session_epoch + 1,
            created_at=auth.created_at,
            updated_at=_now(),
        )
        # Prove the new credentials recover the SAME vault key before committing.
        check = try_unlock(updated, new)
        try:
            if check is None or not hmac.compare_digest(bytes(check), bytes(dek)):
                raise AuthError("Verification of the new password failed. Nothing was changed.")
        finally:
            crypto.wipe(check)
    finally:
        crypto.wipe(dek)
    write_auth(path, updated)
    return updated


def change_username(path: Path, current: str, new_username: str) -> AuthFile:
    auth = read_auth(path)
    dek = _require_current(auth, current)
    crypto.wipe(dek)
    updated = AuthFile(
        username=validate_username(new_username),
        password_hash=auth.password_hash,
        kek_salt=auth.kek_salt,
        kdf=auth.kdf,
        wrapped_dek=auth.wrapped_dek,
        session_epoch=auth.session_epoch + 1,
        created_at=auth.created_at,
        updated_at=_now(),
    )
    write_auth(path, updated)
    return updated
