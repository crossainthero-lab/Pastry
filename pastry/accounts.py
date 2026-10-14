"""Accounts other than the owner. Design: docs/MULTIUSER-CRYPTO.md.

The owner's account stays in config/auth.json (id 0). Every other account lives in the
`users` table (id >= 1). Each account has its own Argon2id salt, password verifier and
random 256-bit vault key, wrapped by a KEK derived from its own password. No account can
derive another account's key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
from dataclasses import dataclass

from . import auth as authmod
from . import crypto
from .crypto import CryptoError, KdfParams
from .db import Store

OWNER_ID = 0
INVITE_TTL_SECONDS = 72 * 3600
INVITE_FAILURE = "This invitation is not valid or has expired."
_dummy_lock = threading.Lock()
_dummy_hash: str | None = None


class AccountError(Exception):
    pass


def _dummy() -> str:
    """A real Argon2id verifier, computed once, so unknown usernames cost the same as known ones."""
    global _dummy_hash
    with _dummy_lock:
        if _dummy_hash is None:
            _dummy_hash = crypto.hash_password(secrets.token_hex(16), KdfParams())
        return _dummy_hash


def _aad(username: str) -> bytes:
    return b"pastry:account-key:v1|" + username.lower().encode("utf-8")


@dataclass
class AccountRow:
    id: int
    username: str
    disabled: bool
    session_epoch: int
    password_hash: str
    kek_salt: bytes
    kdf: KdfParams
    wrapped_dek: bytes


def _row(conn: sqlite3.Connection, where: str, value) -> AccountRow | None:
    row = conn.execute(f"SELECT * FROM users WHERE {where}", (value,)).fetchone()
    if row is None:
        return None
    return AccountRow(
        id=row["id"], username=row["username"], disabled=bool(row["disabled"]),
        session_epoch=row["session_epoch"], password_hash=row["password_hash"],
        kek_salt=bytes(row["kek_salt"]), kdf=KdfParams.from_dict(json.loads(row["kdf"])),
        wrapped_dek=bytes(row["wrapped_dek"]),
    )


def username_taken(store: Store, username: str, owner_username: str) -> bool:
    if username.lower() == owner_username.lower():
        return True
    with store.connect() as conn:
        return conn.execute("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone() is not None


def get_account(store: Store, account_id: int) -> AccountRow | None:
    with store.connect() as conn:
        return _row(conn, "id = ?", account_id)


def open_login(store: Store, username: str, password: str) -> tuple[AccountRow, bytearray] | None:
    """Verify credentials for a non-owner account. Returns (account, vault key) or None.

    Always runs one Argon2id verification, so unknown usernames, disabled accounts and wrong
    passwords take about the same time."""
    with store.connect() as conn:
        account = _row(conn, "username = ? COLLATE NOCASE", username)
    if account is None:
        crypto.verify_password_hash(_dummy(), password)
        return None
    if not crypto.verify_password_hash(account.password_hash, password):
        return None
    if account.disabled:
        return None
    kek = crypto.derive_key(password, account.kek_salt, account.kdf)
    try:
        dek = bytearray(crypto.open_sealed(kek, account.wrapped_dek, _aad(account.username)))
    except CryptoError:
        return None
    finally:
        crypto.wipe(kek)
    return account, dek


def create_invitation(store: Store, username: str, role: str, created_by: str, owner_username: str,
                      now: float) -> str:
    """Single-use invitation for a username. Returns the token (shown once, stored only as a hash)."""
    username = authmod.validate_username(username)
    if role != "user":
        raise AccountError("Only the 'user' role can be invited.")
    if username_taken(store, username, owner_username):
        raise AccountError("That username is already taken.")
    token = secrets.token_urlsafe(32)
    with store.transaction() as conn:
        conn.execute(
            "INSERT INTO invitations (token_hash, username, role, created_by, created_at, expires_at, used_at) "
            "VALUES (?, ?, ?, ?, ?, ?, NULL)",
            (hashlib.sha256(token.encode()).hexdigest(), username, role, created_by, now, now + INVITE_TTL_SECONDS),
        )
    return token


def accept_invitation(store: Store, token: str, password: str, owner_username: str, kdf: KdfParams,
                      now: float) -> int:
    """Create the account. The invitee chooses the password; the server generates the vault key."""
    authmod.validate_password(password)
    digest = hashlib.sha256(token.encode()).hexdigest()
    with store.connect() as conn:
        invite = conn.execute("SELECT * FROM invitations WHERE token_hash = ?", (digest,)).fetchone()
    if invite is None or invite["used_at"] is not None or invite["expires_at"] < now:
        raise AccountError(INVITE_FAILURE)
    username = invite["username"]
    if username_taken(store, username, owner_username):
        raise AccountError("That username is no longer available.")

    dek = crypto.new_key()
    salt = crypto.new_salt()
    kek = crypto.derive_key(password, salt, kdf)
    try:
        wrapped = crypto.seal(kek, bytes(dek), _aad(username))
        verifier = crypto.hash_password(password, kdf)
    finally:
        crypto.wipe(kek)
        crypto.wipe(dek)
    try:
        with store.transaction() as conn:
            # Single use is enforced here: the invitation must still be unused and unexpired.
            cur = conn.execute(
                "UPDATE invitations SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at >= ?",
                (now, digest, now),
            )
            if cur.rowcount != 1:
                raise AccountError(INVITE_FAILURE)
            cur = conn.execute(
                "INSERT INTO users (username, role, password_hash, kek_salt, kdf, wrapped_dek, session_epoch, "
                "disabled, created_at, updated_at) VALUES (?, 'user', ?, ?, ?, ?, 0, 0, ?, ?)",
                (username, verifier, salt, json.dumps(kdf.to_dict()), wrapped, now, now),
            )
            return int(cur.lastrowid)
    except sqlite3.IntegrityError as exc:
        raise AccountError("That username is no longer available.") from exc


def change_password(store: Store, account_id: int, current: str, new: str, now: float) -> None:
    """Re-wrap the account's own vault key under a new password. Entries are not re-encrypted."""
    authmod.validate_password(new)
    account = get_account(store, account_id)
    if account is None:
        raise AccountError("Account not found.")
    opened = open_login(store, account.username, current)
    if opened is None:
        raise AccountError("The current password is incorrect.")
    _, dek = opened
    try:
        salt = crypto.new_salt()
        kek = crypto.derive_key(new, salt, account.kdf)
        try:
            wrapped = crypto.seal(kek, bytes(dek), _aad(account.username))
        finally:
            crypto.wipe(kek)
        verifier = crypto.hash_password(new, account.kdf)
        # Verify before committing: the new password must return the same vault key.
        check_kek = crypto.derive_key(new, salt, account.kdf)
        try:
            check = crypto.open_sealed(check_kek, wrapped, _aad(account.username))
        finally:
            crypto.wipe(check_kek)
        if not hmac.compare_digest(check, bytes(dek)):
            raise AccountError("Verification of the new password failed. Nothing was changed.")
        with store.transaction() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ?, kek_salt = ?, wrapped_dek = ?, session_epoch = session_epoch + 1, "
                "updated_at = ? WHERE id = ?",
                (verifier, salt, wrapped, now, account_id),
            )
    finally:
        crypto.wipe(dek)


def disable(store: Store, account_id: int, now: float) -> None:
    """Disable an account and invalidate its sessions (the epoch changes). Its data is kept."""
    with store.transaction() as conn:
        cur = conn.execute(
            "UPDATE users SET disabled = 1, session_epoch = session_epoch + 1, updated_at = ? WHERE id = ?",
            (now, account_id),
        )
        if cur.rowcount == 0:
            raise AccountError("Account not found.")


def find_id(store: Store, username: str) -> int | None:
    with store.connect() as conn:
        row = conn.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
    return int(row["id"]) if row else None


def list_accounts(store: Store, owner_username: str) -> list[dict]:
    out = [{"id": OWNER_ID, "username": owner_username, "role": "owner", "disabled": False, "created_at": None}]
    with store.connect() as conn:
        rows = conn.execute("SELECT id, username, role, disabled, created_at FROM users ORDER BY id").fetchall()
    for row in rows:
        out.append({"id": row["id"], "username": row["username"], "role": row["role"],
                    "disabled": bool(row["disabled"]), "created_at": row["created_at"]})
    return out


def current_epoch(store: Store, account_id: int) -> int | None:
    """The account's session epoch, or None if the account is missing or disabled."""
    account = get_account(store, account_id)
    if account is None or account.disabled:
        return None
    return account.session_epoch


def pending_invitations(store: Store, now: float) -> list[dict]:
    with store.connect() as conn:
        rows = conn.execute(
            "SELECT username, role, created_at, expires_at FROM invitations WHERE used_at IS NULL AND expires_at >= ? "
            "ORDER BY created_at DESC", (now,)).fetchall()
    return [dict(row) for row in rows]
