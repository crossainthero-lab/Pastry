"""Server-side release service for server-enforced packages.

Design: docs/CRYPTOGRAPHY-V12.md, section 10. Summary:
- Each package has a random release key K_r. The package DEK is wrapped under K_r, and
  K_r is released only through the protocol below.
- K_auth is derived from the package password (Argon2id, then HKDF). The server stores
  K_auth, never the password. Redemption requires an HMAC proof keyed by K_auth over a
  single-use nonce, so the password is never sent.
- K_r and K_auth are sealed at rest under release_kek (config/release.key, not in backups).
- All state transitions run in BEGIN IMMEDIATE transactions and use the server clock.
- Terminal states erase the sealed K_r and K_auth.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from . import crypto
from .crypto import CryptoError
from .db import Store
from .package import PROOF_PREFIX, WRAP_PREFIX

NONCE_TTL_SECONDS = 120
KEK_AAD = b"pastry:release-kek:v1"
KEY_AAD_PREFIX = b"pastry:release-key:v1|"
AUTH_AAD_PREFIX = b"pastry:release-auth:v1|"
AFTER_OPEN_CHOICES = (5 * 60, 15 * 60, 60 * 60, 24 * 60 * 60)
ABSOLUTE_MAX_SECONDS = 30 * 24 * 3600
TERMINAL = ("revoked", "consumed", "expired")


class ReleaseError(Exception):
    """Carries an HTTP-style status and a short, non-secret message."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def cap_hash(capability: bytes) -> str:
    return hashlib.sha256(capability).hexdigest()


def decode_capability(text: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise ReleaseError(404, "not_found", "This package is not available on this server.") from exc
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != text:
        raise ReleaseError(404, "not_found", "This package is not available on this server.")
    return raw


def encode_capability(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def load_or_create_kek(path) -> bytes:
    """release_kek: 256-bit, created with mode 0600 on first use. Never placed in backups."""
    path = os.fspath(path)
    if os.path.exists(path):
        with open(path, "rb") as handle:
            raw = handle.read()
        if len(raw) != 32:
            raise ReleaseError(503, "key_missing", "The release key file is damaged.")
        return raw
    raw = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return raw


def _now_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


@dataclass
class NewPackage:
    owner: str
    capability: bytes
    policy: str
    duration_seconds: int | None
    absolute_expires_at: float | None
    entry_count: int
    meta_blob: bytes
    file_blob: bytes  # may be empty until the file is built; see set_file
    k_r: bytes
    k_auth: bytes


class ReleaseService:
    def __init__(self, store: Store, kek: bytes, clock: Callable[[], float]):
        self.store = store
        self._kek = bytes(kek)
        self._clock = clock

    # ----- sealing helpers ------------------------------------------------

    def _seal(self, plaintext: bytes, aad: bytes) -> bytes:
        return crypto.seal(self._kek, plaintext, aad)

    def _open(self, blob: bytes, aad: bytes) -> bytes:
        try:
            return crypto.open_sealed(self._kek, blob, aad)
        except CryptoError as exc:
            raise ReleaseError(503, "key_missing", "This package's release data could not be read.") from exc

    # ----- creation (owner) ------------------------------------------------

    def create(self, pkg: NewPackage, now: float) -> int:
        digest = cap_hash(pkg.capability)
        binding = digest.encode()
        with self.store.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO packages (owner, cap_hash, state, policy, duration_seconds, expires_at, "
                "first_released_at, created_at, entry_count, meta_blob, file_blob, release_blob, auth_blob) "
                "VALUES (?, ?, 'active', ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)",
                (pkg.owner, digest, pkg.policy, pkg.duration_seconds, pkg.absolute_expires_at, now,
                 pkg.entry_count, pkg.meta_blob, pkg.file_blob,
                 self._seal(pkg.k_r, KEY_AAD_PREFIX + binding),
                 self._seal(pkg.k_auth, AUTH_AAD_PREFIX + binding)),
            )
            return int(cur.lastrowid)

    def set_file(self, package_id: int, file_blob: bytes, owner: str) -> None:
        with self.store.transaction() as conn:
            cur = conn.execute("UPDATE packages SET file_blob = ? WHERE id = ? AND owner = ?",
                               (file_blob, package_id, owner))
            if cur.rowcount == 0:
                raise ReleaseError(404, "not_found", "Package not found.")

    # ----- state ----------------------------------------------------------

    def _settle(self, conn: sqlite3.Connection, row: sqlite3.Row, now: float) -> str:
        """Apply time-based expiry inside the caller's transaction. Returns the current state."""
        state = row["state"]
        if state in TERMINAL:
            return state
        deadline = row["expires_at"]
        if deadline is not None and now >= deadline:
            self._terminate(conn, row["id"], "expired")
            return "expired"
        return "active"

    def _terminate(self, conn: sqlite3.Connection, package_id: int, state: str) -> None:
        # Terminal states erase the sealed release material: nothing is left to release.
        conn.execute(
            "UPDATE packages SET state = ?, release_blob = NULL, auth_blob = NULL WHERE id = ?",
            (state, package_id),
        )

    def _row(self, conn: sqlite3.Connection, digest: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM packages WHERE cap_hash = ?", (digest,)).fetchone()
        if row is None:
            raise ReleaseError(404, "not_found", "This package is not available on this server.")
        return row

    @staticmethod
    def _state_error(state: str) -> ReleaseError:
        messages = {
            "expired": (410, "expired", "This package has expired."),
            "revoked": (410, "revoked", "The owner has revoked this package."),
            "consumed": (409, "consumed", "This one-time package has already been redeemed."),
        }
        status, code, message = messages[state]
        return ReleaseError(status, code, message)

    # ----- public release API ---------------------------------------------

    def status(self, capability: bytes) -> dict:
        now = self._clock()
        with self.store.transaction() as conn:
            row = self._row(conn, cap_hash(capability))
            state = self._settle(conn, row, now)
            expires = row["expires_at"]
        return {"state": state, "expires_at": _now_iso(expires) if expires else None}

    def challenge(self, capability: bytes) -> str:
        now = self._clock()
        nonce = secrets.token_hex(32)
        error = None
        with self.store.transaction() as conn:
            row = self._row(conn, cap_hash(capability))
            state = self._settle(conn, row, now)
            if state != "active":
                error = self._state_error(state)  # raised after commit, so any expiry write persists
            else:
                conn.execute("DELETE FROM release_nonces WHERE expires_at < ?", (now,))
                conn.execute("INSERT INTO release_nonces (nonce, package_id, expires_at) VALUES (?, ?, ?)",
                             (nonce, row["id"], now + NONCE_TTL_SECONDS))
        if error is not None:
            raise error
        return nonce

    def redeem(self, capability: bytes, nonce: str, proof: bytes) -> dict:
        """Verify the proof and release the wrapped K_r. Atomic: at most one winner per one-time package.

        Errors are raised only after the transaction commits, so the single-use nonce deletion
        and any expiry write are never rolled back by an error path.
        """
        now = self._clock()
        digest = cap_hash(capability)
        error = None
        result = None
        with self.store.transaction() as conn:
            nonce_row = conn.execute("SELECT * FROM release_nonces WHERE nonce = ?", (nonce,)).fetchone()
            conn.execute("DELETE FROM release_nonces WHERE nonce = ?", (nonce,))  # single use, even if wrong
            row = self._row(conn, digest)
            if nonce_row is None or nonce_row["package_id"] != row["id"] or nonce_row["expires_at"] < now:
                error = ReleaseError(403, "bad_challenge", "The challenge has expired. Start again.")
            else:
                state = self._settle(conn, row, now)
                if state != "active":
                    error = self._state_error(state)
                else:
                    k_auth = self._open(row["auth_blob"], AUTH_AAD_PREFIX + digest.encode())
                    expected = hmac.new(k_auth, PROOF_PREFIX + str(row["id"]).encode() + b"|" + nonce.encode(),
                                        hashlib.sha256).digest()
                    if not hmac.compare_digest(expected, proof):
                        error = ReleaseError(403, "bad_password", "The package password was not accepted.")
                    else:
                        k_r = self._open(row["release_blob"], KEY_AAD_PREFIX + digest.encode())
                        expires = row["expires_at"]
                        if row["policy"] == "after_open" and row["first_released_at"] is None:
                            expires = now + row["duration_seconds"]
                            conn.execute("UPDATE packages SET first_released_at = ?, expires_at = ? WHERE id = ?",
                                         (now, expires, row["id"]))
                        wrap = crypto.seal(k_auth, k_r, WRAP_PREFIX + str(row["id"]).encode() + b"|" + nonce.encode())
                        if row["policy"] == "one_time":
                            self._terminate(conn, row["id"], "consumed")
                        result = {
                            "package_id": row["id"],
                            "wrapped_key": base64.b64encode(wrap).decode("ascii"),
                            "expires_at": _now_iso(expires) if expires else None,
                        }
        if error is not None:
            raise error
        return result

    # ----- owner operations -----------------------------------------------

    def list_for(self, owner: str) -> list[dict]:
        now = self._clock()
        out = []
        with self.store.transaction() as conn:
            rows = conn.execute("SELECT * FROM packages WHERE owner = ? ORDER BY id DESC", (owner,)).fetchall()
            for row in rows:
                state = self._settle(conn, row, now)
                out.append({
                    "id": row["id"],
                    "cap_hash": row["cap_hash"],
                    "policy": row["policy"],
                    "state": state,
                    "created_at": _now_iso(row["created_at"]),
                    "expires_at": _now_iso(row["expires_at"]) if row["expires_at"] else None,
                    "redeemed": row["first_released_at"] is not None or state == "consumed",
                    "entry_count": row["entry_count"],
                    "has_file": bool(row["file_blob"]),
                    "meta_blob": bytes(row["meta_blob"]),
                })
        return out

    def get_file(self, owner: str, package_id: int) -> bytes:
        with self.store.connect() as conn:
            row = conn.execute("SELECT file_blob FROM packages WHERE id = ? AND owner = ?",
                               (package_id, owner)).fetchone()
        if row is None or not row["file_blob"]:
            raise ReleaseError(404, "not_found", "Package not found.")
        return bytes(row["file_blob"])

    def revoke(self, owner: str, package_id: int) -> None:
        with self.store.transaction() as conn:
            row = conn.execute("SELECT * FROM packages WHERE id = ? AND owner = ?", (package_id, owner)).fetchone()
            if row is None:
                raise ReleaseError(404, "not_found", "Package not found.")
            if row["state"] == "active":
                self._terminate(conn, package_id, "revoked")

    def delete(self, owner: str, package_id: int) -> None:
        """Remove the package record. Revokes first. Touches only this package's rows."""
        with self.store.transaction() as conn:
            row = conn.execute("SELECT id FROM packages WHERE id = ? AND owner = ?", (package_id, owner)).fetchone()
            if row is None:
                raise ReleaseError(404, "not_found", "Package not found.")
            conn.execute("DELETE FROM release_nonces WHERE package_id = ?", (package_id,))
            conn.execute("DELETE FROM packages WHERE id = ?", (package_id,))

    # ----- housekeeping ---------------------------------------------------

    def sweep(self) -> int:
        """Erase release material of packages past their deadline, and drop stale nonces.
        Touches only the packages and release_nonces tables."""
        now = self._clock()
        erased = 0
        with self.store.transaction() as conn:
            rows = conn.execute(
                "SELECT id, state, expires_at FROM packages WHERE state = 'active' AND expires_at IS NOT NULL "
                "AND expires_at <= ?", (now,)).fetchall()
            for row in rows:
                self._terminate(conn, row["id"], "expired")
                erased += 1
            conn.execute("DELETE FROM release_nonces WHERE expires_at < ?", (now,))
        return erased
