"""SQLite storage (schema v3). Every user-supplied value lives inside an encrypted blob.

Plaintext columns are limited to: the row id, a random per-entry uid (used as
AAD, not secret) and the blobs themselves. Timestamps, the locked flag, and the
separate-password salt and parameters are inside the encrypted metadata blob.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA_VERSION = 5

PACKAGE_STATEMENTS = (
    """
CREATE TABLE IF NOT EXISTS packages (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    owner            TEXT NOT NULL,
    cap_hash         TEXT NOT NULL UNIQUE,        -- SHA-256 of the capability
    state            TEXT NOT NULL CHECK (state IN ('active', 'revoked', 'consumed', 'expired')),
    policy           TEXT NOT NULL CHECK (policy IN ('after_open', 'absolute', 'one_time')),
    duration_seconds INTEGER,                     -- after_open: window length from first release
    expires_at       REAL,                        -- absolute deadline, or window end once started
    first_released_at REAL,
    created_at       REAL NOT NULL,
    entry_count      INTEGER NOT NULL,
    meta_blob        BLOB NOT NULL,               -- sealed under the vault key: name, allow_copy
    file_blob        BLOB NOT NULL,               -- encrypted .pastry file (a copy for download)
    release_blob     BLOB,                        -- K_r sealed under release_kek; NULL once terminal
    auth_blob        BLOB                         -- K_auth sealed under release_kek; NULL once terminal
)
""",
    """
CREATE TABLE IF NOT EXISTS release_nonces (
    nonce      TEXT PRIMARY KEY,
    package_id INTEGER NOT NULL,
    expires_at REAL NOT NULL
)
""",
)
# Accounts other than the owner (schema v4). The owner's account stays in config/auth.json.
# Each account has its own Argon2id salt, password verifier and random vault key, wrapped by its KEK.
ACCOUNT_STATEMENTS = (
    """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,   -- account id; the owner is 0 and never appears here
    username     TEXT NOT NULL UNIQUE COLLATE NOCASE,
    role         TEXT NOT NULL CHECK (role IN ('user')),
    password_hash TEXT NOT NULL,                      -- Argon2id verifier (login)
    kek_salt     BLOB NOT NULL,
    kdf          TEXT NOT NULL,                       -- Argon2id parameters, JSON
    wrapped_dek  BLOB NOT NULL,                       -- account vault key, AES-256-GCM under the KEK
    session_epoch INTEGER NOT NULL DEFAULT 0,
    disabled     INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL
)
""",
    """
CREATE TABLE IF NOT EXISTS invitations (
    token_hash   TEXT PRIMARY KEY,                    -- SHA-256 of the invitation token
    username     TEXT NOT NULL,
    role         TEXT NOT NULL CHECK (role IN ('user')),
    created_by   TEXT NOT NULL,
    created_at   REAL NOT NULL,
    expires_at   REAL NOT NULL,
    used_at      REAL
)
""",
)
# Server-enforced packages (schema v3). Release material is sealed under release_kek,
# which lives in config/release.key and is excluded from backups (docs/CRYPTOGRAPHY-V12.md, 10.2).
PACKAGE_SCHEMA = ";\n".join(PACKAGE_STATEMENTS) + ";"

_BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    uid          TEXT NOT NULL UNIQUE,      -- random, used as AAD
    owner_id     INTEGER NOT NULL DEFAULT 0,  -- account that owns the entry (0 = the owner)
    fmt          INTEGER NOT NULL DEFAULT 4,  -- 4: sealed under the account key; 5: under a per-entry key
    key_blob     BLOB,                        -- fmt 5: entry key wrapped under the owner's account key
    key_version  INTEGER NOT NULL DEFAULT 0,  -- increments when the entry key is rotated
    meta_blob    BLOB NOT NULL,             -- vault key: name, url, category, favourite, timestamps, lock info
    content_blob BLOB NOT NULL              -- vault key or entry key: username, password, notes, fields
);
CREATE TABLE IF NOT EXISTS rate_limits (
    key           TEXT PRIMARY KEY,
    failures      TEXT NOT NULL,            -- JSON list of failure times (seconds since epoch)
    blocked_until REAL NOT NULL DEFAULT 0
);
"""
# Entry sharing (schema v5). Public keys are plaintext but MAC-bound to the account id; private
# keys are sealed under the account's vault key and only usable inside that account's session.
SHARING_STATEMENTS = (
    """
CREATE TABLE IF NOT EXISTS account_keys (
    account_id   INTEGER PRIMARY KEY,
    public_key   BLOB NOT NULL,
    public_mac   BLOB NOT NULL,                       -- HMAC(server binding key, account id, public key)
    private_blob BLOB NOT NULL,                       -- AES-256-GCM under the account vault key
    created_at   REAL NOT NULL
)
""",
    """
CREATE TABLE IF NOT EXISTS shares (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id     INTEGER NOT NULL,
    owner_id     INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    can_edit     INTEGER NOT NULL DEFAULT 0 CHECK (can_edit IN (0, 1)),
    can_export   INTEGER NOT NULL DEFAULT 0 CHECK (can_export IN (0, 1)),
    envelope     BLOB NOT NULL,                       -- entry key wrapped to the recipient's public key
    key_version  INTEGER NOT NULL,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL,
    UNIQUE (entry_id, recipient_id)
)
""",
)

SCHEMA = (_BASE_SCHEMA + PACKAGE_SCHEMA + ";\n".join(ACCOUNT_STATEMENTS) + ";\n"
          + ";\n".join(SHARING_STATEMENTS) + ";")


class SchemaError(Exception):
    pass


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)

    def init(self) -> None:
        """Create a new database file (mode 0600) with the current schema."""
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.path.exists():
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(fd)
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        os.chmod(self.path, 0o600)

    def exists(self) -> bool:
        return self.path.exists()

    def schema_version(self) -> int:
        """0 if the file is not a Pastry database, 1 for the original layout, 2 for current."""
        with self.connect() as conn:
            has_meta = conn.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='meta'"
            ).fetchone()[0]
            if not has_meta:
                return 1 if self._has_entries(conn) else 0
            row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if row is None:
                return 1 if self._has_entries(conn) else 0
            return int(row[0])

    @staticmethod
    def _has_entries(conn: sqlite3.Connection) -> bool:
        return conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='entries'"
        ).fetchone()[0] > 0

    def require_current(self) -> None:
        version = self.schema_version()
        if version != SCHEMA_VERSION:
            raise SchemaError(
                f"The vault database is schema v{version}; this Pastry needs v{SCHEMA_VERSION}. "
                "Run: pastry migrate"
            )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        # Overwrite deleted content with zeros. Some SQLite builds leave it in free pages, which would
        # keep plaintext from migrated or deleted rows inside the database file.
        conn.execute("PRAGMA secure_delete = ON")
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    def get_setting(self, key: str, default: str) -> str:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO meta(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def entry_count(self) -> int:
        with self.connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0])
