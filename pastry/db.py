"""SQLite storage (schema v2). Every user-supplied value lives inside an encrypted blob.

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

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    uid          TEXT NOT NULL UNIQUE,      -- random, used as AAD
    meta_blob    BLOB NOT NULL,             -- vault key: name, url, category, favourite, timestamps, lock info
    content_blob BLOB NOT NULL              -- vault key or entry key: username, password, notes, fields
);
CREATE TABLE IF NOT EXISTS rate_limits (
    key           TEXT PRIMARY KEY,
    failures      TEXT NOT NULL,            -- JSON list of failure times (seconds since epoch)
    blocked_until REAL NOT NULL DEFAULT 0
);
"""


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
