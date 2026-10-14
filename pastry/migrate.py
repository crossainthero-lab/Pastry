"""Schema migration v1 -> v2.

v1 kept timestamps, the locked flag and separate-password salt/parameters in
plaintext columns. v2 moves them into the encrypted metadata blob. Content blobs
are byte-identical across the migration, so entries and their separate-password
locks are preserved.

The whole migration runs in one SQLite transaction. Any error (including one
simulated by tests) rolls back, leaving the v1 database untouched. Callers should
also keep a backup (see cli.py, which creates one before calling this).
"""

from __future__ import annotations

import base64
import json
from typing import Callable

from . import crypto
from .db import PACKAGE_STATEMENTS, SCHEMA_VERSION, Store
from .vault import META_AAD_PREFIX

V1_META_PREFIX = b"pastry:meta:"

V2_ENTRIES = """
CREATE TABLE entries_v2 (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    uid          TEXT NOT NULL UNIQUE,
    meta_blob    BLOB NOT NULL,
    content_blob BLOB NOT NULL
)
"""


class MigrationError(Exception):
    pass


def migrate_v1_to_v2(
    store: Store,
    dek: bytes | bytearray,
    _fail_at_row: int | None = None,
    _log: Callable[[str], None] = lambda message: None,
) -> int:
    """Migrate in a single transaction. Returns the number of entries migrated.

    `_fail_at_row` is a test hook that raises partway through, to prove rollback.
    """
    if store.schema_version() != 1:
        raise MigrationError("The database is not schema v1; nothing to migrate.")

    with store.transaction() as conn:
        conn.execute("DROP TABLE IF EXISTS entries_v2")
        conn.execute(V2_ENTRIES)
        rows = conn.execute(
            "SELECT id, uid, meta_blob, content_blob, locked, lock_salt, lock_kdf, created_at, updated_at "
            "FROM entries ORDER BY id"
        ).fetchall()
        for index, row in enumerate(rows):
            if _fail_at_row is not None and index == _fail_at_row:
                raise MigrationError("simulated failure during migration")
            uid = row["uid"]
            v1_meta = json.loads(
                crypto.open_sealed(dek, row["meta_blob"], V1_META_PREFIX + uid.encode("ascii"))
            )
            lock_salt = row["lock_salt"]
            meta = {
                "name": v1_meta["name"],
                "url": v1_meta["url"],
                "category": v1_meta["category"],
                "favourite": bool(v1_meta["favourite"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "locked": bool(row["locked"]),
                "lock_salt": base64.b64encode(lock_salt).decode("ascii") if lock_salt else None,
                "lock_kdf": json.loads(row["lock_kdf"]) if row["lock_kdf"] else None,
            }
            meta_blob = crypto.seal(dek, json.dumps(meta, separators=(",", ":")).encode("utf-8"),
                                    META_AAD_PREFIX + uid.encode("ascii"))
            # Content blob is copied unchanged: its AAD and key are the same in v1 and v2.
            conn.execute(
                "INSERT INTO entries_v2 (id, uid, meta_blob, content_blob) VALUES (?, ?, ?, ?)",
                (row["id"], uid, meta_blob, row["content_blob"]),
            )
            _log(f"migrated entry {row['id']}")

        # Verify every migrated row decrypts before committing.
        for row in conn.execute("SELECT uid, meta_blob, content_blob FROM entries_v2").fetchall():
            check = json.loads(crypto.open_sealed(dek, row["meta_blob"], META_AAD_PREFIX + row["uid"].encode("ascii")))
            if "locked" not in check:
                raise MigrationError("verification failed: metadata incomplete")

        conn.execute("DROP TABLE entries")
        conn.execute("ALTER TABLE entries_v2 RENAME TO entries")
        conn.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("2",),  # this step produces schema v2 exactly; v2 -> v3 is migrate_v2_to_v3
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS rate_limits (key TEXT PRIMARY KEY, failures TEXT NOT NULL, "
            "blocked_until REAL NOT NULL DEFAULT 0)"
        )
    return len(rows)


def migrate_v2_to_v3(store: Store) -> None:
    """Additive: add the package and nonce tables. No existing data is touched.

    Needs no password: nothing is re-encrypted. Runs in one transaction.
    """
    if store.schema_version() != 2:
        raise MigrationError("The database is not schema v2; nothing to migrate.")
    with store.transaction() as conn:
        for statement in PACKAGE_STATEMENTS:
            conn.execute(statement)
        conn.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(SCHEMA_VERSION),),
        )
