"""Entry storage and encryption (schema v2).

Layers
------
1. `meta_blob`: name, url, category, favourite, created/updated timestamps and
   the separate-password state (locked flag, salt, Argon2id parameters). Sealed
   with the vault key (DEK). Nothing in it is readable without the DEK.
2. `content_blob`: username, password, notes, custom fields. Sealed with the DEK
   for normal entries, or with the entry's own key for protected entries. The DEK
   cannot open a protected entry's content.

AAD binds each blob to the entry's random uid and to its layer, so blobs cannot
be swapped between entries or layers. Nonces are random 96-bit values from
`secrets`; with a single DEK the number of messages stays far below the level
where random-nonce collisions become a concern (about 2^32 per key).
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any

from . import crypto
from .crypto import CryptoError, KdfParams
from .db import Store
from .sharing_crypto import EnvelopeError, context as share_context, unwrap_key, wrap_key

EXPORT_FORMAT = "pastry-export"
EXPORT_VERSION = 1  # export layout is unchanged from v1.0 so older exports still import
EXPORT_AAD = b"pastry:export:v1"
UID_RE = re.compile(r"^[0-9a-f]{32}$")
META_AAD_PREFIX = b"pastry:meta2:"


class VaultError(Exception):
    """Vault operation failed. `code` is stable and maps to an HTTP status in web.py."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def meta_aad(uid: str) -> bytes:
    return META_AAD_PREFIX + uid.encode("ascii")


def meta_aad_entry(uid: str) -> bytes:
    """Metadata sealed under a per-entry key (format 5)."""
    return b"pastry:meta3:" + uid.encode("ascii")


def content_aad_entry(uid: str) -> bytes:
    """Unprotected content sealed under a per-entry key (format 5)."""
    return b"pastry:content:" + uid.encode("ascii") + b":E"


def entrykey_aad(uid: str, version: int) -> bytes:
    """An entry key wrapped under the owner's account key; bound to the entry and its key version."""
    return b"pastry:entrykey:" + uid.encode("ascii") + b":" + str(version).encode("ascii")


def content_aad(uid: str, locked: bool) -> bytes:
    return b"pastry:content:" + uid.encode("ascii") + (b":L" if locked else b":U")


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def normalize_meta(data: dict) -> dict:
    try:
        return {
            "name": str(data["name"]),
            "url": str(data.get("url", "")),
            "category": str(data.get("category", "")),
            "favourite": bool(data.get("favourite", False)),
        }
    except (KeyError, TypeError) as exc:
        raise VaultError("invalid", "Malformed entry metadata.") from exc


def normalize_content(data: dict) -> dict:
    try:
        fields = [
            {"name": str(f["name"]), "value": str(f.get("value", "")), "secret": bool(f.get("secret", False))}
            for f in data.get("fields", [])
        ]
        return {
            "username": str(data.get("username", "")),
            "password": str(data.get("password", "")),
            "notes": str(data.get("notes", "")),
            "fields": fields,
        }
    except (KeyError, TypeError, AttributeError) as exc:
        raise VaultError("invalid", "Malformed entry content.") from exc


def _open_json(key: bytes | bytearray, blob: bytes, aad: bytes) -> Any:
    try:
        return json.loads(crypto.open_sealed(key, blob, aad))
    except CryptoError as exc:
        raise VaultError("corrupt", "An entry could not be decrypted.") from exc


class Vault:
    """Operations on the encrypted entry table, scoped to one account.

    Entry formats
    -------------
    fmt 4 (legacy): metadata and unprotected content sealed directly under the account key.
    fmt 5: a random per-entry key K_e seals metadata and unprotected content. K_e is wrapped under
           the owner's account key (`key_blob`) and, for sharing, under each recipient's public key
           (`shares.envelope`). Protected content stays under the separate-password key, so no
           account, recipient or administrator can read it without that password.

    `keys` maps entry id to the separate-password key for entries that are currently unlocked in
    the caller's session. `private_key` is this account's X25519 private key (session only).
    """

    def __init__(self, store: Store, dek: bytes | bytearray, kdf: KdfParams, account_id: int = 0,
                 private_key: bytes | bytearray | None = None):
        self.store = store
        self.dek = dek
        self.kdf = kdf
        self.private_key = private_key
        # Every query is scoped to this account. An entry id that belongs to another account
        # is reported as "not found", so IDs cannot be used to reach other vaults.
        self.account_id = account_id

    # ----- entry keys and layers -------------------------------------------

    @staticmethod
    def _fmt(row: sqlite3.Row) -> int:
        return row["fmt"] if "fmt" in row.keys() else 4

    def _owner_entry_key(self, row: sqlite3.Row) -> bytes:
        try:
            return crypto.open_sealed(self.dek, row["key_blob"], entrykey_aad(row["uid"], row["key_version"]))
        except (CryptoError, TypeError) as exc:
            raise VaultError("corrupt", "An entry key could not be opened.") from exc

    def _layer(self, row: sqlite3.Row, k_e: bytes | None = None) -> tuple[bytes, bytes, bytes]:
        """(key, meta AAD, unprotected-content AAD) for the entry's current format."""
        if self._fmt(row) >= 5:
            key = k_e if k_e is not None else self._owner_entry_key(row)
            return key, meta_aad_entry(row["uid"]), content_aad_entry(row["uid"])
        return bytes(self.dek), meta_aad(row["uid"]), content_aad(row["uid"], False)

    def _fetch(self, conn: sqlite3.Connection, entry_id: int) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM entries WHERE id = ? AND owner_id = ?",
                           (entry_id, self.account_id)).fetchone()
        if row is None:
            raise VaultError("not_found", "Entry not found.")
        return row

    def _meta(self, row: sqlite3.Row, k_e: bytes | None = None) -> dict:
        key, meta_a, _ = self._layer(row, k_e)
        return _open_json(key, row["meta_blob"], meta_a)

    def _content(self, row: sqlite3.Row, meta: dict, key: bytes | bytearray | None,
                 k_e: bytes | None = None) -> dict:
        if meta["locked"]:
            if key is None:
                raise VaultError("locked", "Unlock this entry to view its contents.")
            return _open_json(key, row["content_blob"], content_aad(row["uid"], True))
        layer_key, _, content_a = self._layer(row, k_e)
        return _open_json(layer_key, row["content_blob"], content_a)

    def _seal_meta(self, row: sqlite3.Row, meta: dict, k_e: bytes | None = None) -> bytes:
        key, meta_a, _ = self._layer(row, k_e)
        return crypto.seal(key, _json(meta), meta_a)

    def _seal_plain(self, row: sqlite3.Row, content: dict, k_e: bytes | None = None) -> bytes:
        key, _, content_a = self._layer(row, k_e)
        return crypto.seal(key, _json(content), content_a)

    @staticmethod
    def _summary(row_id: int, meta: dict, key: bytes | bytearray | None) -> dict:
        return {
            "id": row_id,
            "name": meta["name"],
            "url": meta["url"],
            "category": meta["category"],
            "favourite": meta["favourite"],
            "locked": bool(meta["locked"]),
            "unlocked": (not meta["locked"]) or key is not None,
            "created_at": meta["created_at"],
            "updated_at": meta["updated_at"],
        }

    def _read_rows(self) -> list[sqlite3.Row]:
        with self.store.connect() as conn:
            return conn.execute("SELECT * FROM entries WHERE owner_id = ? ORDER BY id",
                                (self.account_id,)).fetchall()

    # ----- reads ---------------------------------------------------------

    def list(self, keys: dict[int, bytearray], query: str = "") -> list[dict]:
        """Summaries of all entries. A non-empty query also matches usernames of
        entries whose contents are readable. Matching happens in memory only."""
        needle = query.strip().lower()
        results = []
        for row in self._read_rows():
            meta = self._meta(row)
            key = keys.get(row["id"])
            if needle:
                haystack = [meta["name"], meta["url"], meta["category"]]
                try:
                    haystack.append(self._content(row, meta, key)["username"])
                except VaultError:
                    pass
                if not any(needle in str(text).lower() for text in haystack):
                    continue
            item = self._summary(row["id"], meta, key)
            item["shared_with"] = self._share_count(row["id"])
            results.append(item)
        results.sort(key=lambda item: item["name"].lower())
        return results

    def _share_count(self, entry_id: int) -> int:
        try:
            with self.store.connect() as conn:
                return int(conn.execute("SELECT COUNT(*) FROM shares WHERE entry_id = ?", (entry_id,)).fetchone()[0])
        except sqlite3.Error:
            return 0

    def get(self, entry_id: int, keys: dict[int, bytearray]) -> dict:
        with self.store.connect() as conn:
            row = self._fetch(conn, entry_id)
        meta = self._meta(row)
        key = keys.get(entry_id)
        item = self._summary(entry_id, meta, key)
        if meta["locked"] and key is None:
            return item  # no content leaves the server without the separate password
        item.update(self._content(row, meta, key))
        return item

    # ----- writes --------------------------------------------------------

    def create(self, meta: dict, content: dict, separate_password: str | None) -> int:
        meta = normalize_meta(meta)
        content = normalize_content(content)
        uid = secrets.token_hex(16)
        now = _now()
        k_e = secrets.token_bytes(32)
        row_like = {"uid": uid, "fmt": 5, "key_blob": None, "key_version": 0}
        lock_fields = {"locked": False, "lock_salt": None, "lock_kdf": None}
        if separate_password:
            salt = crypto.new_salt()
            key = crypto.derive_key(separate_password, salt, self.kdf)
            try:
                content_blob = crypto.seal(key, _json(content), content_aad(uid, True))
            finally:
                crypto.wipe(key)
            lock_fields = {"locked": True, "lock_salt": _b64(salt), "lock_kdf": self.kdf.to_dict()}
        else:
            content_blob = crypto.seal(k_e, _json(content), content_aad_entry(uid))
        full = {**meta, **lock_fields, "created_at": now, "updated_at": now}
        meta_blob = crypto.seal(k_e, _json(full), meta_aad_entry(uid))
        key_blob = crypto.seal(self.dek, k_e, entrykey_aad(row_like["uid"], 0))
        with self.store.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO entries (uid, meta_blob, content_blob, owner_id, fmt, key_blob, key_version) "
                "VALUES (?, ?, ?, ?, 5, ?, 0)",
                (uid, meta_blob, content_blob, self.account_id, key_blob),
            )
            return int(cur.lastrowid)

    def update(self, entry_id: int, meta: dict, content: dict, keys: dict[int, bytearray]) -> None:
        meta = normalize_meta(meta)
        content = normalize_content(content)
        with self.store.transaction() as conn:
            row = self._fetch(conn, entry_id)
            current = self._meta(row)
            key = keys.get(entry_id)
            if current["locked"] and key is None:
                raise VaultError("locked", "Unlock this entry before editing it.")
            full = {**current, **meta, "updated_at": _now()}
            if current["locked"]:
                content_blob = crypto.seal(key, _json(content), content_aad(row["uid"], True))
            else:
                content_blob = self._seal_plain(row, content)
            conn.execute(
                "UPDATE entries SET meta_blob = ?, content_blob = ? WHERE id = ? AND owner_id = ?",
                (self._seal_meta(row, full), content_blob, entry_id, self.account_id),
            )

    def delete(self, entry_id: int) -> None:
        with self.store.transaction() as conn:
            cur = conn.execute("DELETE FROM entries WHERE id = ? AND owner_id = ?", (entry_id, self.account_id))
            if cur.rowcount == 0:
                raise VaultError("not_found", "Entry not found.")
            conn.execute("DELETE FROM shares WHERE entry_id = ? AND owner_id = ?", (entry_id, self.account_id))

    # ----- separate-password layer ---------------------------------------

    @staticmethod
    def _unlock_with(row: sqlite3.Row, meta: dict, password: str) -> tuple[bytearray, dict]:
        if not meta["locked"]:
            raise VaultError("not_locked", "This entry has no separate password.")
        kdf = KdfParams.from_dict(meta["lock_kdf"])
        key = crypto.derive_key(password, _unb64(meta["lock_salt"]), kdf)
        try:
            content = json.loads(crypto.open_sealed(key, row["content_blob"], content_aad(row["uid"], True)))
        except CryptoError as exc:
            crypto.wipe(key)
            raise VaultError("bad_password", "Incorrect separate password.") from exc
        return key, content

    def unlock(self, entry_id: int, password: str) -> tuple[bytearray, dict]:
        """Return (key, content) if the separate password is correct.

        The GCM tag is the verifier, so a wrong password fails authentication.
        """
        with self.store.connect() as conn:
            row = self._fetch(conn, entry_id)
        return self._unlock_with(row, self._meta(row), password)

    def _set_lock(self, entry_id: int, expect_locked: bool, new_meta_lock: dict, content_blob: bytes) -> None:
        with self.store.transaction() as conn:
            row = self._fetch(conn, entry_id)
            current = self._meta(row)
            if bool(current["locked"]) != expect_locked:
                raise VaultError("conflict", "The entry changed; please try again.")
            full = {**current, **new_meta_lock, "updated_at": _now()}
            conn.execute(
                "UPDATE entries SET meta_blob = ?, content_blob = ? WHERE id = ? AND owner_id = ?",
                (self._seal_meta(row, full), content_blob, entry_id, self.account_id),
            )

    def enable_protection(self, entry_id: int, password: str) -> None:
        with self.store.connect() as conn:
            row = self._fetch(conn, entry_id)
        meta = self._meta(row)
        if meta["locked"]:
            raise VaultError("already_locked", "This entry already has a separate password.")
        content = self._content(row, meta, None)
        salt = crypto.new_salt()
        key = crypto.derive_key(password, salt, self.kdf)
        try:
            blob = crypto.seal(key, _json(content), content_aad(row["uid"], True))
        finally:
            crypto.wipe(key)
        lock = {"locked": True, "lock_salt": _b64(salt), "lock_kdf": self.kdf.to_dict()}
        self._set_lock(entry_id, expect_locked=False, new_meta_lock=lock, content_blob=blob)

    def change_protection(self, entry_id: int, new_password: str, old_key: bytes | bytearray) -> bytearray:
        """Re-seal the contents under a new separate password. Returns the new key."""
        with self.store.connect() as conn:
            row = self._fetch(conn, entry_id)
        if not self._meta(row)["locked"]:
            raise VaultError("not_locked", "This entry has no separate password.")
        content = _open_json(old_key, row["content_blob"], content_aad(row["uid"], True))
        salt = crypto.new_salt()
        new_key = crypto.derive_key(new_password, salt, self.kdf)
        blob = crypto.seal(new_key, _json(content), content_aad(row["uid"], True))
        lock = {"locked": True, "lock_salt": _b64(salt), "lock_kdf": self.kdf.to_dict()}
        try:
            self._set_lock(entry_id, expect_locked=True, new_meta_lock=lock, content_blob=blob)
        except VaultError:
            crypto.wipe(new_key)
            raise
        return new_key

    def remove_protection(self, entry_id: int, key: bytes | bytearray) -> None:
        with self.store.connect() as conn:
            row = self._fetch(conn, entry_id)
        if not self._meta(row)["locked"]:
            raise VaultError("not_locked", "This entry has no separate password.")
        content = _open_json(key, row["content_blob"], content_aad(row["uid"], True))
        blob = self._seal_plain(row, content)
        lock = {"locked": False, "lock_salt": None, "lock_kdf": None}
        self._set_lock(entry_id, expect_locked=True, new_meta_lock=lock, content_blob=blob)

    # ----- upgrade of legacy entries to per-entry keys -------------------------

    def upgrade_entries(self) -> int:
        """Convert this account's fmt 4 entries to per-entry keys. Atomic, and verified by reading
        every converted entry back before the transaction commits. Returns the number converted.

        Nothing is decrypted to disk. Separate-password content is not touched at all (it is
        already under its own key), and neither are IDs, owners or timestamps."""
        converted = 0
        with self.store.transaction() as conn:
            rows = conn.execute("SELECT * FROM entries WHERE owner_id = ? AND fmt = 4", (self.account_id,)).fetchall()
            for row in rows:
                converted += self._upgrade_row(conn, row)
            for row in conn.execute("SELECT * FROM entries WHERE owner_id = ? AND fmt = 5", (self.account_id,)):
                self._meta(row)  # verification: every entry key and metadata blob opens
        return converted

    def _upgrade_row(self, conn: sqlite3.Connection, row: sqlite3.Row) -> int:
        meta = self._meta(row)
        k_e = secrets.token_bytes(32)
        uid = row["uid"]
        if meta["locked"]:
            content_blob = row["content_blob"]  # separate-password layer is untouched
        else:
            content = self._content(row, meta, None)
            content_blob = crypto.seal(k_e, _json(content), content_aad_entry(uid))
        cur = conn.execute(
            "UPDATE entries SET meta_blob = ?, content_blob = ?, fmt = 5, key_blob = ?, key_version = 0 "
            "WHERE id = ? AND owner_id = ? AND fmt = 4",
            (crypto.seal(k_e, _json(meta), meta_aad_entry(uid)), content_blob,
             crypto.seal(self.dek, k_e, entrykey_aad(uid, 0)), row["id"], self.account_id),
        )
        return cur.rowcount

    # ----- sharing: owner side -----------------------------------------------

    def _ensure_v5(self, conn: sqlite3.Connection, entry_id: int) -> sqlite3.Row:
        row = self._fetch(conn, entry_id)
        if self._fmt(row) < 5:
            self._upgrade_row(conn, row)
            row = self._fetch(conn, entry_id)
        return row

    def list_access(self, entry_id: int) -> list[dict]:
        with self.store.connect() as conn:
            self._fetch(conn, entry_id)
            rows = conn.execute("SELECT recipient_id, can_edit, can_export, key_version, created_at, updated_at "
                                "FROM shares WHERE entry_id = ? AND owner_id = ? ORDER BY id",
                                (entry_id, self.account_id)).fetchall()
        return [{"recipient_id": r["recipient_id"], "can_edit": bool(r["can_edit"]),
                 "can_export": bool(r["can_export"]), "key_version": r["key_version"],
                 "created_at": r["created_at"], "updated_at": r["updated_at"]} for r in rows]

    def share(self, entry_id: int, recipient_id: int, recipient_public: bytes, can_edit: bool,
              can_export: bool, now: float) -> None:
        """Grant (or update) access. Wraps the entry key to the recipient; plaintext is never copied."""
        if recipient_id == self.account_id:
            raise VaultError("invalid", "An entry cannot be shared with its owner.")
        with self.store.transaction() as conn:
            row = self._ensure_v5(conn, entry_id)
            k_e = self._owner_entry_key(row)
            ctx = share_context(row["uid"], self.account_id, recipient_id, row["key_version"])
            try:
                envelope = wrap_key(recipient_public, k_e, ctx)
            except EnvelopeError as exc:
                raise VaultError("invalid", "The recipient's key could not be used.") from exc
            conn.execute(
                "INSERT INTO shares (entry_id, owner_id, recipient_id, can_edit, can_export, envelope, "
                "key_version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(entry_id, recipient_id) DO UPDATE SET can_edit = excluded.can_edit, "
                "can_export = excluded.can_export, envelope = excluded.envelope, "
                "key_version = excluded.key_version, updated_at = excluded.updated_at",
                (entry_id, self.account_id, recipient_id, int(can_edit), int(can_export), envelope,
                 row["key_version"], now, now),
            )

    def update_share(self, entry_id: int, recipient_id: int, can_edit: bool, can_export: bool, now: float) -> None:
        with self.store.transaction() as conn:
            self._fetch(conn, entry_id)
            cur = conn.execute(
                "UPDATE shares SET can_edit = ?, can_export = ?, updated_at = ? "
                "WHERE entry_id = ? AND owner_id = ? AND recipient_id = ?",
                (int(can_edit), int(can_export), now, entry_id, self.account_id, recipient_id),
            )
            if cur.rowcount == 0:
                raise VaultError("not_found", "That account does not have access.")

    def revoke(self, entry_id: int, recipient_ids: list[int] | None, publics: dict[int, bytes], now: float) -> int:
        """Remove access, then rotate the entry key for everyone who keeps it.

        `recipient_ids` None revokes everyone. `publics` maps each *remaining* recipient to their verified
        public key. The delete, re-sealing, new envelopes and key version change happen in one transaction,
        so no request can observe a half-rotated entry. Returns how many recipients were removed."""
        with self.store.transaction() as conn:
            row = self._ensure_v5(conn, entry_id)
            if recipient_ids is None:
                removed = conn.execute("DELETE FROM shares WHERE entry_id = ? AND owner_id = ?",
                                       (entry_id, self.account_id)).rowcount
            else:
                removed = 0
                for rid in recipient_ids:
                    removed += conn.execute(
                        "DELETE FROM shares WHERE entry_id = ? AND owner_id = ? AND recipient_id = ?",
                        (entry_id, self.account_id, rid)).rowcount
                if removed == 0:
                    raise VaultError("not_found", "That account does not have access.")
            self._rotate(conn, row, publics, now)
        return removed

    def _rotate(self, conn: sqlite3.Connection, row: sqlite3.Row, publics: dict[int, bytes], now: float) -> None:
        uid = row["uid"]
        old_key = self._owner_entry_key(row)
        meta = self._meta(row, old_key)
        new_key = secrets.token_bytes(32)
        new_version = row["key_version"] + 1
        if meta["locked"]:
            content_blob = row["content_blob"]
        else:
            content_blob = crypto.seal(new_key, _json(self._content(row, meta, None, old_key)), content_aad_entry(uid))
        conn.execute(
            "UPDATE entries SET meta_blob = ?, content_blob = ?, key_blob = ?, key_version = ? "
            "WHERE id = ? AND owner_id = ?",
            (crypto.seal(new_key, _json(meta), meta_aad_entry(uid)), content_blob,
             crypto.seal(self.dek, new_key, entrykey_aad(uid, new_version)), new_version,
             row["id"], self.account_id),
        )
        remaining = conn.execute("SELECT recipient_id FROM shares WHERE entry_id = ? AND owner_id = ?",
                                 (row["id"], self.account_id)).fetchall()
        for share in remaining:
            rid = share["recipient_id"]
            if rid not in publics:
                raise VaultError("invalid", "A remaining recipient's key could not be verified. Nothing was changed.")
            envelope = wrap_key(publics[rid], new_key, share_context(uid, self.account_id, rid, new_version))
            conn.execute("UPDATE shares SET envelope = ?, key_version = ?, updated_at = ? "
                         "WHERE entry_id = ? AND recipient_id = ?", (envelope, new_version, now, row["id"], rid))

    def remaining_recipients(self, entry_id: int, excluding: list[int] | None) -> list[int]:
        with self.store.connect() as conn:
            self._fetch(conn, entry_id)
            ids = [r["recipient_id"] for r in conn.execute(
                "SELECT recipient_id FROM shares WHERE entry_id = ? AND owner_id = ?",
                (entry_id, self.account_id))]
        if excluding is None:
            return []
        return [i for i in ids if i not in excluding]

    # ----- sharing: recipient side ---------------------------------------------

    def _shared_rows(self, conn: sqlite3.Connection, entry_id: int | None = None) -> list[sqlite3.Row]:
        sql = ("SELECT e.*, s.can_edit AS s_can_edit, s.can_export AS s_can_export, s.envelope AS s_envelope, "
               "s.key_version AS s_key_version, s.owner_id AS s_owner_id "
               "FROM shares s JOIN entries e ON e.id = s.entry_id AND e.owner_id = s.owner_id "
               "WHERE s.recipient_id = ?")
        params: list = [self.account_id]
        if entry_id is not None:
            sql += " AND e.id = ?"
            params.append(entry_id)
        return conn.execute(sql + " ORDER BY e.id", params).fetchall()

    def _shared_key(self, row: sqlite3.Row) -> bytes:
        if self.private_key is None:
            raise VaultError("not_found", "Entry not found.")
        # An envelope for an older key generation is rejected: it is bound to its version.
        if row["s_key_version"] != row["key_version"]:
            raise VaultError("not_found", "Entry not found.")
        ctx = share_context(row["uid"], row["s_owner_id"], self.account_id, row["s_key_version"])
        try:
            return unwrap_key(bytes(self.private_key), row["s_envelope"], ctx)
        except EnvelopeError as exc:
            raise VaultError("not_found", "Entry not found.") from exc

    def _shared_one(self, entry_id: int) -> tuple[sqlite3.Row, bytes, dict]:
        with self.store.connect() as conn:
            rows = self._shared_rows(conn, entry_id)
        if not rows:
            raise VaultError("not_found", "Entry not found.")
        row = rows[0]
        k_e = self._shared_key(row)
        return row, k_e, self._meta(row, k_e)

    @staticmethod
    def _permissions(row: sqlite3.Row) -> dict:
        return {"shared": True, "can_edit": bool(row["s_can_edit"]), "can_export": bool(row["s_can_export"]),
                "owner_id": row["s_owner_id"]}

    def list_shared(self, keys: dict[int, bytearray]) -> list[dict]:
        with self.store.connect() as conn:
            rows = self._shared_rows(conn)
        out = []
        for row in rows:
            try:
                k_e = self._shared_key(row)
                meta = self._meta(row, k_e)
            except VaultError:
                continue  # an envelope that does not open is simply not shown
            item = self._summary(row["id"], meta, keys.get(row["id"]))
            item.update(self._permissions(row))
            out.append(item)
        out.sort(key=lambda item: item["name"].lower())
        return out

    def get_shared(self, entry_id: int, keys: dict[int, bytearray]) -> dict:
        row, k_e, meta = self._shared_one(entry_id)
        key = keys.get(entry_id)
        item = self._summary(entry_id, meta, key)
        item.update(self._permissions(row))
        if meta["locked"] and key is None:
            return item
        item.update(self._content(row, meta, key, k_e))
        return item

    def unlock_shared(self, entry_id: int, password: str) -> tuple[bytearray, dict]:
        row, k_e, meta = self._shared_one(entry_id)
        return self._unlock_with(row, meta, password)

    def update_shared(self, entry_id: int, meta_in: dict, content: dict, keys: dict[int, bytearray],
                      now_iso: str | None = None) -> None:
        """Edit a shared entry. Requires the edit permission, which is re-read inside the transaction.
        Editors may change name, URL and content. Category, favourite, protection and sharing stay with the owner."""
        meta_in = normalize_meta(meta_in)
        content = normalize_content(content)
        with self.store.transaction() as conn:
            rows = self._shared_rows(conn, entry_id)
            if not rows:
                raise VaultError("not_found", "Entry not found.")
            row = rows[0]
            if not row["s_can_edit"]:
                raise VaultError("forbidden", "You have view-only access to this entry.")
            k_e = self._shared_key(row)
            current = self._meta(row, k_e)
            key = keys.get(entry_id)
            if current["locked"] and key is None:
                raise VaultError("locked", "Unlock this entry before editing it.")
            full = {**current, "name": meta_in["name"], "url": meta_in["url"], "updated_at": now_iso or _now()}
            if current["locked"]:
                content_blob = crypto.seal(key, _json(content), content_aad(row["uid"], True))
            else:
                content_blob = crypto.seal(k_e, _json(content), content_aad_entry(row["uid"]))
            conn.execute(
                "UPDATE entries SET meta_blob = ?, content_blob = ? WHERE id = ? AND owner_id = ? AND key_version = ?",
                (crypto.seal(k_e, _json(full), meta_aad_entry(row["uid"])), content_blob, entry_id,
                 row["s_owner_id"], row["s_key_version"]),
            )

    def shared_export_item(self, entry_id: int, keys: dict[int, bytearray]) -> dict:
        """Content of a shared entry for packaging. Requires the export permission."""
        row, k_e, meta = self._shared_one(entry_id)
        if not row["s_can_export"]:
            raise VaultError("forbidden", "You do not have permission to export this entry.")
        key = keys.get(entry_id)
        item = {"name": meta["name"], "url": meta["url"]}
        if meta["locked"] and key is None:
            item["locked"] = True
            return item
        item.update(self._content(row, meta, key, k_e))
        return item

    # ----- encrypted export / import -------------------------------------

    def export(self, passphrase: str) -> dict:
        """Encrypted document. Protected entries stay sealed under their own passwords."""
        items = []
        for row in self._read_rows():
            meta = self._meta(row)
            item = {
                "uid": row["uid"],
                "meta": {k: meta[k] for k in ("name", "url", "category", "favourite")},
                "locked": bool(meta["locked"]),
                "created_at": meta["created_at"],
                "updated_at": meta["updated_at"],
            }
            if meta["locked"]:
                item["lock_salt"] = meta["lock_salt"]
                item["lock_kdf"] = meta["lock_kdf"]
                item["sealed_content"] = _b64(row["content_blob"])
            else:
                item["content"] = self._content(row, meta, None)
            items.append(item)
        salt = crypto.new_salt()
        key = crypto.derive_key(passphrase, salt, self.kdf)
        try:
            blob = crypto.seal(key, _json(items), EXPORT_AAD)
        finally:
            crypto.wipe(key)
        return {
            "format": EXPORT_FORMAT,
            "version": EXPORT_VERSION,
            "kdf": {"algorithm": "argon2id", **self.kdf.to_dict(), "salt": _b64(salt)},
            "data": _b64(blob),
        }

    def import_(self, document: dict, passphrase: str) -> dict:
        """Import an export (v1 or v2 files). Entries whose uid already exists are skipped."""
        try:
            if document["format"] != EXPORT_FORMAT or document["version"] != EXPORT_VERSION:
                raise VaultError("invalid", "This is not a Pastry export file.")
            kdf = KdfParams.from_dict(document["kdf"])
            salt = _unb64(document["kdf"]["salt"])
            blob = _unb64(document["data"])
        except (KeyError, TypeError, ValueError) as exc:
            raise VaultError("invalid", "This is not a valid Pastry export file.") from exc

        key = crypto.derive_key(passphrase, salt, kdf)
        try:
            raw = crypto.open_sealed(key, blob, EXPORT_AAD)
        except CryptoError as exc:
            raise VaultError("bad_passphrase", "Wrong export passphrase, or the file is corrupted.") from exc
        finally:
            crypto.wipe(key)

        items = json.loads(raw)
        imported = skipped = 0
        with self.store.transaction() as conn:
            for item in items:
                uid = item.get("uid", "")
                if not UID_RE.match(uid):
                    raise VaultError("invalid", "Export contains an invalid entry identifier.")
                if conn.execute("SELECT 1 FROM entries WHERE uid = ?", (uid,)).fetchone():
                    skipped += 1
                    continue
                meta = normalize_meta(item["meta"])
                k_e = secrets.token_bytes(32)
                if item["locked"]:
                    content_blob = _unb64(item["sealed_content"])
                    lock = {"locked": True, "lock_salt": item["lock_salt"],
                            "lock_kdf": KdfParams.from_dict(item["lock_kdf"]).to_dict()}
                else:
                    content = normalize_content(item["content"])
                    content_blob = crypto.seal(k_e, _json(content), content_aad_entry(uid))
                    lock = {"locked": False, "lock_salt": None, "lock_kdf": None}
                full = {**meta, **lock, "created_at": str(item["created_at"]), "updated_at": str(item["updated_at"])}
                conn.execute(
                    "INSERT INTO entries (uid, meta_blob, content_blob, owner_id, fmt, key_blob, key_version) "
                    "VALUES (?, ?, ?, ?, 5, ?, 0)",
                    (uid, crypto.seal(k_e, _json(full), meta_aad_entry(uid)), content_blob, self.account_id,
                     crypto.seal(self.dek, k_e, entrykey_aad(uid, 0))),
                )
                imported += 1
        return {"imported": imported, "skipped": skipped}
