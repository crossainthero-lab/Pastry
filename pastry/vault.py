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

from . import crypto, entryfile
from .crypto import CryptoError, KdfParams
from .db import Store

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
    """Operations on the encrypted entry table.

    `keys` maps entry id to the separate-password key for entries that are
    currently unlocked in the caller's session. Only those entries can be read or
    changed while protected.
    """

    def __init__(self, store: Store, dek: bytes | bytearray, kdf: KdfParams):
        self.store = store
        self.dek = dek
        self.kdf = kdf

    # ----- helpers -------------------------------------------------------

    @staticmethod
    def _fetch(conn: sqlite3.Connection, entry_id: int) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
        if row is None:
            raise VaultError("not_found", "Entry not found.")
        return row

    def _meta(self, row: sqlite3.Row) -> dict:
        return _open_json(self.dek, row["meta_blob"], meta_aad(row["uid"]))

    def _content(self, row: sqlite3.Row, meta: dict, key: bytes | bytearray | None) -> dict:
        if meta["locked"]:
            if key is None:
                raise VaultError("locked", "Unlock this entry to view its contents.")
            return _open_json(key, row["content_blob"], content_aad(row["uid"], True))
        return _open_json(self.dek, row["content_blob"], content_aad(row["uid"], False))

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
            return conn.execute("SELECT * FROM entries ORDER BY id").fetchall()

    def _seal_meta(self, uid: str, meta: dict) -> bytes:
        return crypto.seal(self.dek, _json(meta), meta_aad(uid))

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
            results.append(self._summary(row["id"], meta, key))
        results.sort(key=lambda item: item["name"].lower())
        return results

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
            content_blob = crypto.seal(self.dek, _json(content), content_aad(uid, False))
        full = {**meta, **lock_fields, "created_at": now, "updated_at": now}
        with self.store.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO entries (uid, meta_blob, content_blob) VALUES (?, ?, ?)",
                (uid, self._seal_meta(uid, full), content_blob),
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
            uid = row["uid"]
            full = {**current, **meta, "updated_at": _now()}
            if current["locked"]:
                content_blob = crypto.seal(key, _json(content), content_aad(uid, True))
            else:
                content_blob = crypto.seal(self.dek, _json(content), content_aad(uid, False))
            conn.execute(
                "UPDATE entries SET meta_blob = ?, content_blob = ? WHERE id = ?",
                (self._seal_meta(uid, full), content_blob, entry_id),
            )

    def delete(self, entry_id: int) -> None:
        with self.store.transaction() as conn:
            cur = conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
            if cur.rowcount == 0:
                raise VaultError("not_found", "Entry not found.")

    # ----- separate-password layer ---------------------------------------

    def unlock(self, entry_id: int, password: str) -> tuple[bytearray, dict]:
        """Return (key, content) if the separate password is correct.

        The GCM tag is the verifier, so a wrong password fails authentication.
        """
        with self.store.connect() as conn:
            row = self._fetch(conn, entry_id)
        meta = self._meta(row)
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

    def _set_lock(self, entry_id: int, expect_locked: bool, new_meta_lock: dict, content_blob: bytes) -> None:
        with self.store.transaction() as conn:
            row = self._fetch(conn, entry_id)
            current = self._meta(row)
            if bool(current["locked"]) != expect_locked:
                raise VaultError("conflict", "The entry changed; please try again.")
            full = {**current, **new_meta_lock, "updated_at": _now()}
            conn.execute(
                "UPDATE entries SET meta_blob = ?, content_blob = ? WHERE id = ?",
                (self._seal_meta(row["uid"], full), content_blob, entry_id),
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
        blob = crypto.seal(self.dek, _json(content), content_aad(row["uid"], False))
        lock = {"locked": False, "lock_salt": None, "lock_kdf": None}
        self._set_lock(entry_id, expect_locked=True, new_meta_lock=lock, content_blob=blob)

    # ----- encrypted export / import -------------------------------------

    def export_entry(self, entry_id: int, keys: dict[int, bytearray], passphrase: str) -> tuple[str, dict]:
        """One entry as a `.pastry` document under its own password. A protected entry
        must be unlocked in the caller's session first. Returns (name, document)."""
        with self.store.connect() as conn:
            row = self._fetch(conn, entry_id)
        meta = self._meta(row)
        content = self._content(row, meta, keys.get(entry_id))
        try:
            document = entryfile.seal_entry(
                {
                    "name": meta["name"], "url": meta["url"], "category": meta["category"],
                    "favourite": meta["favourite"], "created_at": meta["created_at"],
                    "updated_at": meta["updated_at"], **content,
                },
                passphrase,
                self.kdf,
            )
        except entryfile.EntryFileError as exc:
            raise VaultError("invalid", exc.message) from exc
        return meta["name"], document

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
                if item["locked"]:
                    content_blob = _unb64(item["sealed_content"])
                    lock = {"locked": True, "lock_salt": item["lock_salt"],
                            "lock_kdf": KdfParams.from_dict(item["lock_kdf"]).to_dict()}
                else:
                    content = normalize_content(item["content"])
                    content_blob = crypto.seal(self.dek, _json(content), content_aad(uid, False))
                    lock = {"locked": False, "lock_salt": None, "lock_kdf": None}
                full = {**meta, **lock, "created_at": str(item["created_at"]), "updated_at": str(item["updated_at"])}
                conn.execute(
                    "INSERT INTO entries (uid, meta_blob, content_blob) VALUES (?, ?, ?)",
                    (uid, self._seal_meta(uid, full), content_blob),
                )
                imported += 1
        return {"imported": imported, "skipped": skipped}
