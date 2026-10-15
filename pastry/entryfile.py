"""Single-entry export files (`.pastry`).

A `.pastry` file holds ONE entry, encrypted under a password chosen at export time
(Argon2id key derivation, AES-256-GCM). It contains no vault key and nothing from
the rest of the vault, and it can be opened without the Pastry server using the
`pastry` terminal UI. There is no recovery if the file's password is lost.
"""

from __future__ import annotations

import base64
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from . import crypto
from .crypto import CryptoError, KdfParams

ENTRY_FORMAT = "pastry-entry"
ENTRY_VERSION = 1
ENTRY_AAD = b"pastry:entry:v1"
VAULT_EXPORT_FORMAT = "pastry-export"  # whole-vault export, handled by the web UI
EXTENSION = ".pastry"
MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 256
MAX_FILE_BYTES = 1_000_000

# Upper bounds on the Argon2id cost read from a file, so a crafted file cannot make
# the terminal UI allocate gigabytes or spin for minutes.
_MAX_TIME_COST = 10
_MAX_MEMORY_KIB = 1_048_576
_MAX_PARALLELISM = 16


class EntryFileError(Exception):
    """`code` is one of: invalid, whole_vault, bad_password, weak_password, exists, io."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _normalize(entry: dict) -> dict:
    try:
        return {
            "name": str(entry["name"]),
            "url": str(entry.get("url", "")),
            "category": str(entry.get("category", "")),
            "favourite": bool(entry.get("favourite", False)),
            "username": str(entry.get("username", "")),
            "password": str(entry.get("password", "")),
            "notes": str(entry.get("notes", "")),
            "fields": [
                {"name": str(f["name"]), "value": str(f.get("value", "")), "secret": bool(f.get("secret", False))}
                for f in entry.get("fields", [])
            ],
            "created_at": str(entry.get("created_at", "")),
            "updated_at": str(entry.get("updated_at", "")),
        }
    except (KeyError, TypeError, AttributeError) as exc:
        raise EntryFileError("invalid", "The entry is malformed.") from exc


def seal_entry(entry: dict, passphrase: str, kdf: KdfParams | None = None) -> dict:
    """Encrypt one entry (a dict with name, url, category, favourite, username,
    password, notes, fields, created_at, updated_at) into a `.pastry` document."""
    if not MIN_PASSWORD_LEN <= len(passphrase) <= MAX_PASSWORD_LEN:
        raise EntryFileError(
            "weak_password",
            f"The file password must be {MIN_PASSWORD_LEN} to {MAX_PASSWORD_LEN} characters.",
        )
    kdf = kdf or KdfParams()
    item = _normalize(entry)
    item["exported_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    plaintext = json.dumps(item, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    salt = crypto.new_salt()
    key = crypto.derive_key(passphrase, salt, kdf)
    try:
        blob = crypto.seal(key, plaintext, ENTRY_AAD)
    finally:
        crypto.wipe(key)
    return {
        "format": ENTRY_FORMAT,
        "version": ENTRY_VERSION,
        "kdf": {"algorithm": "argon2id", **kdf.to_dict(), "salt": _b64(salt)},
        "data": _b64(blob),
    }


def open_entry(document: dict, passphrase: str) -> dict:
    """Decrypt a `.pastry` document. Raises EntryFileError (`bad_password` for a wrong
    password or a tampered file)."""
    try:
        if document["format"] == VAULT_EXPORT_FORMAT:
            raise EntryFileError(
                "whole_vault",
                "This is a whole-vault export, not a single entry. Import it in the web UI "
                "(Settings, Backup and export).",
            )
        if document["format"] != ENTRY_FORMAT or document["version"] != ENTRY_VERSION:
            raise EntryFileError("invalid", "This is not a Pastry entry file.")
        kdf = KdfParams.from_dict(document["kdf"])
        if not (1 <= kdf.time_cost <= _MAX_TIME_COST and 8 <= kdf.memory_cost <= _MAX_MEMORY_KIB
                and 1 <= kdf.parallelism <= _MAX_PARALLELISM):
            raise EntryFileError("invalid", "The file uses key-derivation settings outside the allowed range.")
        salt = _unb64(document["kdf"]["salt"])
        blob = _unb64(document["data"])
    except EntryFileError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise EntryFileError("invalid", "This is not a valid Pastry entry file.") from exc

    key = crypto.derive_key(passphrase, salt, kdf)
    try:
        raw = crypto.open_sealed(key, blob, ENTRY_AAD)
    except CryptoError as exc:
        raise EntryFileError("bad_password", "Wrong password, or the file is damaged.") from exc
    finally:
        crypto.wipe(key)
    try:
        data = json.loads(raw)
        entry = _normalize(data)
        entry["exported_at"] = str(data.get("exported_at", ""))
        return entry
    except (ValueError, AttributeError) as exc:
        raise EntryFileError("invalid", "The file decrypted but its contents are malformed.") from exc


def load_file(path: str | Path) -> dict:
    """Read and parse a `.pastry` file (no decryption)."""
    path = Path(path).expanduser()
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise EntryFileError("invalid", "The file is too large to be a Pastry entry.")
        document = json.loads(path.read_text(encoding="utf-8"))
    except EntryFileError:
        raise
    except OSError as exc:
        raise EntryFileError("io", f"Cannot read {path}: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise EntryFileError("invalid", "This is not a Pastry file.") from exc
    if not isinstance(document, dict) or "format" not in document:
        raise EntryFileError("invalid", "This is not a Pastry file.")
    return document


def write_file(path: str | Path, document: dict, overwrite: bool = False) -> Path:
    """Write a document with mode 0600. Refuses to replace a file unless `overwrite`."""
    path = Path(path).expanduser()
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise EntryFileError("exists", f"{path} already exists.") from exc
    except OSError as exc:
        raise EntryFileError("io", f"Cannot write {path}: {exc.strerror or exc}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(document, handle, separators=(",", ":"))
        handle.write("\n")
    return path


def suggested_filename(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.")[:60] or "entry"
    return f"pastry-{slug}{EXTENSION}"
