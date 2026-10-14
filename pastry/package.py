"""`.pastry` offline encrypted packages (format version 1). See docs/CRYPTOGRAPHY-V12.md.

This module depends only on the standard library and `pastry.crypto`, so the
recipient's viewer does not need the server code.
"""

from __future__ import annotations

import base64
import json
import os
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import crypto
from .crypto import CryptoError, KdfParams

MAGIC = b"PSTRYPKG"
FORMAT_VERSION = 1
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_ENTRIES = 200
MAX_FIELDS = 200
WRAPPED_DEK_LEN = 1 + crypto.NONCE_LEN + crypto.KEY_LEN + crypto.TAG_LEN  # 61
MIN_PASSWORD = 12
MAX_PASSWORD = 256
HEADER_KEYS = {"kind", "name", "created_at", "access", "allow_copy", "expires_at", "kdf"}
SERVER_HEADER_KEYS = {"kind", "name", "created_at", "access", "allow_copy", "policy", "package_id",
                      "capability", "release_url", "kdf"}
AUTH_INFO = b"pastry-release-auth/v1"
PROOF_PREFIX = b"pastry-release-proof/v1"
WRAP_PREFIX = b"pastry-release-wrap/v1"
AFTER_OPEN_SECONDS = (300, 900, 3600, 86400)
MAX_ABSOLUTE_SECONDS = 30 * 24 * 3600
KDF_BOUNDS = {"time_cost": (1, 10), "memory_cost": (8192, 262144), "parallelism": (1, 8)}
ENTRY_LIMITS = {"name": 200, "url": 2000, "username": 500, "password": 5000, "notes": 10000}
FIELD_LIMITS = {"name": 100, "value": 5000}


class PackageError(Exception):
    """Malformed, unsupported or wrong-password package. Messages never contain plaintext."""


@dataclass
class Header:
    name: str
    created_at: str
    access: str
    allow_copy: bool
    expires_at: str | None
    kdf: KdfParams
    salt: bytes
    raw: bytes = b""  # exact header bytes, used as AAD
    # Server-enforced packages only:
    policy: dict | None = None
    package_id: int | None = None
    capability: bytes | None = None
    release_url: str | None = None

    def to_json(self) -> dict:
        return {
            "kind": "pastry-package",
            "name": self.name,
            "created_at": self.created_at,
            "access": self.access,
            "allow_copy": self.allow_copy,
            "expires_at": self.expires_at,
            "kdf": {"algorithm": "argon2id", **self.kdf.to_dict(), "salt": base64.b64encode(self.salt).decode()},
        }

    def expired(self, now: datetime) -> bool:
        return self.expires_at is not None and now >= parse_time(self.expires_at)

    @property
    def is_server(self) -> bool:
        return self.access == "server"


def _now_iso(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_time(text: str) -> datetime:
    try:
        value = datetime.fromisoformat(text)
    except (TypeError, ValueError) as exc:
        raise PackageError("Malformed package header.") from exc
    if value.tzinfo is None:
        raise PackageError("Malformed package header.")
    return value


def _clean_name(name: str) -> str:
    name = name.strip()
    if not 1 <= len(name) <= 100 or any(ord(c) < 32 for c in name):
        raise PackageError("Package name must be 1 to 100 printable characters.")
    return name


def safe_filename(name: str) -> str:
    """A download name made only of [A-Za-z0-9-_], so it can never carry a path."""
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-")[:60] or "package"
    return f"{slug}.pastry"


# ----- server-enforced key derivation (client and server share these) --------


def derive_keys(password: str, salt: bytes, kdf: KdfParams) -> tuple[bytearray, bytes]:
    """Return (K_pw, K_auth). K_pw is wiped by the caller; K_auth is what the server stores."""
    k_pw = crypto.derive_key(password, salt, kdf)
    k_auth = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=AUTH_INFO).derive(bytes(k_pw))
    return k_pw, k_auth


def proof_for(k_auth: bytes, package_id: int, nonce: str) -> bytes:
    import hashlib
    import hmac

    return hmac.new(k_auth, PROOF_PREFIX + str(package_id).encode() + b"|" + nonce.encode(), hashlib.sha256).digest()


def _validate_policy(policy: Any) -> dict:
    if not isinstance(policy, dict):
        raise PackageError("Malformed package policy.")
    kind = policy.get("type")
    if kind == "after_open" and set(policy) == {"type", "seconds"} and policy["seconds"] in AFTER_OPEN_SECONDS:
        return policy
    if kind == "absolute" and set(policy) == {"type", "expires_at"}:
        parse_time(str(policy["expires_at"]))
        return {"type": "absolute", "expires_at": str(policy["expires_at"])}
    if kind == "one_time" and set(policy) == {"type"}:
        return policy
    raise PackageError("Unsupported package policy.")


def _validate_release_url(url: str) -> str:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return url
    if parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost"):
        return url  # local development only; the client refuses plain HTTP to any other host
    raise PackageError("The release address must be an https:// address.")


# ----- building ---------------------------------------------------------------


def _check_entries(entries: list[dict]) -> list[dict]:
    if not 1 <= len(entries) <= MAX_ENTRIES:
        raise PackageError(f"A package holds 1 to {MAX_ENTRIES} entries.")
    cleaned = []
    for entry in entries:
        item = {}
        for key, limit in ENTRY_LIMITS.items():
            value = str(entry.get(key, ""))
            if len(value) > limit:
                raise PackageError(f"Field '{key}' is longer than {limit} characters.")
            item[key] = value
        if not item["name"]:
            raise PackageError("Every entry needs a name.")
        fields = entry.get("fields", [])
        if len(fields) > MAX_FIELDS:
            raise PackageError(f"An entry can hold at most {MAX_FIELDS} custom fields.")
        item["fields"] = []
        for f in fields:
            name, value = str(f.get("name", "")), str(f.get("value", ""))
            if not 1 <= len(name) <= FIELD_LIMITS["name"] or len(value) > FIELD_LIMITS["value"]:
                raise PackageError("A custom field is empty or too long.")
            item["fields"].append({"name": name, "value": value, "secret": bool(f.get("secret", False))})
        cleaned.append(item)
    return cleaned


def build_package(
    entries: list[dict],
    password: str,
    name: str,
    *,
    allow_copy: bool,
    expires_at: datetime | None,
    kdf: KdfParams,
    now: datetime | None = None,
) -> bytes:
    """Return the complete `.pastry` file as bytes. Nothing is written to disk here."""
    if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
        raise PackageError(f"The package password must be {MIN_PASSWORD} to {MAX_PASSWORD} characters.")
    cleaned = _check_entries(entries)
    payload = json.dumps({"v": 1, "entries": cleaned}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise PackageError("The selected entries are too large for one package.")

    salt = crypto.new_salt()
    header_obj = {
        "kind": "pastry-package",
        "name": _clean_name(name),
        "created_at": _now_iso(now),
        "access": "offline",
        "allow_copy": bool(allow_copy),
        "expires_at": _now_iso(expires_at) if expires_at else None,
        "kdf": {"algorithm": "argon2id", **kdf.to_dict(), "salt": base64.b64encode(salt).decode()},
    }
    header = json.dumps(header_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(header) > MAX_HEADER_BYTES:
        raise PackageError("Package header too large.")
    prefix = MAGIC + bytes([FORMAT_VERSION]) + struct.pack(">I", len(header)) + header

    dek = crypto.new_key()
    kek = crypto.derive_key(password, salt, kdf)
    try:
        wrapped = crypto.seal(kek, bytes(dek), prefix)
        sealed = crypto.seal(dek, payload, prefix)
    finally:
        crypto.wipe(kek)
        crypto.wipe(dek)
    assert len(wrapped) == WRAPPED_DEK_LEN
    return prefix + wrapped + sealed


def build_server_package(
    entries: list[dict],
    name: str,
    *,
    allow_copy: bool,
    policy: dict,
    release_url: str,
    package_id: int,
    capability: bytes,
    salt: bytes,
    kdf: KdfParams,
    k_r: bytes,
    now: datetime,
) -> bytes:
    """A server-enforced `.pastry` file. Contains no password-derived ciphertext:
    the DEK is wrapped only under the release key K_r, which the server releases."""
    if len(capability) != 32 or len(salt) != crypto.SALT_LEN:
        raise PackageError("Internal error: bad capability or salt length.")
    cleaned = _check_entries(entries)
    payload = json.dumps({"v": 1, "entries": cleaned}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise PackageError("The selected entries are too large for one package.")
    header_obj = {
        "kind": "pastry-package",
        "name": _clean_name(name),
        "created_at": _now_iso(now),
        "access": "server",
        "allow_copy": bool(allow_copy),
        "policy": _validate_policy(policy),
        "package_id": int(package_id),
        "capability": base64.urlsafe_b64encode(capability).rstrip(b"=").decode("ascii"),
        "release_url": _validate_release_url(release_url),
        "kdf": {"algorithm": "argon2id", **kdf.to_dict(), "salt": base64.b64encode(salt).decode()},
    }
    header = json.dumps(header_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(header) > MAX_HEADER_BYTES:
        raise PackageError("Package header too large.")
    prefix = MAGIC + bytes([FORMAT_VERSION]) + struct.pack(">I", len(header)) + header
    dek = crypto.new_key()
    try:
        wrapped = crypto.seal(k_r, bytes(dek), prefix)
        sealed = crypto.seal(dek, payload, prefix)
    finally:
        crypto.wipe(dek)
    return prefix + wrapped + sealed


def open_with_release_key(data: bytes, k_r: bytes) -> tuple[Header, list[dict]]:
    """Decrypt a server-enforced package once the server has released K_r."""
    header, offset = read_header(data)
    if not header.is_server:
        raise PackageError("This is not a server-enforced package.")
    wrapped = data[offset : offset + WRAPPED_DEK_LEN]
    sealed = data[offset + WRAPPED_DEK_LEN :]
    try:
        dek = bytearray(crypto.open_sealed(k_r, wrapped, header.raw))
    except CryptoError as exc:
        raise PackageError("The release key does not open this package.") from exc
    try:
        payload = crypto.open_sealed(dek, sealed, header.raw)
    except CryptoError as exc:
        raise PackageError("The package has been modified.") from exc
    finally:
        crypto.wipe(dek)
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise PackageError("Package contents are malformed.") from exc
    if not isinstance(obj, dict) or obj.get("v") != 1 or not isinstance(obj.get("entries"), list):
        raise PackageError("Package contents are malformed.")
    return header, _check_entries(obj["entries"])


# ----- reading ----------------------------------------------------------------


def read_header(data: bytes) -> tuple[Header, int]:
    """Parse and validate the plaintext structure. Returns (header, offset of wrapped DEK)."""
    if len(data) > MAX_FILE_BYTES:
        raise PackageError("This file is larger than a Pastry package can be.")
    if len(data) < len(MAGIC) + 5 or data[: len(MAGIC)] != MAGIC:
        raise PackageError("This is not a Pastry package.")
    version = data[len(MAGIC)]
    if version != FORMAT_VERSION:
        raise PackageError(f"Unsupported package format version {version}. Upgrade the Pastry viewer.")
    (length,) = struct.unpack(">I", data[len(MAGIC) + 1 : len(MAGIC) + 5])
    if length == 0 or length > MAX_HEADER_BYTES:
        raise PackageError("Malformed package header length.")
    start = len(MAGIC) + 5
    end = start + length
    if end + WRAPPED_DEK_LEN + crypto.NONCE_LEN + crypto.TAG_LEN + 1 > len(data):
        raise PackageError("The package is truncated.")
    try:
        obj = json.loads(data[start:end].decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise PackageError("Malformed package header.") from exc
    if not isinstance(obj, dict) or obj.get("kind") != "pastry-package":
        raise PackageError("Malformed package header.")
    if obj.get("access") == "server":
        if set(obj) != SERVER_HEADER_KEYS:
            raise PackageError("Malformed package header.")
    elif obj.get("access") == "offline":
        if set(obj) != HEADER_KEYS:
            raise PackageError("Malformed package header.")
    else:
        raise PackageError("Unsupported package access type.")
    if not isinstance(obj["allow_copy"], bool):
        raise PackageError("Malformed package header.")
    kdf_obj = obj["kdf"]
    if not isinstance(kdf_obj, dict) or kdf_obj.get("algorithm") != "argon2id":
        raise PackageError("Unsupported key derivation in package.")
    for key, (low, high) in KDF_BOUNDS.items():
        if not isinstance(kdf_obj.get(key), int) or not low <= kdf_obj[key] <= high:
            raise PackageError("Package key-derivation parameters are outside the allowed range.")
    try:
        salt = base64.b64decode(kdf_obj["salt"], validate=True)
    except (ValueError, TypeError) as exc:
        raise PackageError("Malformed package salt.") from exc
    if len(salt) != crypto.SALT_LEN:
        raise PackageError("Malformed package salt.")
    name = obj["name"]
    if not isinstance(name, str):
        raise PackageError("Malformed package header.")
    server_fields: dict = {}
    if obj["access"] == "server":
        server_fields = {
            "policy": _validate_policy(obj["policy"]),
            "package_id": obj["package_id"] if isinstance(obj["package_id"], int) else None,
            "capability": _decode_b64url(obj["capability"]),
            "release_url": _validate_release_url(str(obj["release_url"])),
        }
        if server_fields["package_id"] is None or len(server_fields["capability"]) != 32:
            raise PackageError("Malformed package header.")
    header = Header(
        name=name,
        created_at=str(obj["created_at"]),
        access=obj["access"],
        allow_copy=obj["allow_copy"],
        expires_at=obj.get("expires_at") if obj.get("expires_at") is None else str(obj.get("expires_at")),
        kdf=KdfParams(kdf_obj["time_cost"], kdf_obj["memory_cost"], kdf_obj["parallelism"]),
        salt=salt,
        raw=data[: end],
        **server_fields,
    )
    if header.expires_at is not None:
        parse_time(header.expires_at)
    parse_time(header.created_at)
    return header, end


def _decode_b64url(text: Any) -> bytes:
    if not isinstance(text, str):
        raise PackageError("Malformed package header.")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise PackageError("Malformed package header.") from exc


def inspect_package(data: bytes) -> Header:
    """Safe metadata only. Never decrypts anything."""
    header, _ = read_header(data)
    return header


def open_package(data: bytes, password: str) -> tuple[Header, list[dict]]:
    """Decrypt a package. Raises PackageError with a message that reveals no plaintext."""
    header, offset = read_header(data)
    if header.is_server:
        raise PackageError("This package is server-enforced. Open it with `pastry open` so the release server can be reached.")
    wrapped = data[offset : offset + WRAPPED_DEK_LEN]
    sealed = data[offset + WRAPPED_DEK_LEN :]
    if not sealed or len(sealed) > MAX_PAYLOAD_BYTES + 64:
        raise PackageError("Malformed package payload.")
    kek = crypto.derive_key(password, header.salt, header.kdf)
    try:
        dek = bytearray(crypto.open_sealed(kek, wrapped, header.raw))
    except CryptoError as exc:
        raise PackageError("The password is wrong, or the package has been modified.") from exc
    finally:
        crypto.wipe(kek)
    try:
        payload = crypto.open_sealed(dek, sealed, header.raw)
    except CryptoError as exc:
        raise PackageError("The password is wrong, or the package has been modified.") from exc
    finally:
        crypto.wipe(dek)
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise PackageError("Package contents are malformed.") from exc
    if not isinstance(obj, dict) or obj.get("v") != 1 or not isinstance(obj.get("entries"), list):
        raise PackageError("Package contents are malformed.")
    entries = _check_entries(obj["entries"])
    return header, entries


def read_package_file(path: str | os.PathLike) -> bytes:
    """Read a package file, refusing anything that is not a bounded regular file."""
    st = os.stat(path)
    if not os.path.isfile(path):
        raise PackageError("That is not a regular file.")
    if st.st_size > MAX_FILE_BYTES:
        raise PackageError("This file is larger than a Pastry package can be.")
    with open(path, "rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise PackageError("This file is larger than a Pastry package can be.")
    return data
