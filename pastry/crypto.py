"""Cryptographic primitives.

Only established libraries are used:
- argon2-cffi for Argon2id password hashing and key derivation.
- cryptography (AES-256-GCM) for authenticated encryption.

Nothing here invents an algorithm. Secrets are handled as bytearray where
practical so they can be overwritten (best effort; Python cannot guarantee
that no copies remain in memory).
"""

from __future__ import annotations

import secrets
import unicodedata
from dataclasses import asdict, dataclass

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32  # AES-256
NONCE_LEN = 12  # 96-bit GCM nonce, random per message
SALT_LEN = 16
TAG_LEN = 16
FORMAT_VERSION = 1  # first byte of every sealed blob


class CryptoError(Exception):
    """Decryption or authentication failed. Carries no secret details."""


@dataclass
class KdfParams:
    """Argon2id cost parameters. Stored alongside the data they protect."""

    time_cost: int = 3
    memory_cost: int = 65536  # KiB, i.e. 64 MiB
    parallelism: int = 4

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "KdfParams":
        return cls(
            time_cost=int(data["time_cost"]),
            memory_cost=int(data["memory_cost"]),
            parallelism=int(data["parallelism"]),
        )


def normalize_password(password: str) -> bytes:
    return unicodedata.normalize("NFC", password).encode("utf-8")


def _hasher(params: KdfParams) -> PasswordHasher:
    return PasswordHasher(
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=32,
        salt_len=SALT_LEN,
        type=Type.ID,
    )


def hash_password(password: str, params: KdfParams) -> str:
    """Return an encoded Argon2id hash (includes its own random salt)."""
    return _hasher(params).hash(normalize_password(password))


def verify_password_hash(encoded: str, password: str) -> bool:
    """Check a password against an encoded Argon2id hash. Never raises on mismatch."""
    try:
        # verify() reads the cost parameters from the encoded hash itself.
        return _hasher(KdfParams()).verify(encoded, normalize_password(password))
    except (VerificationError, InvalidHashError):
        return False


def derive_key(password: str, salt: bytes, params: KdfParams) -> bytearray:
    """Derive a 256-bit key from a password with Argon2id."""
    raw = hash_secret_raw(
        secret=normalize_password(password),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )
    return bytearray(raw)


def new_key() -> bytearray:
    return bytearray(secrets.token_bytes(KEY_LEN))


def new_salt() -> bytes:
    return secrets.token_bytes(SALT_LEN)


def seal(key: bytes | bytearray, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt and authenticate with AES-256-GCM.

    Output layout: version (1 byte) || nonce (12 bytes) || ciphertext || tag.
    `aad` binds the blob to its context so it cannot be moved to another record.
    """
    nonce = secrets.token_bytes(NONCE_LEN)
    ciphertext = AESGCM(bytes(key)).encrypt(nonce, plaintext, aad)
    return bytes([FORMAT_VERSION]) + nonce + ciphertext


def open_sealed(key: bytes | bytearray, blob: bytes, aad: bytes) -> bytes:
    """Verify and decrypt a blob produced by `seal`. Raises CryptoError on any failure."""
    if len(blob) < 1 + NONCE_LEN + TAG_LEN or blob[0] != FORMAT_VERSION:
        raise CryptoError("unrecognised ciphertext")
    nonce = blob[1 : 1 + NONCE_LEN]
    ciphertext = blob[1 + NONCE_LEN :]
    try:
        return AESGCM(bytes(key)).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoError("authentication failed") from exc


def wipe(buffer: bytearray | None) -> None:
    """Overwrite a bytearray in place (best effort)."""
    if buffer is not None:
        buffer[:] = bytes(len(buffer))
