"""Per-recipient key envelopes for entry sharing. Design: docs/MULTIUSER-CRYPTO.md.

Construction (ECIES-style, established primitives only):
  eph = fresh X25519 key pair
  shared = X25519(eph_private, recipient_public)
  key = HKDF-SHA256(shared, salt = eph_public || recipient_public, info = "pastry-share/v1|" + context)
  envelope = eph_public (32) || AES-256-GCM(key, entry_key, aad = context)

`context` binds the envelope to one entry, one recipient, one owner and one key version, so an
envelope cannot be replayed for another entry, recipient or generation.

The envelope is not sender-authenticated. In this server-side-decryption design the trusted
server performs the wrapping; a compromised server can substitute keys (see the design document).
Public keys are protected at rest by a server-keyed MAC (`bind_public_key`).
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import secrets

INFO_PREFIX = b"pastry-share/v1|"
BIND_INFO = b"pastry-pubkey-binding/v1"
ENVELOPE_VERSION = 1


class EnvelopeError(Exception):
    """Wrapping or unwrapping failed. Carries no key material."""


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_raw, public_raw), both 32 bytes."""
    private = X25519PrivateKey.generate()
    return (
        private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                              serialization.NoEncryption()),
        private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
    )


def public_from_private(private_raw: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private_raw).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(public_raw: bytes) -> str:
    """Short, human-comparable digest of a public key (for out-of-band verification)."""
    digest = hashlib.sha256(b"pastry-fingerprint/v1|" + public_raw).hexdigest()[:40]
    return " ".join(digest[i:i + 5] for i in range(0, 40, 5))


def context(entry_uid: str, owner_id: int, recipient_id: int, version: int) -> bytes:
    return f"{ENVELOPE_VERSION}|{entry_uid}|{owner_id}|{recipient_id}|{version}".encode("ascii")


def _derive(shared: bytes, eph_pub: bytes, recipient_pub: bytes, ctx: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + recipient_pub,
                info=INFO_PREFIX + ctx).derive(shared)


def wrap_key(recipient_public: bytes, entry_key: bytes, ctx: bytes) -> bytes:
    if len(recipient_public) != 32 or len(entry_key) != 32:
        raise EnvelopeError("bad key length")
    eph_private = X25519PrivateKey.generate()
    eph_public = eph_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    try:
        shared = eph_private.exchange(X25519PublicKey.from_public_bytes(recipient_public))
    except ValueError as exc:  # low-order or invalid point
        raise EnvelopeError("invalid recipient key") from exc
    key = _derive(shared, eph_public, recipient_public, ctx)
    nonce = secrets.token_bytes(12)
    return bytes([ENVELOPE_VERSION]) + eph_public + nonce + AESGCM(key).encrypt(nonce, entry_key, ctx)


def unwrap_key(recipient_private: bytes, envelope: bytes, ctx: bytes) -> bytes:
    if len(envelope) < 1 + 32 + 12 + 16 or envelope[0] != ENVELOPE_VERSION:
        raise EnvelopeError("unrecognised envelope")
    eph_public = envelope[1:33]
    nonce = envelope[33:45]
    ciphertext = envelope[45:]
    try:
        private = X25519PrivateKey.from_private_bytes(recipient_private)
        shared = private.exchange(X25519PublicKey.from_public_bytes(eph_public))
        recipient_public = private.public_key().public_bytes(serialization.Encoding.Raw,
                                                             serialization.PublicFormat.Raw)
        key = _derive(shared, eph_public, recipient_public, ctx)
        return AESGCM(key).decrypt(nonce, ciphertext, ctx)
    except (InvalidTag, ValueError) as exc:
        raise EnvelopeError("envelope could not be opened") from exc


def binding_key(server_secret: bytes) -> bytes:
    """Derive the public-key binding key from a server secret (the release KEK)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=BIND_INFO).derive(server_secret)


def bind_public_key(bind_key: bytes, account_id: int, public_raw: bytes) -> bytes:
    return hmac.new(bind_key, f"{account_id}|".encode() + public_raw, hashlib.sha256).digest()


def verify_public_key(bind_key: bytes, account_id: int, public_raw: bytes, mac: bytes) -> bool:
    return hmac.compare_digest(bind_public_key(bind_key, account_id, public_raw), mac)
