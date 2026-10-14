"""Per-account X25519 key pairs for entry sharing. Design: docs/MULTIUSER-CRYPTO.md.

- The private key is sealed under the account's own vault key, so only that account's session
  can use it.
- The public key is stored in the clear with a MAC keyed by a server secret that is derived from
  config/release.key. A public key that fails the MAC is never used to wrap an entry key, so a row
  edited by someone who has only the database cannot redirect shared keys.
- A server that holds the MAC key and the database can still substitute keys. That is the
  documented trust boundary; fingerprints are shown so users can compare them out of band.
"""

from __future__ import annotations

from . import crypto
from . import sharing_crypto as sc
from .crypto import CryptoError
from .db import Store


class KeyBindingError(Exception):
    """A public key is missing or fails verification. Nothing is wrapped to it."""


def _aad(account_id: int) -> bytes:
    return b"pastry:account-private-key:v1|" + str(account_id).encode("ascii")


def ensure_keys(store: Store, account_id: int, dek: bytes | bytearray, bind_key: bytes,
                now: float) -> bytearray:
    """Create the account's key pair if missing. Returns the private key (caller wipes it)."""
    with store.transaction() as conn:
        row = conn.execute("SELECT * FROM account_keys WHERE account_id = ?", (account_id,)).fetchone()
        if row is None:
            private, public = sc.generate_keypair()
            conn.execute(
                "INSERT INTO account_keys (account_id, public_key, public_mac, private_blob, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (account_id, public, sc.bind_public_key(bind_key, account_id, public),
                 crypto.seal(dek, private, _aad(account_id)), now),
            )
            return bytearray(private)
    try:
        private = crypto.open_sealed(dek, row["private_blob"], _aad(account_id))
    except CryptoError as exc:
        raise KeyBindingError("The account key pair could not be opened.") from exc
    if sc.public_from_private(private) != bytes(row["public_key"]):
        raise KeyBindingError("The account key pair is inconsistent.")
    return bytearray(private)


def load_public(store: Store, account_id: int, bind_key: bytes) -> bytes:
    """The account's public key, verified against its binding MAC. Fails closed."""
    with store.connect() as conn:
        row = conn.execute("SELECT public_key, public_mac FROM account_keys WHERE account_id = ?",
                           (account_id,)).fetchone()
    if row is None:
        raise KeyBindingError("That account has not generated a sharing key yet. They need to sign in once.")
    public = bytes(row["public_key"])
    if not sc.verify_public_key(bind_key, account_id, public, bytes(row["public_mac"])):
        raise KeyBindingError("That account's sharing key failed verification.")
    return public


def fingerprint_of(store: Store, account_id: int) -> str | None:
    with store.connect() as conn:
        row = conn.execute("SELECT public_key FROM account_keys WHERE account_id = ?", (account_id,)).fetchone()
    return sc.fingerprint(bytes(row["public_key"])) if row else None


def rebind_all(store: Store, bind_key: bytes) -> list[tuple[int, str]]:
    """Recompute every binding MAC under the current server secret. For use after restoring a
    backup onto a machine whose config/release.key differs. The owner must compare fingerprints."""
    out = []
    with store.transaction() as conn:
        for row in conn.execute("SELECT account_id, public_key FROM account_keys").fetchall():
            public = bytes(row["public_key"])
            conn.execute("UPDATE account_keys SET public_mac = ? WHERE account_id = ?",
                         (sc.bind_public_key(bind_key, row["account_id"], public), row["account_id"]))
            out.append((row["account_id"], sc.fingerprint(public)))
    return out
