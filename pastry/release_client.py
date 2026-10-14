"""Recipient side of the server-enforced release protocol (docs/CRYPTOGRAPHY-V12.md, 10.4).

Transports:
- HttpTransport: standard library urllib with default TLS verification. Plain HTTP is
  allowed only to loopback addresses, for local development and tests.
- Any object with status/challenge/redeem methods (for example the in-process
  LocalTransport used by tests) can be passed to open_server_package.

Nothing here falls back to offline decryption. A server-enforced package that cannot
be released cannot be opened.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from . import crypto
from . import package as pk
from .crypto import CryptoError


class TransportError(Exception):
    """The release server could not be reached, or its answer was not understood."""


class ReleaseRefused(Exception):
    """The server refused the request. `code` is stable (see release.py)."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def check_release_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return url
    if parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost"):
        return url
    raise TransportError("The package's release address is not a secure (https) address. Refusing to connect.")


class HttpTransport:
    def __init__(self, base_url: str, timeout: float = 10.0, context: ssl.SSLContext | None = None):
        self.base_url = check_release_url(base_url).rstrip("/")
        self.timeout = timeout
        # Default context: certificate and hostname verification are always on.
        self._context = context or ssl.create_default_context()

    def _post(self, path: str, body: dict) -> dict:
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path, data=data, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self._context) as response:
                payload = response.read(1024 * 1024)
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read(64 * 1024).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                detail = {}
            raise ReleaseRefused(exc.code, str(detail.get("code", "server")),
                                 str(detail.get("detail", "The server refused the request."))) from None
        except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
            raise TransportError("The release server could not be reached.") from exc
        try:
            return json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise TransportError("The release server sent an unreadable answer.") from exc

    def status(self, capability: str) -> dict:
        return self._post("/release/v1/status", {"capability": capability})

    def challenge(self, capability: str) -> str:
        return self._post("/release/v1/challenge", {"capability": capability})["nonce"]

    def redeem(self, capability: str, nonce: str, proof_b64: str) -> dict:
        return self._post("/release/v1/redeem", {"capability": capability, "nonce": nonce, "proof": proof_b64})


@dataclass
class Release:
    header: pk.Header
    entries: list[dict]
    expires_at: str | None
    state: str


def open_server_package(data: bytes, password: str, transport: Any) -> Release:
    """Run the release protocol and decrypt. Raises ReleaseRefused, TransportError or PackageError."""
    header, _ = pk.read_header(data)
    if not header.is_server:
        raise pk.PackageError("This package does not use the release server. Use the offline open path.")
    capability = base64.urlsafe_b64encode(header.capability).rstrip(b"=").decode("ascii")

    state = transport.status(capability)
    if state.get("state") != "active":
        current = state.get("state", "unavailable")
        status = 409 if current == "consumed" else 410
        raise ReleaseRefused(status, current, _STATE_MESSAGES.get(current, "Unavailable."))

    k_pw, k_auth = pk.derive_keys(password, header.salt, header.kdf)
    crypto.wipe(k_pw)
    try:
        nonce = transport.challenge(capability)
        proof = base64.b64encode(pk.proof_for(k_auth, header.package_id, nonce)).decode("ascii")
        answer = transport.redeem(capability, nonce, proof)
        wrap = base64.b64decode(answer["wrapped_key"], validate=True)
        try:
            k_r = bytearray(crypto.open_sealed(
                k_auth, wrap, pk.WRAP_PREFIX + str(header.package_id).encode() + b"|" + nonce.encode()))
        except CryptoError as exc:
            raise TransportError("The release answer could not be verified. Nothing was opened.") from exc
        try:
            opened_header, entries = pk.open_with_release_key(data, bytes(k_r))
        finally:
            crypto.wipe(k_r)
        return Release(header=opened_header, entries=entries, expires_at=answer.get("expires_at"), state="active")
    finally:
        crypto.wipe(bytearray(k_auth))


_STATE_MESSAGES = {
    "expired": "This package has expired.",
    "revoked": "The owner has revoked this package.",
    "consumed": "This one-time package has already been redeemed.",
}


def message_for(error: Exception) -> str:
    """User-facing text. Never includes package contents, and never says whether a password is close."""
    if isinstance(error, ReleaseRefused):
        known = {
            "not_found": "This package is not available on this server.",
            "expired": "This package has expired.",
            "revoked": "The owner has revoked this package.",
            "consumed": "This one-time package has already been redeemed.",
            "bad_password": "The package password was not accepted.",
            "bad_challenge": "The request timed out. Try again.",
        }
        if error.code in known:
            return known[error.code]
        if error.status == 429:
            return "Too many attempts. Wait a while, then try again."
        return "The release server refused the request."
    if isinstance(error, TransportError):
        return (str(error) + " Server-enforced packages cannot be opened offline. "
                "Check that the Pastry server is running and reachable (for example through Tailscale).")
    return str(error)
