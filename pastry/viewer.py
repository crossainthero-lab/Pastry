"""Viewer state for `.pastry` packages. No terminal code here, so it is unit-testable.

Enforcement levels (see docs/CRYPTOGRAPHY-V12.md, section 6):
- allow_copy=False removes the copy action in this viewer only.
- expires_at is advisory: enforced by this program, bypassable by a modified one.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from . import clipboard
from .package import Header

REVEAL_SECONDS = 15


@dataclass
class ViewRow:
    label: str
    value: str
    secret: bool


@dataclass
class Viewer:
    header: Header
    entries: list[dict]
    clip: Callable[[str], bool] = clipboard.copy
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    mono: Callable[[], float] = time.monotonic
    clear_after: float = 30.0
    entry_index: int = 0
    row_index: int = 0
    revealed_until: float = 0.0
    message: str = ""
    _clear_timer: object | None = field(default=None, repr=False)
    # Server-enforced packages: the release server's expiry, and a check that runs every poll_seconds.
    server_expires_at: str | None = None
    status_check: Callable[[], str] | None = None
    poll_seconds: float = 30.0
    closed_reason: str = ""
    _last_poll: float = field(default=-1e9, repr=False)
    _poll_failures: int = field(default=0, repr=False)

    # ----- rows -----

    def rows(self, entry: dict | None = None) -> list[ViewRow]:
        entry = entry or self.entries[self.entry_index]
        rows = [
            ViewRow("Username", entry["username"], False),
            ViewRow("Password", entry["password"], True),
        ]
        for f in entry.get("fields", []):
            rows.append(ViewRow(f["name"], f["value"], bool(f["secret"])))
        if entry.get("url"):
            rows.append(ViewRow("URL", entry["url"], False))
        if entry.get("notes"):
            rows.append(ViewRow("Notes", entry["notes"], False))
        return [r for r in rows if r.value]

    def current_row(self) -> ViewRow | None:
        rows = self.rows()
        return rows[self.row_index] if rows else None

    # ----- navigation -----

    def select_entry(self, index: int) -> None:
        self.entry_index = max(0, min(index, len(self.entries) - 1))
        self.row_index = 0
        self.hide()

    def next_row(self) -> None:
        count = len(self.rows())
        if count:
            self.row_index = (self.row_index + 1) % count
        self.hide()

    def prev_row(self) -> None:
        count = len(self.rows())
        if count:
            self.row_index = (self.row_index - 1) % count
        self.hide()

    # ----- reveal and copy -----

    def is_revealed(self) -> bool:
        return self.mono() < self.revealed_until

    def reveal(self) -> None:
        """Toggle the display of secret values. Reveals lapse after REVEAL_SECONDS."""
        if self.is_revealed():
            self.hide()
        else:
            self.revealed_until = self.mono() + REVEAL_SECONDS

    def hide(self) -> None:
        self.revealed_until = 0.0

    def display(self, row: ViewRow) -> str:
        if row.secret and not self.is_revealed():
            return "•" * 14
        return row.value

    def copy_allowed(self) -> bool:
        return self.header.allow_copy

    def copy_current(self) -> str:
        """Copy the selected value. Returns a message for the user. Never returns the value."""
        if not self.copy_allowed():
            self.message = "Copying is turned off for this package by its sender."
            return self.message
        row = self.current_row()
        if row is None:
            self.message = "Nothing to copy here."
            return self.message
        if not self.clip(row.value):
            self.message = "No clipboard tool found. Install xclip, xsel or wl-clipboard."
            return self.message
        self.message = f"{row.label} copied. It is cleared in {int(self.clear_after)} seconds if unchanged."
        self._schedule_clear(row.value)
        return self.message

    def _schedule_clear(self, value: str) -> None:
        # Imported lazily; the timer is a daemon thread that only clears if unchanged.
        if self.clear_after <= 0:
            return
        timer = clipboard.DelayedClear(value, self.clear_after)
        timer.start()
        self._clear_timer = timer

    # ----- expiry -----

    def expired(self) -> bool:
        if self.server_expires_at:
            return self.now() >= datetime.fromisoformat(self.server_expires_at)
        return self.header.expired(self.now())

    def check_server(self) -> None:
        """Ask the release server whether the package is still active. Fails closed:
        two failed checks in a row close the view, because the server may have revoked it."""
        if self.status_check is None or self.closed_reason:
            return
        if self.mono() - self._last_poll < self.poll_seconds:
            return
        self._last_poll = self.mono()
        try:
            state = self.status_check()
        except Exception:  # any transport or refusal: treated as "cannot confirm"
            self._poll_failures += 1
            if self._poll_failures >= 2:
                self.closed_reason = "Lost contact with the release server. Secrets were closed."
            return
        self._poll_failures = 0
        if state != "active":
            self.closed_reason = {
                "expired": "This package has expired. Secrets were closed.",
                "revoked": "The owner revoked this package. Secrets were closed.",
                "consumed": "This one-time package was already redeemed. Secrets were closed.",
            }.get(state, "The release server no longer releases this package. Secrets were closed.")

    def wipe_secrets(self) -> None:
        """Best effort: drop references to decrypted data. Python cannot guarantee erasure."""
        self.hide()
        self.entries = []
        self.message = ""

    def expiry_text(self) -> str:
        if self.server_expires_at:
            remaining = datetime.fromisoformat(self.server_expires_at) - self.now()
            seconds = int(remaining.total_seconds())
            return "Expired" if seconds <= 0 else f"Server-enforced: closes in {max(1, seconds // 60)} min"
        if not self.header.expires_at:
            return "No expiry set"
        remaining = datetime.fromisoformat(self.header.expires_at) - self.now()
        seconds = int(remaining.total_seconds())
        if seconds <= 0:
            return "Expired"
        if seconds < 3600:
            return f"Expires in {seconds // 60} min (advisory)"
        return f"Expires in {seconds // 3600} h (advisory)"
