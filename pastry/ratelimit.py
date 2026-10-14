"""Failed-attempt limiter persisted in SQLite, so lockouts survive restarts."""

from __future__ import annotations

import json
import time
from typing import Callable

from .db import Store


class SqlRateLimiter:
    """Block a key for `lockout_seconds` after `max_failures` within `window_seconds`.

    Keys are chosen by the caller (for example "login-ip:<address>"). Client-supplied
    headers are never used to build keys; see web.py.
    """

    def __init__(
        self,
        store: Store,
        max_failures: int,
        window_seconds: float,
        lockout_seconds: float,
        clock: Callable[[], float] = time.time,
    ):
        self.store = store
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._clock = clock

    def blocked_for(self, key: str) -> int:
        """Seconds until the key may try again, or 0."""
        now = self._clock()
        with self.store.connect() as conn:
            row = conn.execute("SELECT blocked_until FROM rate_limits WHERE key = ?", (key,)).fetchone()
        if row is None:
            return 0
        remaining = row["blocked_until"] - now
        return max(0, int(remaining + 0.999)) if remaining > 0 else 0

    def record_failure(self, key: str) -> None:
        now = self._clock()
        with self.store.transaction() as conn:
            row = conn.execute("SELECT failures FROM rate_limits WHERE key = ?", (key,)).fetchone()
            recent = [t for t in json.loads(row["failures"]) if now - t < self.window_seconds] if row else []
            recent.append(now)
            blocked_until = 0.0
            if len(recent) >= self.max_failures:
                blocked_until = now + self.lockout_seconds
                recent = []
            conn.execute(
                "INSERT INTO rate_limits(key, failures, blocked_until) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET failures = excluded.failures, blocked_until = excluded.blocked_until",
                (key, json.dumps(recent), blocked_until),
            )
            # Drop stale rows so the table stays small on a Raspberry Pi.
            conn.execute("DELETE FROM rate_limits WHERE blocked_until < ? AND failures = '[]'", (now,))

    def reset(self, key: str) -> None:
        with self.store.transaction() as conn:
            conn.execute("DELETE FROM rate_limits WHERE key = ?", (key,))
