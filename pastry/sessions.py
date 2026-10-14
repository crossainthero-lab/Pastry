"""In-memory sessions.

Sessions hold the vault key only in RAM. A restart signs everyone out. Only a
SHA-256 digest of each token is kept. The first 16 hex characters of that digest
form the public session id shown in the UI, so revoking a session never needs
the token itself.

Separate-password keys live on the session and expire after an inactivity
period, per entry.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from .crypto import wipe


@dataclass
class Session:
    username: str
    dek: bytearray
    csrf: str
    epoch: int
    created: float
    last_seen: float
    sid: str = ""
    account_id: int = 0          # 0 is the owner; others are in the users table
    role: str = "owner"
    # Entry id -> (separate-password key, time it was last used).
    unlocked: dict[int, tuple[bytearray, float]] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock)

    def wipe(self) -> None:
        with self.lock:
            wipe(self.dek)
            for key, _ in self.unlocked.values():
                wipe(key)
            self.unlocked.clear()

    # ----- entry keys ------------------------------------------------------

    def put_key(self, entry_id: int, key: bytearray, now: float) -> None:
        old = self.unlocked.pop(entry_id, None)
        if old is not None:
            wipe(old[0])
        self.unlocked[entry_id] = (key, now)

    def drop_key(self, entry_id: int) -> None:
        old = self.unlocked.pop(entry_id, None)
        if old is not None:
            wipe(old[0])

    def expire_keys(self, now: float, idle_seconds: float) -> None:
        for entry_id in [i for i, (_, used) in self.unlocked.items() if now - used > idle_seconds]:
            self.drop_key(entry_id)

    def key_for(self, entry_id: int, now: float, idle_seconds: float, touch: bool) -> bytearray | None:
        """Return the entry key if still unlocked; expire it when idle. `touch` resets the idle timer."""
        self.expire_keys(now, idle_seconds)
        item = self.unlocked.get(entry_id)
        if item is None:
            return None
        if touch:
            self.unlocked[entry_id] = (item[0], now)
        return item[0]

    def keys_map(self, now: float, idle_seconds: float) -> dict[int, bytearray]:
        self.expire_keys(now, idle_seconds)
        return {entry_id: key for entry_id, (key, _) in self.unlocked.items()}


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class SessionStore:
    def __init__(
        self,
        idle_seconds: float,
        max_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._clock = clock
        self.idle_seconds = idle_seconds
        self.max_seconds = max_seconds

    def now(self) -> float:
        return self._clock()

    def create(self, username: str, dek: bytearray, epoch: int, account_id: int = 0,
               role: str = "owner") -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)  # 256 bits from the OS CSPRNG
        digest = _digest(token)
        now = self._clock()
        session = Session(
            username=username,
            dek=dek,
            csrf=secrets.token_urlsafe(32),
            epoch=epoch,
            account_id=account_id,
            role=role,
            created=now,
            last_seen=now,
            sid=digest[:16],
        )
        with self._lock:
            self._sessions[digest] = session
        return token, session

    def get(self, token: str | None, epoch: int | None = None, touch: bool = True) -> Session | None:
        """Look up a session. The caller checks the account's current epoch when epoch is None."""
        if not token:
            return None
        digest = _digest(token)
        now = self._clock()
        with self._lock:
            session = self._sessions.get(digest)
            if session is None:
                return None
            expired = (
                (epoch is not None and session.epoch != epoch)
                or now - session.last_seen > self.idle_seconds
                or now - session.created > self.max_seconds
            )
            if expired:
                del self._sessions[digest]
                session.wipe()
                return None
            if touch:
                session.last_seen = now
            return session

    def list(self, current_token: str | None) -> list[dict]:
        current = _digest(current_token) if current_token else None
        with self._lock:
            items = [
                {
                    "id": s.sid,
                    "created": s.created,
                    "last_seen": s.last_seen,
                    "current": digest == current,
                }
                for digest, s in self._sessions.items()
            ]
        return sorted(items, key=lambda item: item["created"])

    def destroy_account(self, account_id: int) -> int:
        """Drop every session of one account (used when that account is disabled)."""
        with self._lock:
            doomed = [d for d, s in self._sessions.items() if s.account_id == account_id]
            removed = [self._sessions.pop(d) for d in doomed]
        for session in removed:
            session.wipe()
        return len(removed)

    def destroy(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            session = self._sessions.pop(_digest(token), None)
        if session is not None:
            session.wipe()

    def revoke_id(self, sid: str) -> bool:
        with self._lock:
            digest = next((d for d, s in self._sessions.items() if s.sid == sid), None)
            session = self._sessions.pop(digest, None) if digest else None
        if session is None:
            return False
        session.wipe()
        return True

    def revoke_others(self, current_token: str | None) -> int:
        keep = _digest(current_token) if current_token else None
        with self._lock:
            doomed = [d for d in self._sessions if d != keep]
            removed = [self._sessions.pop(d) for d in doomed]
        for session in removed:
            session.wipe()
        return len(removed)

    def destroy_all(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.wipe()

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)
