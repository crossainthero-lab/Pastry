"""Runtime settings. Defaults are safe; optional overrides live in config/pastry.json."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .crypto import KdfParams

# The directory that contains the `pastry` package (the project root when
# installed with `pip install -e .`). Override with PASTRY_HOME.
DEFAULT_HOME = Path(__file__).resolve().parent.parent

ALLOWED_OVERRIDES = {
    "lan",
    "host",
    "port",
    "session_timeout_minutes",
    "session_max_hours",
    "cookie_secure",
    "allowed_hosts",
    "allowed_origins",
    "entry_idle_minutes",
    "login_max_failures",
    "login_lockout_minutes",
    "entry_max_failures",
    "entry_lockout_minutes",
}


@dataclass
class Settings:
    home: Path = DEFAULT_HOME
    # LAN mode: HTTPS (self-signed) on all interfaces, port 8443. Same as `pastry start --lan`.
    lan: bool = False
    host: str = "127.0.0.1"
    port: int = 8787
    session_timeout_minutes: int = 10
    session_max_hours: int = 12
    # Secure cookies are required by the spec. Browsers treat http://localhost
    # as a secure context, so local testing works on localhost.
    cookie_secure: bool = True
    # Host header values accepted by the server (DNS-rebinding protection).
    # Add your Tailscale or LAN hostname here, see README.
    allowed_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    # Extra origins allowed to send unsafe requests, e.g. "https://pastry.lan".
    allowed_origins: list[str] = field(default_factory=list)
    # A separate-password entry re-locks after this long without being opened.
    entry_idle_minutes: int = 5
    # Failed-attempt thresholds (persisted in SQLite, so they survive restarts).
    login_max_failures: int = 5
    login_lockout_minutes: int = 15
    entry_max_failures: int = 5
    entry_lockout_minutes: int = 10
    kdf: KdfParams = field(default_factory=KdfParams)

    @property
    def config_dir(self) -> Path:
        return self.home / "config"

    @property
    def auth_path(self) -> Path:
        return self.config_dir / "auth.json"

    @property
    def data_dir(self) -> Path:
        return self.home / "data"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "pastry.db"

    @property
    def backup_dir(self) -> Path:
        return self.home / "backups"


def load_settings(home: str | Path | None = None) -> Settings:
    base = Path(home or os.environ.get("PASTRY_HOME") or DEFAULT_HOME).expanduser().resolve()
    settings = Settings(home=base)
    path = base / "config" / "pastry.json"
    if not path.exists():
        return settings

    data = json.loads(path.read_text(encoding="utf-8"))
    unknown = set(data) - ALLOWED_OVERRIDES
    if unknown:
        raise ValueError(f"Unknown keys in {path}: {', '.join(sorted(unknown))}")
    for key, value in data.items():
        setattr(settings, key, value)
    if not 1 <= settings.session_timeout_minutes <= 120:
        raise ValueError("session_timeout_minutes must be between 1 and 120")
    if not 1 <= settings.entry_idle_minutes <= 120:
        raise ValueError("entry_idle_minutes must be between 1 and 120")
    return settings
