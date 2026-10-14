"""Backup, verification and restore.

Archive format (version 2): a gzip tar containing
  manifest.json  format, version, created_at, schema_version, entry_count, sha256 per file
  pastry.db      consistent SQLite snapshot (online backup API)
  auth.json      admin account and wrapped vault key

Version 1 archives (written by Pastry 1.0) have no manifest. They are accepted,
but without checksums; `verify` reports that.

Entry data is already encrypted, and the vault key is wrapped under the master
password, so an archive needs that password to be useful. Archives are mode 0600.
Verification is done in a private staging directory and never touches the active
vault.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import auth as authmod
from .config import Settings
from .crypto import wipe
from .db import Store
from .vault import Vault

FORMAT_NAME = "pastry-backup"
FORMAT_VERSION = 2
DB_NAME = "pastry.db"
AUTH_NAME = "auth.json"
MANIFEST_NAME = "manifest.json"
DATA_MEMBERS = (DB_NAME, AUTH_NAME)


class BackupError(Exception):
    pass


@dataclass
class VerifyReport:
    archive: str
    format_version: int
    schema_version: int
    entry_count: int
    checksums: str  # "verified" or "absent (version 1 archive)"
    integrity: str = "ok"
    username: str = ""
    decrypted_unlocked: int | None = None
    protected_entries: int | None = None
    notes: list[str] = field(default_factory=list)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_backup(settings: Settings, out_dir: Path) -> Path:
    if not settings.db_path.exists() or not settings.auth_path.exists():
        raise BackupError("Nothing to back up yet. Run: pastry setup")
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(out_dir, 0o700)
    target = out_dir / f"pastry-backup-{datetime.now():%Y%m%d-%H%M%S}.tar.gz"
    partial = target.with_name(target.name + ".part")

    with tempfile.TemporaryDirectory(dir=out_dir) as work:
        work_path = Path(work)
        snapshot = work_path / DB_NAME
        source = sqlite3.connect(settings.db_path)
        try:
            dest = sqlite3.connect(snapshot)
            try:
                source.backup(dest)  # consistent even if the server is running
            finally:
                dest.close()
        finally:
            source.close()
        auth_copy = work_path / AUTH_NAME
        shutil.copyfile(settings.auth_path, auth_copy)
        entries = Store(snapshot).entry_count()
        manifest = {
            "format": FORMAT_NAME,
            "version": FORMAT_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "schema_version": Store(snapshot).schema_version(),
            "entry_count": entries,
            "sha256": {DB_NAME: _sha256(snapshot), AUTH_NAME: _sha256(auth_copy)},
        }
        manifest_path = work_path / MANIFEST_NAME
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        try:
            fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as handle:
                with tarfile.open(fileobj=handle, mode="w:gz") as tar:
                    for path in (manifest_path, snapshot, auth_copy):
                        tar.add(path, arcname=path.name)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(partial, target)  # atomic: the archive appears only when complete
        except BaseException:
            partial.unlink(missing_ok=True)  # an interrupted write leaves no partial archive behind
            raise
    os.chmod(target, 0o600)
    return target


def _extract(archive: Path, staging: Path) -> dict | None:
    """Extract a backup into `staging`, refusing anything unexpected. Returns the manifest or None."""
    if not archive.is_file():
        raise BackupError(f"Backup file not found: {archive}")
    try:
        tar_handle = tarfile.open(archive, "r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise BackupError("This is not a readable Pastry backup archive.") from exc
    with tar_handle as tar:
        members = tar.getmembers()
        names = {m.name for m in members}
        allowed = set(DATA_MEMBERS) | {MANIFEST_NAME}
        if not set(DATA_MEMBERS) <= names or not names <= allowed or len(names) != len(members):
            raise BackupError("This is not a Pastry backup archive (unexpected contents).")
        if not all(m.isreg() for m in members):
            raise BackupError("Backup archive contains non-regular entries.")
        for member in members:
            source = tar.extractfile(member)
            assert source is not None
            fd = os.open(staging / member.name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as handle:
                shutil.copyfileobj(source, handle)
    if MANIFEST_NAME not in names:
        return None
    try:
        manifest = json.loads((staging / MANIFEST_NAME).read_text(encoding="utf-8"))
    except ValueError as exc:
        raise BackupError("The backup manifest is malformed.") from exc
    if manifest.get("format") != FORMAT_NAME or manifest.get("version") != FORMAT_VERSION:
        raise BackupError("Unsupported backup format version.")
    return manifest


def verify_backup(settings: Settings, archive: Path, password: str | None = None) -> VerifyReport:
    """Check an archive without touching the active vault.

    Always checks: checksums (v2 archives), SQLite integrity, auth.json parsing,
    and that the entry count matches the manifest. With `password`, also unwraps
    the vault key and decrypts every unprotected entry.
    """
    staging = Path(tempfile.mkdtemp(prefix="verify-", dir=settings.home))
    try:
        os.chmod(staging, 0o700)
        manifest = _extract(Path(archive), staging)
        db_path = staging / DB_NAME
        auth_path = staging / AUTH_NAME

        if manifest is not None:
            for name in DATA_MEMBERS:
                if _sha256(staging / name) != manifest["sha256"].get(name):
                    raise BackupError(f"Checksum mismatch for {name}: the archive is corrupted or altered.")

        store = Store(db_path)
        check = sqlite3.connect(db_path)
        try:
            result = check.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            check.close()
        if result != "ok":
            raise BackupError("The database inside the archive failed the SQLite integrity check.")

        auth = authmod.read_auth(auth_path)  # raises AuthError when malformed
        schema = store.schema_version()
        entries = store.entry_count() if schema in (1, 2, 3, 4) else 0
        if manifest is not None and manifest["entry_count"] != entries:
            raise BackupError("Entry count does not match the manifest.")

        report = VerifyReport(
            archive=str(archive),
            format_version=manifest["version"] if manifest else 1,
            schema_version=schema,
            entry_count=entries,
            checksums="verified" if manifest else "absent (version 1 archive)",
            username=auth.username,
        )
        if schema == 1:
            report.notes.append("Schema v1 database: run `pastry migrate` after restoring.")
        elif schema not in (2, 3, 4):
            raise BackupError(f"Unknown database schema version {schema}.")

        if password is not None:
            dek = authmod.try_unlock(auth, password)
            if dek is None:
                raise BackupError("The password does not unlock this backup's vault key.")
            try:
                if schema >= 2:
                    vault = Vault(store, dek, auth.kdf)
                    unlocked = protected = 0
                    for item in vault.list({}):
                        if item["locked"]:
                            protected += 1
                        else:
                            vault.get(item["id"], {})
                            unlocked += 1
                    report.decrypted_unlocked = unlocked
                    report.protected_entries = protected
                else:
                    report.notes.append("Entries not decrypted: content checks need schema v2.")
            finally:
                wipe(dek)
        return report
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def restore_backup(settings: Settings, archive: Path) -> dict:
    """Verify the archive, then replace the current database and auth.json.

    Previous files are kept as *.before-restore-<stamp>. Stop the server first.
    """
    report = verify_backup(settings, archive)  # refuses corrupted or foreign archives
    staging = Path(tempfile.mkdtemp(prefix="restore-", dir=settings.home))
    try:
        os.chmod(staging, 0o700)
        _extract(Path(archive), staging)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        settings.config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        for live in (settings.auth_path, settings.db_path):
            if live.exists():
                live.rename(live.with_name(f"{live.name}.before-restore-{stamp}"))
        shutil.move(str(staging / DB_NAME), str(settings.db_path))
        shutil.move(str(staging / AUTH_NAME), str(settings.auth_path))
        os.chmod(settings.db_path, 0o600)
        os.chmod(settings.auth_path, 0o600)
        # Post-restore check on the live files.
        restored = authmod.read_auth(settings.auth_path)
        if restored.username != report.username:
            raise BackupError("Restored account does not match the verified archive.")
        return {"entries": report.entry_count, "archive": str(archive), "schema_version": report.schema_version,
                "notes": report.notes}
    finally:
        shutil.rmtree(staging, ignore_errors=True)
