"""Backup format v2: verification, corruption detection, legacy archives, isolated restore."""
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from pastry import cli
from pastry.backup import BackupError, create_backup, restore_backup, verify_backup
from pastry.config import Settings
from pastry.db import Store
from tests.conftest import FAST_KDF, PASSWORD, SAMPLE_ENTRY, USERNAME, write_headers
from tests.test_setup_admin import Prompts

FIXTURE = Path(__file__).parent / "fixtures" / "v1"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def populated(provisioned, signed_in):
    headers = write_headers(signed_in)
    signed_in.post("/api/entries", json={**SAMPLE_ENTRY, "name": "Backed up"}, headers=headers)
    signed_in.post("/api/entries", json={**SAMPLE_ENTRY, "name": "Locked one", "separate_password": "lock-pass-long-1"},
                   headers=headers)
    return provisioned


@pytest.fixture
def archive(populated, tmp_path):
    return create_backup(populated, tmp_path / "out")


def _rewrite_archive(src: Path, dst: Path, mutate) -> None:
    """Copy a tar.gz, letting `mutate(name, data)` return new bytes (or None to drop the member)."""
    with tarfile.open(src, "r:gz") as tar_in, tarfile.open(dst, "w:gz") as tar_out:
        for member in tar_in.getmembers():
            data = tar_in.extractfile(member).read()
            new = mutate(member.name, data)
            if new is None:
                continue
            info = tarfile.TarInfo(member.name)
            info.size = len(new)
            tar_out.addfile(info, io.BytesIO(new))


def test_v2_archive_has_manifest_with_checksums(archive):
    with tarfile.open(archive, "r:gz") as tar:
        manifest = json.loads(tar.extractfile("manifest.json").read())
    assert manifest["format"] == "pastry-backup"
    assert manifest["version"] == 2
    assert manifest["schema_version"] == 3
    assert manifest["entry_count"] == 2
    assert set(manifest["sha256"]) == {"pastry.db", "auth.json"}


def test_verify_checks_checksums_integrity_and_entries(populated, archive):
    report = verify_backup(populated, archive)
    assert report.checksums == "verified"
    assert report.integrity == "ok"
    assert report.entry_count == 2
    assert report.username == USERNAME


def test_verify_with_password_decrypts_unprotected_entries(populated, archive):
    report = verify_backup(populated, archive, password=PASSWORD)
    assert report.decrypted_unlocked == 1
    assert report.protected_entries == 1


def test_verify_with_wrong_password_fails(populated, archive):
    with pytest.raises(BackupError, match="does not unlock"):
        verify_backup(populated, archive, password="definitely not it")


def test_verify_never_modifies_the_active_vault(populated, archive):
    before_db = _digest(populated.db_path)
    before_auth = _digest(populated.auth_path)
    verify_backup(populated, archive, password=PASSWORD)
    assert _digest(populated.db_path) == before_db
    assert _digest(populated.auth_path) == before_auth


def test_tampered_database_is_detected_by_checksum(populated, archive, tmp_path):
    def tamper(name, data):
        if name == "pastry.db":
            middle = len(data) // 2  # flip one byte in the middle of the SQLite file
            return data[:middle] + bytes([data[middle] ^ 0xFF]) + data[middle + 1:]
        return data

    bad = tmp_path / "tampered.tar.gz"
    _rewrite_archive(archive, bad, tamper)
    with pytest.raises(BackupError):
        verify_backup(populated, bad)


def test_tampered_manifest_count_is_detected(populated, archive, tmp_path):
    def tamper(name, data):
        if name == "manifest.json":
            manifest = json.loads(data)
            manifest["entry_count"] = 99
            return json.dumps(manifest).encode()
        return data

    bad = tmp_path / "count.tar.gz"
    _rewrite_archive(archive, bad, tamper)
    with pytest.raises(BackupError, match="Entry count|manifest"):
        verify_backup(populated, bad)


def test_foreign_archive_is_rejected(populated, tmp_path):
    foreign = tmp_path / "foreign.tar.gz"
    with tarfile.open(foreign, "w:gz") as tar:
        data = b"hello"
        info = tarfile.TarInfo("notes.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with pytest.raises(BackupError, match="not a Pastry backup"):
        verify_backup(populated, foreign)


def test_unreadable_file_is_rejected(populated, tmp_path):
    junk = tmp_path / "junk.tar.gz"
    junk.write_bytes(b"not a tarball at all")
    with pytest.raises(BackupError):
        verify_backup(populated, junk)


def test_legacy_v1_archive_is_accepted_with_a_note(populated, tmp_path):
    legacy = tmp_path / "legacy-v1.tar.gz"
    with tarfile.open(legacy, "w:gz") as tar:
        tar.add(FIXTURE / "pastry.db", arcname="pastry.db")
        tar.add(FIXTURE / "auth.json", arcname="auth.json")
    report = verify_backup(populated, legacy)
    assert report.format_version == 1
    assert report.checksums.startswith("absent")
    assert report.schema_version == 1
    assert any("migrate" in note for note in report.notes)


def test_restore_into_isolated_home_verifies_entries(populated, archive, tmp_path):
    isolated = Settings(home=tmp_path / "isolated", kdf=FAST_KDF, allowed_hosts=["testserver"])
    isolated.home.mkdir()
    result = restore_backup(isolated, archive)
    assert result["entries"] == 2
    assert result["schema_version"] == 3
    store = Store(isolated.db_path)
    assert store.entry_count() == 2
    import stat, os
    assert stat.S_IMODE(os.stat(isolated.auth_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(isolated.db_path).st_mode) == 0o600


def test_restore_keeps_a_copy_of_the_previous_vault(populated, archive, tmp_path):
    before = _digest(populated.db_path)
    restore_backup(populated, archive)  # restores over the same home, which keeps the originals
    kept = list(populated.data_dir.glob("pastry.db.before-restore-*"))
    assert kept and _digest(kept[0]) == before


def test_corrupted_archive_never_replaces_the_active_vault(populated, archive, tmp_path):
    before = _digest(populated.db_path)

    def tamper(name, data):
        return data[:-50] + bytes(50) if name == "auth.json" else data

    bad = tmp_path / "bad.tar.gz"
    _rewrite_archive(archive, bad, tamper)
    with pytest.raises(BackupError):
        restore_backup(populated, bad)
    assert _digest(populated.db_path) == before


def test_restore_refuses_without_confirmation(populated, archive, capsys):
    before = _digest(populated.db_path)
    prompts = Prompts(passwords=[], text=["no"])
    context = cli.Context(settings=populated, prompt_password=prompts.password, prompt_text=prompts.input)
    assert cli.main(["restore", str(archive)], context) == 1
    assert _digest(populated.db_path) == before


def test_interrupted_backup_leaves_no_partial_archive(populated, tmp_path, monkeypatch):
    import os as os_module

    out = tmp_path / "interrupt"

    def boom(src, dst):
        raise OSError("simulated disk full")

    monkeypatch.setattr(os_module, "replace", boom)
    with pytest.raises(OSError):
        create_backup(populated, out)
    monkeypatch.undo()
    assert not list(out.glob("*.tar.gz")) and not list(out.glob("*.part"))


def test_cli_backup_verify_reports_and_leaves_vault_alone(populated, archive, capsys):
    before = _digest(populated.db_path)
    prompts = Prompts(passwords=[PASSWORD], text=[])
    context = cli.Context(settings=populated, prompt_password=prompts.password, prompt_text=prompts.input)
    assert cli.main(["backup", "verify", str(archive), "--password-check"], context) == 0
    out = capsys.readouterr().out
    assert "Checksums        : verified" in out
    assert "Verification passed" in out
    assert _digest(populated.db_path) == before


def test_cli_backup_verify_requires_a_file(populated):
    context = cli.Context(settings=populated)
    assert cli.main(["backup", "verify"], context) == 1
