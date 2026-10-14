"""Backup and restore, plus checks that plaintext never reaches disk or logs."""
import logging
import tarfile

from pastry import backup as backupmod
from pastry import cli
from pastry.config import Settings
from pastry.web import create_app
from fastapi.testclient import TestClient
from tests.conftest import FAST_KDF, PASSWORD, SAMPLE_ENTRY, login, write_headers

MARKERS = [
    "MARKER-USER-aa11",
    "MARKER-PASSWORD-7f3a",
    "MARKER-NOTE-9c21",
    "MARKER-FIELD-5e88",
    "MARKER-NAME-d4e5",
    "MARKER-SEPARATE-pw-1a2b3c4d",
]


def create_marked_entries(client):
    headers = write_headers(client)
    plain = {
        **SAMPLE_ENTRY,
        "name": "MARKER-NAME-d4e5",
        "username": "MARKER-USER-aa11",
        "password": "MARKER-PASSWORD-7f3a",
        "notes": "MARKER-NOTE-9c21",
        "fields": [{"name": "Recovery", "value": "MARKER-FIELD-5e88", "secret": True}],
    }
    assert client.post("/api/entries", json=plain, headers=headers).status_code == 201
    locked = {**plain, "name": "Locked", "username": "x", "password": "y", "notes": "", "fields": [],
              "separate_password": "MARKER-SEPARATE-pw-1a2b3c4d"}
    assert client.post("/api/entries", json=locked, headers=headers).status_code == 201


def test_backup_and_restore_round_trip(provisioned, signed_in, tmp_path):
    create_marked_entries(signed_in)
    archive = backupmod.create_backup(provisioned, tmp_path / "out")
    assert archive.name.startswith("pastry-backup-") and archive.name.endswith(".tar.gz")
    assert oct(archive.stat().st_mode & 0o777) == "0o600"
    with tarfile.open(archive, "r:gz") as tar:
        assert sorted(tar.getnames()) == ["auth.json", "manifest.json", "pastry.db"]

    fresh = Settings(home=tmp_path / "fresh", kdf=FAST_KDF, allowed_hosts=["testserver"])
    fresh.home.mkdir()
    result = backupmod.restore_backup(fresh, archive)
    assert result["entries"] == 2
    client = TestClient(create_app(fresh), base_url="https://testserver")
    assert login(client).status_code == 303
    names = sorted(e["name"] for e in client.get("/api/entries").json()["entries"])
    assert names == ["Locked", "MARKER-NAME-d4e5"]


def test_restore_keeps_previous_files_and_rejects_foreign_archives(provisioned, signed_in, tmp_path):
    archive = backupmod.create_backup(provisioned, tmp_path / "out")
    bogus = tmp_path / "bogus.tar.gz"
    with tarfile.open(bogus, "w:gz") as tar:
        tar.add(archive, arcname="notes.txt")
    try:
        backupmod.restore_backup(provisioned, bogus)
        raise AssertionError("foreign archive should be rejected")
    except backupmod.BackupError:
        pass

    backupmod.restore_backup(provisioned, archive)
    kept = list(provisioned.config_dir.glob("auth.json.before-restore-*"))
    assert kept, "the previous auth.json should be kept"


def test_cli_backup_and_restore(provisioned, tmp_path, capsys):
    context = cli.Context(settings=provisioned, prompt_password=lambda _p: PASSWORD, prompt_text=lambda _p: "RESTORE")
    assert cli.main(["backup", "--output-dir", str(tmp_path / "cli")], context) == 0
    archive = next((tmp_path / "cli").glob("*.tar.gz"))
    assert cli.main(["restore", str(archive)], context) == 0
    assert "Restored 0 entries" in capsys.readouterr().out


def test_plaintext_never_reaches_database_config_or_backups(signed_in, provisioned, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    create_marked_entries(signed_in)
    signed_in.get("/api/entries", params={"q": "MARKER-NAME"})
    signed_in.get("/api/entries/1")
    export = signed_in.post("/api/export", json={"passphrase": "export passphrase 1"}, headers=write_headers(signed_in))
    assert export.status_code == 200

    raw_db = provisioned.db_path.read_bytes()
    raw_auth = provisioned.auth_path.read_bytes()
    for marker in MARKERS:
        assert marker.encode() not in raw_db, f"{marker} found in database"
        assert marker.encode() not in raw_auth, f"{marker} found in auth.json"
        assert marker not in export.text, f"{marker} found in export file"
        assert marker not in caplog.text, f"{marker} written to logs"

    assert PASSWORD.encode() not in raw_auth
    assert PASSWORD.encode() not in raw_db

    archive = backupmod.create_backup(provisioned, tmp_path / "bk")
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            payload = tar.extractfile(member).read()
            for marker in MARKERS:
                assert marker.encode() not in payload


def test_database_and_config_are_private_files(provisioned):
    import os
    import stat

    for path in (provisioned.db_path, provisioned.auth_path):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
