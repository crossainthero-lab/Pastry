"""Upgrade to multi-user schema v4: automatic owner migration, interrupted migrations, backups, packages."""
import hashlib
import shutil
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pastry import auth as authmod
from pastry import backup as backupmod
from pastry import migrate as mig
from pastry import package as pk
from pastry import release as rel
from pastry.config import Settings
from pastry.db import Store
from pastry.release import NewPackage, ReleaseService
from pastry.web import create_app
from tests.conftest import BASE_URL, FAST_KDF, login, write_headers
from tests.test_multiuser import ALICE_PW, invite, accept

FIXTURE = Path(__file__).parent / "fixtures" / "v1"
V1_PASSWORD = "correct horse battery"
V1_SEPARATE = "v1-separate-pass-9"


@pytest.fixture
def v3_home(tmp_path, clock):
    """A v1 fixture upgraded to schema v3 (the state before multi-user), with a timed package in it."""
    settings = Settings(home=tmp_path, kdf=FAST_KDF, allowed_hosts=["testserver"], public_url="https://pastry.example")
    settings.data_dir.mkdir(mode=0o700)
    settings.config_dir.mkdir(mode=0o700)
    shutil.copy(FIXTURE / "pastry.db", settings.db_path)
    shutil.copy(FIXTURE / "auth.json", settings.auth_path)
    store = Store(settings.db_path)
    dek = authmod.try_unlock(authmod.read_auth(settings.auth_path), V1_PASSWORD)
    mig.migrate_v1_to_v2(store, dek)
    mig.migrate_v2_to_v3(store)
    assert store.schema_version() == 3
    # A timed package created on v3 (its release key lives beside the database, not in backups).
    import secrets
    svc = ReleaseService(store, rel.load_or_create_kek(settings.release_key_path), lambda: clock.now)
    from pastry import crypto as c
    salt = c.new_salt()
    k_pw, k_auth = pk.derive_keys("package password 2026", salt, FAST_KDF)
    c.wipe(k_pw)
    capability = secrets.token_bytes(32)
    k_r = secrets.token_bytes(32)
    pid = svc.create(NewPackage("owner", capability, "absolute", None, clock.now + 3600, 2, b"meta", b"", k_r, k_auth),
                     clock.now)
    data = pk.build_server_package([{"name": "Old timed", "username": "u", "password": "old-timed-pw-1234",
                                     "notes": "", "url": "", "fields": []}], "old timed",
                                   allow_copy=False, policy={"type": "absolute", "expires_at": "2099-01-01T00:00:00+00:00"},
                                   release_url="https://pastry.example", package_id=pid, capability=capability,
                                   salt=salt, kdf=FAST_KDF, k_r=k_r, now=__import__("datetime").datetime.now(
                                       __import__("datetime").timezone.utc))
    svc.set_file(pid, data, "owner")
    return {"settings": settings, "store": store, "package_id": pid, "capability": capability,
            "k_auth": k_auth, "file": data}


def _app(settings, clock):
    return create_app(settings, clock=clock, wall_clock=clock)


def test_owner_login_migrates_automatically_and_keeps_everything(v3_home, clock):
    settings = v3_home["settings"]
    client = TestClient(_app(settings, clock), base_url=BASE_URL)
    assert login(client, "owner", V1_PASSWORD).status_code == 303
    assert Store(settings.db_path).schema_version() == 4
    names = sorted(e["name"] for e in client.get("/api/entries").json()["entries"])
    assert names == ["Locked Bank", "Plain Server"]
    locked = next(e for e in client.get("/api/entries").json()["entries"] if e["name"] == "Locked Bank")
    assert client.post(f"/api/entries/{locked['id']}/unlock", json={"password": V1_SEPARATE},
                       headers=write_headers(client)).status_code == 200


def test_automatic_migration_writes_a_verified_backup_first(v3_home, clock):
    settings = v3_home["settings"]
    login(TestClient(_app(settings, clock), base_url=BASE_URL), "owner", V1_PASSWORD)
    backups = list(settings.backup_dir.glob("pastry-backup-*.tar.gz"))
    assert len(backups) == 1
    report = backupmod.verify_backup(settings, backups[0])
    assert report.schema_version == 3 and report.entry_count == 2


def test_interrupted_migration_rolls_back_and_refuses_login(v3_home, clock, monkeypatch):
    settings = v3_home["settings"]
    before = hashlib.sha256(settings.db_path.read_bytes()).hexdigest()
    # Make the second statement fail after the column was added: a genuine mid-transaction failure.
    monkeypatch.setattr(mig, "ACCOUNT_STATEMENTS", ("CREATE TABLE users (x INTEGER)", "THIS IS NOT SQL"))
    client = TestClient(_app(settings, clock), base_url=BASE_URL)
    response = login(client, "owner", V1_PASSWORD)
    assert response.status_code == 503
    assert "migration failed" in response.text.lower()
    store = Store(settings.db_path)
    assert store.schema_version() == 3
    with sqlite3.connect(settings.db_path) as conn:
        columns = [r[1] for r in conn.execute("PRAGMA table_info(entries)")]
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    assert "owner_id" not in columns and "users" not in tables
    assert hashlib.sha256(settings.db_path.read_bytes()).hexdigest() == before  # byte-identical


def test_retry_after_an_interrupted_migration_succeeds(v3_home, clock, monkeypatch):
    settings = v3_home["settings"]
    monkeypatch.setattr(mig, "ACCOUNT_STATEMENTS", ("THIS IS NOT SQL",))
    assert login(TestClient(_app(settings, clock), base_url=BASE_URL), "owner", V1_PASSWORD).status_code == 503
    monkeypatch.undo()
    assert login(TestClient(_app(settings, clock), base_url=BASE_URL), "owner", V1_PASSWORD).status_code == 303
    assert Store(settings.db_path).schema_version() == 4


def test_other_accounts_cannot_sign_in_before_the_owner_has_migrated(v3_home, clock):
    settings = v3_home["settings"]
    response = login(TestClient(_app(settings, clock), base_url=BASE_URL), "alice", ALICE_PW)
    assert response.status_code == 503
    assert "migrated first" in response.text


def test_timed_package_created_before_the_upgrade_still_releases(v3_home, clock):
    settings = v3_home["settings"]
    client = TestClient(_app(settings, clock), base_url=BASE_URL)
    login(client, "owner", V1_PASSWORD)  # migrates
    from pastry.release_client import open_server_package
    from tests.test_release_api import HttpTestTransport

    release = open_server_package(v3_home["file"], "package password 2026", HttpTestTransport(client))
    assert release.entries[0]["password"] == "old-timed-pw-1234"


def test_owner_package_ownership_is_rewritten_to_account_id(v3_home, clock):
    settings = v3_home["settings"]
    login(TestClient(_app(settings, clock), base_url=BASE_URL), "owner", V1_PASSWORD)
    with sqlite3.connect(settings.db_path) as conn:
        owners = [r[0] for r in conn.execute("SELECT owner FROM packages")]
    assert owners == ["0"]


def test_backup_and_restore_preserve_accounts_and_their_data(v3_home, clock, tmp_path):
    settings = v3_home["settings"]
    owner = TestClient(_app(settings, clock), base_url=BASE_URL)
    login(owner, "owner", V1_PASSWORD)
    token = invite(owner, "alice")
    accept(_app(settings, clock), token, ALICE_PW)
    alice = TestClient(_app(settings, clock), base_url=BASE_URL)
    login(alice, "alice", ALICE_PW)
    alice.post("/api/entries", json={"name": "Alice keeps", "username": "a", "password": "alice-kept-pw-1",
                                     "notes": "", "url": "", "fields": []}, headers=write_headers(alice))
    archive = backupmod.create_backup(settings, tmp_path / "bk")
    assert backupmod.verify_backup(settings, archive).entry_count == 3  # owner's 2 + alice's 1

    fresh = Settings(home=tmp_path / "fresh", kdf=FAST_KDF, allowed_hosts=["testserver"])
    fresh.home.mkdir()
    backupmod.restore_backup(fresh, archive)
    restored = TestClient(_app(fresh, clock), base_url=BASE_URL)
    assert login(restored, "alice", ALICE_PW).status_code == 303
    assert [e["name"] for e in restored.get("/api/entries").json()["entries"]] == ["Alice keeps"]
    assert login(TestClient(_app(fresh, clock), base_url=BASE_URL), "owner", V1_PASSWORD).status_code == 303


def test_release_key_is_not_in_backups(v3_home, clock, tmp_path):
    settings = v3_home["settings"]
    login(TestClient(_app(settings, clock), base_url=BASE_URL), "owner", V1_PASSWORD)
    archive = backupmod.create_backup(settings, tmp_path / "bk2")
    import tarfile
    with tarfile.open(archive) as tar:
        assert "release.key" not in tar.getnames()
