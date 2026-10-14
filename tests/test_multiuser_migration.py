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
    assert Store(settings.db_path).schema_version() == 5
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
    assert Store(settings.db_path).schema_version() == 5


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


# ----- entries upgraded to per-entry keys (schema v5) -----------------------------------------


def _entry_formats(settings):
    with sqlite3.connect(settings.db_path) as conn:
        return [tuple(r) for r in conn.execute("SELECT id, fmt, key_version FROM entries ORDER BY id")]


def test_legacy_entries_upgrade_to_entry_keys_at_signin_and_stay_readable(v3_home, clock):
    settings = v3_home["settings"]
    client = TestClient(_app(settings, clock), base_url=BASE_URL)
    assert login(client, "owner", V1_PASSWORD).status_code == 303
    assert all(fmt == 5 for _, fmt, _ in _entry_formats(settings))
    entries = {e["name"]: e for e in client.get("/api/entries").json()["entries"]}
    assert set(entries) == {"Plain Server", "Locked Bank"}
    plain = client.get(f"/api/entries/{entries['Plain Server']['id']}").json()
    assert plain["password"] == "v1-plain-pass-111" and plain["fields"][0]["value"] == "v1-ssh"
    assert plain["created_at"] and plain["url"] == "https://example.com"
    locked = entries["Locked Bank"]
    assert locked["locked"] is True
    unlocked = client.post(f"/api/entries/{locked['id']}/unlock", json={"password": V1_SEPARATE},
                           headers=write_headers(client))
    assert unlocked.json()["password"] == "v1-locked-pass"          # separate password still works
    wrong = client.post(f"/api/entries/{locked['id']}/unlock", json={"password": "not the entry password"},
                        headers=write_headers(client))
    assert wrong.status_code == 403


def test_upgraded_entries_keep_ids_and_can_be_shared(v3_home, clock):
    settings = v3_home["settings"]
    before_ids = [r[0] for r in sqlite3.connect(settings.db_path).execute("SELECT id FROM entries ORDER BY id")]
    app = _app(settings, clock)
    owner = TestClient(app, base_url=BASE_URL)
    login(owner, "owner", V1_PASSWORD)
    assert [r[0] for r in _entry_formats(settings)] == before_ids
    token = invite(owner, "alice")
    accept(app, token, ALICE_PW)
    plain_id = next(e["id"] for e in owner.get("/api/entries").json()["entries"] if e["name"] == "Plain Server")
    # A new account has no sharing key until its first sign-in, and the API says so.
    early = owner.post(f"/api/entries/{plain_id}/shares", json={"username": "alice"}, headers=write_headers(owner))
    assert early.status_code == 422 and "sign in once" in early.json()["detail"]
    alice = TestClient(app, base_url=BASE_URL)
    login(alice, "alice", ALICE_PW)
    response = owner.post(f"/api/entries/{plain_id}/shares", json={"username": "alice"}, headers=write_headers(owner))
    assert response.status_code == 201
    assert alice.get(f"/api/shared/{plain_id}").json()["password"] == "v1-plain-pass-111"


def test_interrupted_entry_upgrade_rolls_back_and_changes_nothing(v3_home, clock, monkeypatch):
    settings = v3_home["settings"]
    TestClient(_app(settings, clock), base_url=BASE_URL)
    # Migrate the schema first, then fail the entry upgrade partway through.
    from pastry import vault as vault_module
    original = vault_module.Vault._upgrade_row
    calls = {"n": 0}

    def flaky(self, conn, row):
        calls["n"] += 1
        if calls["n"] == 2:
            raise sqlite3.OperationalError("simulated crash during entry upgrade")
        return original(self, conn, row)

    monkeypatch.setattr(vault_module.Vault, "_upgrade_row", flaky)
    client = TestClient(_app(settings, clock), base_url=BASE_URL)
    assert login(client, "owner", V1_PASSWORD).status_code == 303   # sign-in still works
    assert all(fmt == 4 for _, fmt, _ in _entry_formats(settings))   # nothing was half-converted
    names = sorted(e["name"] for e in client.get("/api/entries").json()["entries"])
    assert names == ["Locked Bank", "Plain Server"]                 # legacy entries still readable
    monkeypatch.undo()
    again = TestClient(_app(settings, clock), base_url=BASE_URL)
    assert login(again, "owner", V1_PASSWORD).status_code == 303
    assert all(fmt == 5 for _, fmt, _ in _entry_formats(settings))


def test_schema_v5_migration_failure_rolls_back_and_refuses_signin(v3_home, clock, monkeypatch):
    settings = v3_home["settings"]
    mig.migrate_v3_to_v4(Store(settings.db_path))
    before = hashlib.sha256(settings.db_path.read_bytes()).hexdigest()
    monkeypatch.setattr(mig, "SHARING_STATEMENTS", ("THIS IS NOT SQL",))
    response = login(TestClient(_app(settings, clock), base_url=BASE_URL), "owner", V1_PASSWORD)
    assert response.status_code == 503
    with sqlite3.connect(settings.db_path) as conn:
        columns = [r[1] for r in conn.execute("PRAGMA table_info(entries)")]
    assert "fmt" not in columns
    assert hashlib.sha256(settings.db_path.read_bytes()).hexdigest() == before
    monkeypatch.undo()
    assert login(TestClient(_app(settings, clock), base_url=BASE_URL), "owner", V1_PASSWORD).status_code == 303


def test_separate_password_content_blob_is_byte_identical_across_the_upgrade(v3_home, clock):
    settings = v3_home["settings"]
    mig.migrate_v3_to_v4(Store(settings.db_path))
    with sqlite3.connect(settings.db_path) as conn:
        before = {r[0]: bytes(r[1]) for r in conn.execute("SELECT id, content_blob FROM entries")}
    login(TestClient(_app(settings, clock), base_url=BASE_URL), "owner", V1_PASSWORD)
    with sqlite3.connect(settings.db_path) as conn:
        rows = conn.execute("SELECT id, content_blob FROM entries").fetchall()
        locked_ids = [i for i, _ in rows if before[i] == bytes(dict(rows)[i])]
    assert len(locked_ids) == 1   # exactly the protected entry was left untouched
