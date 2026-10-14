"""v1 -> v2 migration on a real v1 vault fixture (tests/fixtures/v1), with rollback."""
import hashlib
import shutil
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pastry import auth as authmod
from pastry import cli
from pastry.backup import verify_backup
from pastry.config import Settings
from pastry.db import SchemaError, Store
from pastry.migrate import MigrationError, migrate_v1_to_v2, migrate_v2_to_v3
from pastry.vault import Vault
from pastry.web import create_app
from tests.conftest import FAST_KDF, login
from tests.test_setup_admin import Prompts

FIXTURE = Path(__file__).parent / "fixtures" / "v1"
V1_PASSWORD = "correct horse battery"
V1_SEPARATE = "v1-separate-pass-9"


@pytest.fixture
def v1_home(tmp_path):
    """A copy of the v1 fixture laid out as a Pastry home. The fixture itself is never modified."""
    settings = Settings(home=tmp_path, kdf=FAST_KDF, allowed_hosts=["testserver"])
    settings.data_dir.mkdir(mode=0o700)
    settings.config_dir.mkdir(mode=0o700)
    shutil.copy(FIXTURE / "pastry.db", settings.db_path)
    shutil.copy(FIXTURE / "auth.json", settings.auth_path)
    return settings


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _dek(settings):
    return authmod.try_unlock(authmod.read_auth(settings.auth_path), V1_PASSWORD)


def test_fixture_is_schema_v1_with_plaintext_timestamps(v1_home):
    assert Store(v1_home.db_path).schema_version() == 1
    raw = v1_home.db_path.read_bytes()
    assert b"Plain Server" not in raw  # names were always encrypted in v1
    assert b"2026-" in raw             # ...but timestamps were plaintext in v1


def test_migration_preserves_entries_and_separate_password(v1_home):
    from pastry.migrate import migrate_v3_to_v4

    store = Store(v1_home.db_path)
    assert migrate_v1_to_v2(store, _dek(v1_home)) == 2
    assert store.schema_version() == 2
    migrate_v2_to_v3(store)
    migrate_v3_to_v4(store)  # the full chain a real upgrade runs
    assert store.schema_version() == 4

    dek = _dek(v1_home)
    vault = Vault(store, dek, FAST_KDF)
    names = {e["name"]: e for e in vault.list({})}
    assert set(names) == {"Plain Server", "Locked Bank"}
    assert names["Plain Server"]["url"] == "https://example.com"
    assert names["Plain Server"]["favourite"] is True
    assert names["Plain Server"]["created_at"]          # timestamps survived the move
    assert names["Locked Bank"]["locked"] is True
    assert vault.get(names["Plain Server"]["id"], {})["password"] == "v1-plain-pass-111"
    assert vault.get(names["Plain Server"]["id"], {})["fields"][0]["value"] == "v1-ssh"

    # The v1 separate-password lock still works with the same password.
    key, content = vault.unlock(names["Locked Bank"]["id"], V1_SEPARATE)
    assert content["password"] == "v1-locked-pass"
    key[:] = bytes(len(key))


def test_migrated_database_has_no_plaintext_metadata(v1_home):
    migrate_v1_to_v2(Store(v1_home.db_path), _dek(v1_home))
    raw = v1_home.db_path.read_bytes()
    for needle in (b"Plain Server", b"Locked Bank", b"example.com", b"Servers", b"Bank", b"2026-", b"v1-plain-pass-111"):
        assert needle not in raw, needle
    with sqlite3.connect(v1_home.db_path) as conn:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(entries)")]
    assert columns == ["id", "uid", "meta_blob", "content_blob"]


def test_failed_migration_rolls_back_and_leaves_v1_intact(v1_home):
    store = Store(v1_home.db_path)
    before = _digest(v1_home.db_path)
    with pytest.raises(MigrationError):
        migrate_v1_to_v2(store, _dek(v1_home), _fail_at_row=1)
    assert _digest(v1_home.db_path) == before  # byte-identical after rollback
    assert store.schema_version() == 1

    # A later, clean run succeeds.
    assert migrate_v1_to_v2(store, _dek(v1_home)) == 2
    assert store.schema_version() == 2


def test_cli_migrate_creates_backup_first_and_verifies(v1_home, capsys):
    prompts = Prompts(passwords=[V1_PASSWORD], text=[])
    context = cli.Context(settings=v1_home, prompt_password=prompts.password, prompt_text=prompts.input)
    assert cli.main(["migrate"], context) == 0
    backups = list(v1_home.backup_dir.glob("pastry-backup-*.tar.gz"))
    assert len(backups) == 1
    # The pre-migration backup is a valid v1 archive that can be restored if needed.
    report = verify_backup(v1_home, backups[0])
    assert report.schema_version == 1 and report.entry_count == 2
    assert Store(v1_home.db_path).schema_version() == 5


def test_cli_migrate_with_wrong_password_changes_nothing(v1_home, capsys):
    before = _digest(v1_home.db_path)
    prompts = Prompts(passwords=["not the password at all"], text=[])
    context = cli.Context(settings=v1_home, prompt_password=prompts.password, prompt_text=prompts.input)
    assert cli.main(["migrate"], context) == 1
    assert _digest(v1_home.db_path) == before
    assert not v1_home.backup_dir.exists() or not any(v1_home.backup_dir.glob("*.tar.gz"))


def test_server_refuses_to_serve_unmigrated_vault(v1_home):
    with pytest.raises(SchemaError):
        Store(v1_home.db_path).require_current()
    client = TestClient(create_app(v1_home), base_url="https://testserver")
    response = client.post("/login", data={"username": "owner", "password": V1_PASSWORD})
    assert response.status_code == 503
    assert "pastry migrate" in response.text


def test_start_command_refuses_unmigrated_vault(v1_home, capsys):
    context = cli.Context(settings=v1_home)
    assert cli.main(["start"], context) == 1
    assert "pastry migrate" in capsys.readouterr().err


def test_migrated_vault_serves_normally(v1_home):
    migrate_v1_to_v2(Store(v1_home.db_path), _dek(v1_home))
    migrate_v2_to_v3(Store(v1_home.db_path))
    from pastry.migrate import migrate_v3_to_v4
    migrate_v3_to_v4(Store(v1_home.db_path))
    client = TestClient(create_app(v1_home), base_url="https://testserver")
    assert login(client, "owner", V1_PASSWORD).status_code == 303
    names = sorted(e["name"] for e in client.get("/api/entries").json()["entries"])
    assert names == ["Locked Bank", "Plain Server"]
