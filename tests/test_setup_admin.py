"""First-run setup and `pastry admin` commands, driven through the CLI entry point."""
import json
import os
import stat

import pytest

from pastry import auth as authmod
from pastry import cli
from pastry.config import Settings
from pastry.db import Store
from pastry.vault import Vault
from tests.conftest import FAST_KDF, PASSWORD, USERNAME


class Prompts:
    """Scripted answers for the interactive commands."""

    def __init__(self, passwords=(), text=()):
        self.passwords = list(passwords)
        self.text = list(text)

    def password(self, _prompt):
        return self.passwords.pop(0)

    def input(self, _prompt):
        return self.text.pop(0)


@pytest.fixture
def home(tmp_path):
    return Settings(home=tmp_path, kdf=FAST_KDF)


def run(settings, argv, passwords=(), text=()):
    prompts = Prompts(passwords, text)
    context = cli.Context(settings=settings, prompt_password=prompts.password, prompt_text=prompts.input)
    return cli.main(argv, context)


def test_first_run_setup_creates_auth_file_without_plaintext(home, capsys):
    code = run(home, ["setup"], passwords=[PASSWORD, PASSWORD], text=[USERNAME])
    assert code == 0
    raw = home.auth_path.read_text()
    data = json.loads(raw)
    assert data["username"] == USERNAME
    assert data["password_hash"].startswith("$argon2id$")
    assert PASSWORD not in raw
    assert stat.S_IMODE(os.stat(home.auth_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(home.db_path).st_mode) == 0o600


def test_setup_refuses_to_overwrite_existing_account(home, capsys):
    run(home, ["setup"], passwords=[PASSWORD, PASSWORD], text=[USERNAME])
    code = run(home, ["setup"], passwords=[PASSWORD, PASSWORD], text=[USERNAME])
    assert code == 1
    assert "already set up" in capsys.readouterr().err


def test_setup_rejects_mismatched_passwords(home, capsys):
    code = run(home, ["setup"], passwords=[PASSWORD, PASSWORD + "x"], text=[USERNAME])
    assert code == 1
    assert not home.auth_path.exists()


def test_setup_rejects_short_passwords(home, capsys):
    code = run(home, ["setup"], passwords=["short", "short"], text=[USERNAME])
    assert code == 1
    assert "at least 12" in capsys.readouterr().err


def test_setup_refuses_when_orphaned_vault_data_exists(home, capsys):
    Store(home.db_path).init()
    dek = bytearray(b"k" * 32)
    vault = Vault(Store(home.db_path), dek, FAST_KDF)
    vault.create({"name": "x", "url": "", "category": "", "favourite": False}, {"username": "", "password": "p", "notes": "", "fields": []}, None)
    code = run(home, ["setup"], passwords=[PASSWORD, PASSWORD], text=[USERNAME])
    assert code == 1
    assert "cannot be decrypted" in capsys.readouterr().err


def test_admin_status_never_shows_secrets(home, capsys):
    run(home, ["setup"], passwords=[PASSWORD, PASSWORD], text=[USERNAME])
    capsys.readouterr()
    assert run(home, ["admin", "status"]) == 0
    out = capsys.readouterr().out
    assert USERNAME in out
    assert "$argon2id$" not in out
    assert PASSWORD not in out
    assert json.loads(home.auth_path.read_text())["password_hash"] not in out


def test_set_password_with_wrong_old_password_changes_nothing(home, capsys):
    run(home, ["setup"], passwords=[PASSWORD, PASSWORD], text=[USERNAME])
    before = home.auth_path.read_text()
    code = run(home, ["admin", "set-password"], passwords=["not-the-password", "brand new password 1", "brand new password 1"])
    assert code == 1
    assert home.auth_path.read_text() == before


def test_set_password_keeps_entries_readable_and_rejects_old_password(home):
    run(home, ["setup"], passwords=[PASSWORD, PASSWORD], text=[USERNAME])
    auth = authmod.read_auth(home.auth_path)
    dek = authmod.try_unlock(auth, PASSWORD)
    store = Store(home.db_path)
    vault = Vault(store, dek, FAST_KDF)
    vault.create({"name": "Kept", "url": "", "category": "", "favourite": False},
                 {"username": "u", "password": "keep-me", "notes": "", "fields": []}, None)
    old_epoch = authmod.read_auth(home.auth_path).session_epoch

    code = run(home, ["admin", "set-password"], passwords=[PASSWORD, "brand new password 1", "brand new password 1"])
    assert code == 0

    after = authmod.read_auth(home.auth_path)
    assert after.session_epoch == old_epoch + 1
    assert authmod.try_unlock(after, PASSWORD) is None
    new_dek = authmod.try_unlock(after, "brand new password 1")
    assert new_dek == dek  # same vault key, merely re-wrapped
    entries = Vault(store, new_dek, FAST_KDF).list({})
    assert entries[0]["name"] == "Kept"
    assert Vault(store, new_dek, FAST_KDF).get(entries[0]["id"], {})["password"] == "keep-me"
    assert stat.S_IMODE(os.stat(home.auth_path).st_mode) == 0o600


def test_set_username_requires_password_and_updates_file(home):
    run(home, ["setup"], passwords=[PASSWORD, PASSWORD], text=[USERNAME])
    assert run(home, ["admin", "set-username", "--username", "wrong"], passwords=["nope-nope-nope-nope"]) == 1
    assert authmod.read_auth(home.auth_path).username == USERNAME
    assert run(home, ["admin", "set-username", "--username", "renamed"], passwords=[PASSWORD]) == 0
    assert authmod.read_auth(home.auth_path).username == "renamed"


def test_username_can_be_edited_directly_in_config_file(home):
    run(home, ["setup"], passwords=[PASSWORD, PASSWORD], text=[USERNAME])
    data = json.loads(home.auth_path.read_text())
    data["username"] = "edited-by-hand"
    home.auth_path.write_text(json.dumps(data))
    assert authmod.read_auth(home.auth_path).username == "edited-by-hand"
    assert authmod.try_unlock(authmod.read_auth(home.auth_path), PASSWORD) is not None


def test_permission_warning_for_world_readable_auth_file(home):
    run(home, ["setup"], passwords=[PASSWORD, PASSWORD], text=[USERNAME])
    os.chmod(home.auth_path, 0o644)
    assert authmod.permission_warnings(home.auth_path)
