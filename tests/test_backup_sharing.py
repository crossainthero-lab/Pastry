"""Backups with sharing: envelopes and keys preserved, authenticity, and the release-key recovery path."""
import hashlib
import io
import json
import shutil
import sqlite3
import tarfile

import pytest

from pastry import backup as backupmod
from pastry import cli
from pastry.backup import BackupError
from pastry.config import Settings
from pastry.db import Store
from pastry.web import create_app
from tests.conftest import FAST_KDF, write_headers
from tests.test_multiuser import ALICE_PW, _client, entry, join, login
from tests.test_setup_admin import Prompts


@pytest.fixture
def shared_world(provisioned, clock):
    app = create_app(provisioned, clock=clock, wall_clock=clock)
    owner = _client(app)
    login(owner)
    alice = join(app, owner, "alice", ALICE_PW)
    eid = entry(alice, "Backed up share", password="backup-share-secret")
    assert alice.post(f"/api/entries/{eid}/shares", json={"username": "owner", "can_edit": True},
                      headers=write_headers(alice)).status_code == 201
    return {"app": app, "settings": provisioned, "entry": eid, "clock": clock}


def _rewrite(src, dst, mutate):
    with tarfile.open(src) as tin, tarfile.open(dst, "w:gz") as tout:
        for member in tin.getmembers():
            data = mutate(member.name, tin.extractfile(member).read())
            info = tarfile.TarInfo(member.name)
            info.size = len(data)
            tout.addfile(info, io.BytesIO(data))


def _restore_home(tmp_path, name, keep_release_key_from=None):
    home = tmp_path / name
    home.mkdir()
    settings = Settings(home=home, kdf=FAST_KDF, allowed_hosts=["testserver"])
    if keep_release_key_from is not None:
        settings.config_dir.mkdir(mode=0o700)
        shutil.copy(keep_release_key_from, settings.release_key_path)
    return settings


def test_backup_verifies_as_authentic_on_the_producing_server(shared_world, tmp_path):
    archive = backupmod.create_backup(shared_world["settings"], tmp_path / "bk")
    report = backupmod.verify_backup(shared_world["settings"], archive)
    assert report.authenticity == "verified"
    with tarfile.open(archive) as tar:
        manifest = json.loads(tar.extractfile("manifest.json").read())
    assert manifest["auth"]["alg"] == "hmac-sha256"
    assert "release.key" not in tarfile.open(archive).getnames()


def test_recomputed_checksums_do_not_make_a_forged_archive_authentic(shared_world, tmp_path):
    """SHA-256 is not authentication: an attacker can recompute checksums, but not the keyed MAC."""
    archive = backupmod.create_backup(shared_world["settings"], tmp_path / "bk")
    forged_db = tmp_path / "forged.db"
    Store(forged_db).init()
    forged_bytes = forged_db.read_bytes()

    def forge(name, data):
        if name == "pastry.db":
            return forged_bytes
        if name == "manifest.json":
            manifest = json.loads(data)
            manifest["sha256"]["pastry.db"] = hashlib.sha256(forged_bytes).hexdigest()  # attacker recomputes
            manifest["entry_count"] = 0
            return json.dumps(manifest).encode()
        return data

    forged = tmp_path / "forged.tar.gz"
    _rewrite(archive, forged, forge)
    with pytest.raises(BackupError, match="Authenticity check failed"):
        backupmod.verify_backup(shared_world["settings"], forged)


def test_restore_can_require_authenticity(tmp_path, provisioned):
    """An archive from a machine with no release key carries no MAC, and can be refused."""
    archive = backupmod.create_backup(provisioned, tmp_path / "bk")
    assert backupmod.verify_backup(provisioned, archive).authenticity == "none"
    fresh = _restore_home(tmp_path, "fresh")
    with pytest.raises(BackupError, match="authenticity"):
        backupmod.restore_backup(fresh, archive, require_authentic=True)
    assert not fresh.db_path.exists()  # nothing was written


def test_restore_preserves_accounts_shares_and_envelopes(shared_world, tmp_path, clock):
    settings = shared_world["settings"]
    archive = backupmod.create_backup(settings, tmp_path / "bk")
    fresh = _restore_home(tmp_path, "fresh", keep_release_key_from=settings.release_key_path)
    result = backupmod.restore_backup(fresh, archive, require_authentic=True)
    assert result["authenticity"] == "verified"
    with sqlite3.connect(fresh.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM shares").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM account_keys").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
    app = create_app(fresh, clock=clock, wall_clock=clock)
    owner = _client(app)
    from tests.conftest import PASSWORD
    assert login(owner, "owner", PASSWORD).status_code == 303
    shared = owner.get("/api/shared").json()["entries"]
    assert [(e["name"], e["owner"], e["can_edit"]) for e in shared] == [("Backed up share", "alice", True)]
    assert owner.get(f"/api/shared/{shared[0]['id']}").json()["password"] == "backup-share-secret"


def test_without_the_release_key_sharing_fails_closed_until_keys_are_rebound(shared_world, tmp_path, clock):
    settings = shared_world["settings"]
    archive = backupmod.create_backup(settings, tmp_path / "bk")
    fresh = _restore_home(tmp_path, "fresh")  # a new machine: no release.key
    backupmod.restore_backup(fresh, archive)
    app = create_app(fresh, clock=clock, wall_clock=clock)
    alice = _client(app)
    assert login(alice, "alice", ALICE_PW).status_code == 303
    eid = alice.get("/api/entries").json()["entries"][0]["id"]
    # Existing envelopes still open: they never depended on the binding key.
    owner = _client(app)
    from tests.conftest import PASSWORD
    login(owner, "owner", PASSWORD)
    assert owner.get(f"/api/shared/{eid}").status_code == 200
    # But new wrapping is refused: the stored public keys no longer verify under the new server secret.
    refused = alice.post(f"/api/entries/{eid}/shares", json={"username": "owner"}, headers=write_headers(alice))
    assert refused.status_code == 422 and "failed verification" in refused.json()["detail"]
    # The owner re-binds after comparing fingerprints, and sharing works again.
    prompts = Prompts(passwords=[], text=["REBIND"])
    context = cli.Context(settings=fresh, prompt_password=prompts.password, prompt_text=prompts.input)
    assert cli.main(["admin", "rebind-keys"], context) == 0
    ok = alice.post(f"/api/entries/{eid}/shares", json={"username": "owner", "can_edit": True},
                    headers=write_headers(alice))
    assert ok.status_code == 201


def test_rebind_requires_explicit_confirmation(shared_world, capsys):
    prompts = Prompts(passwords=[], text=["no"])
    context = cli.Context(settings=shared_world["settings"], prompt_password=prompts.password,
                          prompt_text=prompts.input)
    assert cli.main(["admin", "rebind-keys"], context) == 1
    assert "Cancelled" in capsys.readouterr().out


def test_cli_verify_reports_authenticity(shared_world, tmp_path, capsys):
    archive = backupmod.create_backup(shared_world["settings"], tmp_path / "bk")
    context = cli.Context(settings=shared_world["settings"])
    assert cli.main(["backup", "verify", str(archive)], context) == 0
    assert "Authenticity     : verified" in capsys.readouterr().out
