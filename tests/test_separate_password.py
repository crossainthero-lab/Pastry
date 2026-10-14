"""Require Separate Password: per-entry encryption layer."""
import json
import sqlite3

from pastry import crypto
from tests.conftest import SAMPLE_ENTRY, write_headers

SECOND = "entry-specific-pass-1"
SECOND_NEW = "entry-specific-pass-2"


def create_locked(client, password=SECOND, **overrides):
    # Name, URL and category stay visible on locked entries by design, so the
    # secret-looking values below are chosen not to appear in those fields.
    body = {**SAMPLE_ENTRY, "name": "Locked Server", "username": "hidden-user-7",
            "separate_password": password, **overrides}
    response = client.post("/api/entries", json=body, headers=write_headers(client))
    assert response.status_code == 201, response.text
    return response.json()["id"]


def unlock(client, entry_id, password=SECOND):
    return client.post(f"/api/entries/{entry_id}/unlock", json={"password": password}, headers=write_headers(client))


def test_locked_entry_reveals_only_its_name_until_unlocked(signed_in):
    entry_id = create_locked(signed_in)
    data = signed_in.get(f"/api/entries/{entry_id}").json()
    assert data["locked"] is True and data["unlocked"] is False
    assert data["name"] == "Locked Server"
    for secret in ("hidden-user-7", "p4ss-VERY-unique-value", "ssh-secret-value", "Rotate quarterly"):
        assert secret not in json.dumps(data)
    assert "password" not in data and "fields" not in data


def test_wrong_separate_password_is_refused(signed_in):
    entry_id = create_locked(signed_in)
    response = unlock(signed_in, entry_id, password="the wrong separate one")
    assert response.status_code == 403
    assert response.json()["detail"] == "Incorrect separate password."
    assert "password" not in signed_in.get(f"/api/entries/{entry_id}").json()


def test_correct_separate_password_reveals_contents(signed_in):
    entry_id = create_locked(signed_in)
    response = unlock(signed_in, entry_id)
    assert response.status_code == 200
    data = response.json()
    assert data["unlocked"] is True
    assert data["password"] == "p4ss-VERY-unique-value"
    assert data["fields"][0]["value"] == "ssh-secret-value"


def test_lock_again_hides_contents(signed_in):
    entry_id = create_locked(signed_in)
    unlock(signed_in, entry_id)
    assert signed_in.post(f"/api/entries/{entry_id}/lock", headers=write_headers(signed_in)).status_code == 204
    assert "password" not in signed_in.get(f"/api/entries/{entry_id}").json()


def test_repeated_failures_lock_the_entry_for_everyone(signed_in, clock):
    entry_id = create_locked(signed_in)
    for _ in range(5):
        assert unlock(signed_in, entry_id, password="guess-guess-guess").status_code == 403
    blocked = unlock(signed_in, entry_id)  # even the correct password is refused for now
    assert blocked.status_code == 429
    clock.advance(10 * 60 + 1)
    from tests.conftest import login

    login(signed_in)  # the session itself idled out during the wait
    assert unlock(signed_in, entry_id).status_code == 200


def test_editing_a_locked_entry_requires_unlocking_first(signed_in):
    entry_id = create_locked(signed_in)
    response = signed_in.put(f"/api/entries/{entry_id}", json=SAMPLE_ENTRY, headers=write_headers(signed_in))
    assert response.status_code == 423
    unlock(signed_in, entry_id)
    assert signed_in.put(f"/api/entries/{entry_id}", json=SAMPLE_ENTRY, headers=write_headers(signed_in)).status_code == 200


def test_ordinary_vault_key_cannot_open_the_protected_layer(signed_in, provisioned):
    """Bypassing the UI and reading the database directly still fails without the separate password."""
    from pastry import auth as authmod

    entry_id = create_locked(signed_in)
    dek = authmod.try_unlock(authmod.read_auth(provisioned.auth_path), "correct horse battery")
    with sqlite3.connect(provisioned.db_path) as conn:
        row = conn.execute("SELECT uid, content_blob FROM entries WHERE id = ?", (entry_id,)).fetchone()
    uid, content_blob = row
    from pastry.vault import content_aad as _content_aad

    try:
        crypto.open_sealed(dek, content_blob, _content_aad(uid, False))
        raise AssertionError("the vault key must not open a protected entry")
    except crypto.CryptoError:
        pass
    try:
        crypto.open_sealed(dek, content_blob, _content_aad(uid, True))
        raise AssertionError("the vault key must not open a protected entry")
    except crypto.CryptoError:
        pass


def test_change_separate_password_requires_unlock_and_takes_effect(signed_in):
    entry_id = create_locked(signed_in)
    headers = write_headers(signed_in)
    assert signed_in.post(f"/api/entries/{entry_id}/protect/change", json={"password": SECOND_NEW}, headers=headers).status_code == 423

    unlock(signed_in, entry_id)
    assert signed_in.post(f"/api/entries/{entry_id}/protect/change", json={"password": SECOND_NEW}, headers=headers).status_code == 204
    signed_in.post(f"/api/entries/{entry_id}/lock", headers=headers)
    assert unlock(signed_in, entry_id, SECOND).status_code == 403
    assert unlock(signed_in, entry_id, SECOND_NEW).status_code == 200


def test_remove_separate_password_makes_entry_ordinary(signed_in, provisioned):
    entry_id = create_locked(signed_in)
    headers = write_headers(signed_in)
    unlock(signed_in, entry_id)
    assert signed_in.post(f"/api/entries/{entry_id}/protect/remove", headers=headers).status_code == 204
    signed_in.post(f"/api/entries/{entry_id}/lock", headers=headers)
    data = signed_in.get(f"/api/entries/{entry_id}").json()
    assert data["locked"] is False
    assert data["password"] == "p4ss-VERY-unique-value"


def test_enable_separate_password_on_an_existing_entry(signed_in):
    entry_id = create_locked(signed_in, password=SECOND)
    headers = write_headers(signed_in)
    unlock(signed_in, entry_id)
    signed_in.post(f"/api/entries/{entry_id}/protect/remove", headers=headers)
    assert signed_in.get(f"/api/entries/{entry_id}").json()["locked"] is False

    assert signed_in.post(f"/api/entries/{entry_id}/protect/enable", json={"password": SECOND}, headers=headers).status_code == 204
    data = signed_in.get(f"/api/entries/{entry_id}").json()
    assert data["locked"] is True and "password" not in data


def test_short_separate_password_is_rejected(signed_in):
    response = signed_in.post(
        "/api/entries",
        json={**SAMPLE_ENTRY, "separate_password": "short"},
        headers=write_headers(signed_in),
    )
    assert response.status_code == 422


def test_master_password_change_keeps_protected_entries_accessible(signed_in, provisioned):
    from pastry import auth as authmod
    from tests.conftest import PASSWORD

    entry_id = create_locked(signed_in)
    authmod.change_password(provisioned.auth_path, PASSWORD, "a second master password")
    from tests.conftest import login

    assert login(signed_in, password="a second master password").status_code == 303
    assert unlock(signed_in, entry_id, SECOND).status_code == 200


def test_export_and_import_keep_protected_entries_protected(signed_in, client, provisioned, tmp_path):
    from pastry.config import Settings
    from pastry.db import Store
    from pastry.web import create_app
    from tests.conftest import FAST_KDF, PASSWORD, USERNAME, login
    from fastapi.testclient import TestClient
    from pastry import auth as authmod

    entry_id = create_locked(signed_in)
    plain_id = signed_in.post("/api/entries", json={**SAMPLE_ENTRY, "name": "Plain"}, headers=write_headers(signed_in)).json()["id"]
    export = signed_in.post("/api/export", json={"passphrase": "export passphrase 1"}, headers=write_headers(signed_in))
    assert export.status_code == 200
    document = export.json()
    assert "p4ss-VERY-unique-value" not in export.text  # encrypted with the passphrase
    assert "ssh-secret-value" not in export.text
    assert plain_id and entry_id

    # Import into a fresh vault that has the same master password but no entries.
    other = Settings(home=tmp_path / "other", kdf=FAST_KDF, allowed_hosts=["testserver"])
    other.home.mkdir()
    Store(other.db_path).init()
    authmod.create_auth(other.auth_path, USERNAME, PASSWORD, FAST_KDF)
    other_client = TestClient(create_app(other), base_url="https://testserver")
    login(other_client)
    result = other_client.post("/api/import", json={"passphrase": "export passphrase 1", "data": json.dumps(document)},
                               headers=write_headers(other_client))
    assert result.status_code == 200
    assert result.json() == {"imported": 2, "skipped": 0}

    listed = {e["name"]: e for e in other_client.get("/api/entries").json()["entries"]}
    assert listed["Locked Server"]["locked"] is True
    assert "password" not in other_client.get(f"/api/entries/{listed['Locked Server']['id']}").json()
    assert unlock(other_client, listed["Locked Server"]["id"]).status_code == 200
    assert other_client.get(f"/api/entries/{listed['Plain']['id']}").json()["password"] == "p4ss-VERY-unique-value"

    again = other_client.post("/api/import", json={"passphrase": "export passphrase 1", "data": json.dumps(document)},
                              headers=write_headers(other_client))
    assert again.json() == {"imported": 0, "skipped": 2}


def test_import_with_wrong_passphrase_fails(signed_in):
    create_locked(signed_in)
    export = signed_in.post("/api/export", json={"passphrase": "export passphrase 1"}, headers=write_headers(signed_in))
    bad = signed_in.post("/api/import", json={"passphrase": "not the passphrase", "data": export.text},
                         headers=write_headers(signed_in))
    assert bad.status_code == 400
