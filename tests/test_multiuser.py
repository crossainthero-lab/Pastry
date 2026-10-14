"""Multi-user accounts, adversarial isolation with three accounts (owner, alice, bob), over HTTP."""
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from pastry import accounts
from pastry import package as pk
from pastry.web import create_app
from tests.conftest import BASE_URL, PASSWORD, SAMPLE_ENTRY, USERNAME, login, write_headers

ALICE_PW = "alice master password 1"
BOB_PW = "bob master password 22"


def _client(app):
    return TestClient(app, base_url=BASE_URL)


def _token(client):
    return re.search(r'data-csrf="([^"]+)"', client.get("/").text).group(1)


def invite(owner, username):
    response = owner.post("/api/users/invitations", json={"username": username}, headers=write_headers(owner))
    assert response.status_code == 201, response.text
    return response.json()["token"]


def accept(app, token, password):
    client = _client(app)
    return client.post(f"/invite/{token}", data={"password": password, "repeat": password})


def join(app, owner, username, password):
    token = invite(owner, username)
    assert accept(app, token, password).status_code == 200
    user = _client(app)
    assert login(user, username, password).status_code == 303
    return user


def account_id(client, username):
    for account in client.get("/api/users").json()["accounts"]:
        if account["username"] == username:
            return account["id"]
    raise AssertionError(f"no account {username}")


def entry(client, name, password="entry-secret-pw-1", **extra):
    body = {**SAMPLE_ENTRY, "name": name, "password": password, "fields": [], **extra}
    response = client.post("/api/entries", json=body, headers=write_headers(client))
    assert response.status_code == 201, response.text
    return response.json()["id"]


@pytest.fixture
def world(provisioned, clock):
    clock.now = time.time()
    provisioned.public_url = "https://pastry.example.ts.net"
    app = create_app(provisioned, clock=clock, wall_clock=clock)
    owner = _client(app)
    assert login(owner).status_code == 303
    alice = join(app, owner, "alice", ALICE_PW)
    bob = join(app, owner, "bob", BOB_PW)
    return {"app": app, "owner": owner, "alice": alice, "bob": bob, "clock": clock, "store": provisioned}


# ----- separation of vaults ---------------------------------------------------------------


def test_each_account_sees_only_its_own_entries(world):
    owner, alice, bob = world["owner"], world["alice"], world["bob"]
    entry(owner, "Owner Server")
    entry(alice, "Alice Bank")
    entry(bob, "Bob Mail")
    names = lambda c: sorted(e["name"] for e in c.get("/api/entries").json()["entries"])
    assert names(owner) == ["Owner Server"]
    assert names(alice) == ["Alice Bank"]
    assert names(bob) == ["Bob Mail"]


def test_search_never_crosses_accounts(world):
    entry(world["alice"], "Shared-looking name", username="alice-only-user")
    assert world["owner"].get("/api/entries", params={"q": "alice-only"}).json()["entries"] == []
    assert world["bob"].get("/api/entries", params={"q": "shared-looking"}).json()["entries"] == []


def test_alice_cannot_reach_bobs_entry_by_changing_its_id(world):
    bob_entry = entry(world["bob"], "Bob Secret", password="bob-secret-value")
    alice = world["alice"]
    assert alice.get(f"/api/entries/{bob_entry}").status_code == 404
    assert alice.put(f"/api/entries/{bob_entry}", json=SAMPLE_ENTRY, headers=write_headers(alice)).status_code == 404
    assert alice.delete(f"/api/entries/{bob_entry}", headers=write_headers(alice)).status_code == 404
    assert alice.post(f"/api/entries/{bob_entry}/unlock", json={"password": "x" * 12},
                      headers=write_headers(alice)).status_code == 404
    export = alice.post("/api/packages/export", json={"entry_ids": [bob_entry], "name": "x", "password": "p" * 14,
                                                       "access": "offline", "allow_copy": True},
                        headers=write_headers(alice))
    assert export.status_code == 404
    assert world["bob"].get(f"/api/entries/{bob_entry}").json()["password"] == "bob-secret-value"


def test_owner_cannot_read_a_users_private_entries(world):
    alice_entry = entry(world["alice"], "Alice Private", password="alice-only-password")
    owner = world["owner"]
    assert owner.get(f"/api/entries/{alice_entry}").status_code == 404
    assert "alice-only-password" not in owner.get("/api/entries").text


def test_locked_entry_of_a_user_stays_locked_for_others(world):
    locked = entry(world["alice"], "Alice Locked", password="visible-to-alice",
                   separate_password="alice-separate-1")
    owner = world["owner"]
    assert owner.post(f"/api/entries/{locked}/unlock", json={"password": "alice-separate-1"},
                      headers=write_headers(owner)).status_code == 404
    assert world["alice"].get(f"/api/entries/{locked}").json()["locked"] is True


def test_export_contains_only_the_callers_entries(world):
    entry(world["owner"], "Owner Only")
    entry(world["alice"], "Alice Only")
    response = world["alice"].post("/api/export", json={"passphrase": "export passphrase 1"},
                                   headers=write_headers(world["alice"]))
    assert response.status_code == 200
    assert "Owner Only" not in response.text and "Alice Only" not in response.text  # encrypted
    alice_export = world["alice"].post("/api/export", json={"passphrase": "export passphrase 1"},
                                       headers=write_headers(world["alice"])).json()
    _, items = pk_export_items(alice_export, "export passphrase 1")
    assert [i["meta"]["name"] for i in items] == ["Alice Only"]


def pk_export_items(document, passphrase):
    import base64
    import json as _json
    from pastry import crypto
    from pastry.vault import EXPORT_AAD

    salt = base64.b64decode(document["kdf"]["salt"])
    from pastry.crypto import KdfParams
    kdf = KdfParams.from_dict(document["kdf"])
    key = crypto.derive_key(passphrase, salt, kdf)
    raw = crypto.open_sealed(key, base64.b64decode(document["data"]), EXPORT_AAD)
    return None, _json.loads(raw)


def test_packages_are_scoped_to_their_creator(world):
    alice = world["alice"]
    created = alice.post("/api/packages", json={"entry_ids": [entry(alice, "Alice Pkg")], "name": "alice pkg",
                                                "password": "package password 2026", "policy": "one_time"},
                         headers=write_headers(alice))
    assert created.status_code == 200
    pid = int(created.headers["x-pastry-package-id"])
    assert [p["name"] for p in world["owner"].get("/api/packages").json()["packages"]] == []
    assert world["bob"].get(f"/api/packages/{pid}/file").status_code == 404
    assert world["owner"].post(f"/api/packages/{pid}/revoke", headers=write_headers(world["owner"])).status_code == 404
    assert world["owner"].delete(f"/api/packages/{pid}", headers=write_headers(world["owner"])).status_code == 404
    assert [p["name"] for p in alice.get("/api/packages").json()["packages"]] == ["alice pkg"]


# ----- roles ------------------------------------------------------------------------------


def test_regular_users_cannot_use_owner_only_routes(world):
    alice = world["alice"]
    headers = write_headers(alice)
    assert alice.get("/api/users").status_code == 403
    assert alice.post("/api/users/invitations", json={"username": "mallory"}, headers=headers).status_code == 403
    assert alice.post("/api/users/2/disable", headers=headers).status_code == 403
    assert alice.put("/api/settings", json={"session_timeout_minutes": 1}, headers=headers).status_code == 403


def test_owner_can_list_and_see_roles(world):
    listing = world["owner"].get("/api/users").json()
    roles = {a["username"]: a["role"] for a in listing["accounts"]}
    assert roles == {USERNAME: "owner", "alice": "user", "bob": "user"}


def test_sharing_endpoints_are_disabled_for_everyone(world):
    for client in (world["owner"], world["alice"]):
        assert client.get("/api/shares").status_code == 501
        assert client.post("/api/shares/1", json={}, headers=write_headers(client)).status_code == 501


# ----- invitations ---------------------------------------------------------------------


def test_invitation_is_single_use(world):
    token = invite(world["owner"], "carol")
    assert accept(world["app"], token, "carol master pass 1").status_code == 200
    again = accept(world["app"], token, "carol other pass 2")
    assert again.status_code == 422
    assert "not valid or has expired" in again.text


def test_invitation_expires_after_72_hours(world):
    token = invite(world["owner"], "dave")
    world["clock"].advance(72 * 3600 + 1)
    response = accept(world["app"], token, "dave master pass 1")
    assert response.status_code == 422 and "expired" in response.text


def test_unknown_and_malformed_invitation_tokens_fail_the_same_way(world):
    assert accept(world["app"], "not-a-real-token-value-000000000000", "some master pass 1").status_code == 422
    assert accept(world["app"], "x", "some master pass 1").status_code == 422


def test_invitation_usernames_are_unique_across_owner_and_users_case_insensitively(world):
    owner = world["owner"]
    assert owner.post("/api/users/invitations", json={"username": "ALICE"}, headers=write_headers(owner)).status_code == 422
    assert owner.post("/api/users/invitations", json={"username": USERNAME}, headers=write_headers(owner)).status_code == 422


def test_invitation_password_is_chosen_by_the_user_and_is_at_least_12_characters(world):
    token = invite(world["owner"], "erin")
    assert accept(world["app"], token, "short").status_code == 422


def test_invitation_token_is_stored_only_as_a_hash(world):
    token = invite(world["owner"], "frank")
    raw = world["store"].db_path.read_bytes()
    assert token.encode() not in raw


def test_invitation_creation_requires_owner_csrf_and_session(world):
    anon = _client(world["app"])
    assert anon.post("/api/users/invitations", json={"username": "gus"}).status_code == 401
    assert world["owner"].post("/api/users/invitations", json={"username": "gus"}).status_code == 403


# ----- disabling and sessions -------------------------------------------------------------


def test_disabling_an_account_ends_its_sessions_at_once(world):
    alice = world["alice"]
    assert alice.get("/api/entries").status_code == 200
    response = world["owner"].post(f"/api/users/{account_id(world['owner'], 'alice')}/disable",
                                   headers=write_headers(world["owner"]))
    assert response.status_code == 204
    assert alice.get("/api/entries").status_code == 401


def test_disabled_account_cannot_sign_in_again_and_keeps_its_data(world):
    entry(world["alice"], "Kept Entry")
    world["owner"].post(f"/api/users/{account_id(world['owner'], 'alice')}/disable",
                        headers=write_headers(world["owner"]))
    retry = login(_client(world["app"]), "alice", ALICE_PW)
    assert retry.status_code == 401
    alice_row = accounts.get_account(world["app"].state.ctx.store, account_id(world["owner"], "alice"))
    assert alice_row is not None and alice_row.disabled  # data retained, account disabled


def test_owner_cannot_be_disabled_through_the_api(world):
    response = world["owner"].post("/api/users/0/disable", headers=write_headers(world["owner"]))
    assert response.status_code == 422


def test_session_of_another_account_is_not_affected_by_disabling(world):
    world["owner"].post(f"/api/users/{account_id(world['owner'], 'alice')}/disable",
                        headers=write_headers(world["owner"]))
    assert world["bob"].get("/api/entries").status_code == 200


# ----- secure password changes ------------------------------------------------------------


def test_user_password_change_keeps_entries_and_ends_only_that_account_sessions(world):
    alice = world["alice"]
    kept = entry(alice, "Alice Keeper", password="keeper-value-1")
    bob = world["bob"]
    response = alice.post("/api/account/password", json={"current": ALICE_PW, "new": "alice new master pass 9"},
                          headers=write_headers(alice))
    assert response.status_code == 204
    assert alice.get("/api/entries").status_code == 401
    assert bob.get("/api/entries").status_code == 200
    new_alice = _client(world["app"])
    assert login(new_alice, "alice", "alice new master pass 9").status_code == 303
    assert new_alice.get(f"/api/entries/{kept}").json()["password"] == "keeper-value-1"
    assert login(_client(world["app"]), "alice", ALICE_PW).status_code == 401


def test_user_password_change_requires_the_current_password(world):
    alice = world["alice"]
    response = alice.post("/api/account/password", json={"current": "wrong current pass", "new": "alice new master pass 9"},
                          headers=write_headers(alice))
    assert response.status_code == 403
    assert alice.get("/api/entries").status_code == 200


def test_owner_password_change_does_not_sign_out_other_accounts(world):
    owner = world["owner"]
    response = owner.post("/api/account/password", json={"current": PASSWORD, "new": "owner new master pass 9"},
                          headers=write_headers(owner))
    assert response.status_code == 204
    assert world["alice"].get("/api/entries").status_code == 200
    assert world["bob"].get("/api/entries").status_code == 200


# ----- failure modes ----------------------------------------------------------------------


def test_invalid_key_wrapping_fails_closed(world):
    with sqlite3.connect(world["store"].db_path) as conn:
        conn.execute("UPDATE users SET wrapped_dek = ? WHERE username = 'alice'", (b"\x01" * 80,))
    response = login(_client(world["app"]), "alice", ALICE_PW)
    assert response.status_code == 401  # generic refusal, never a server error


def test_wrong_password_for_a_user_is_refused_generically(world):
    response = login(_client(world["app"]), "alice", "wrong password entirely")
    assert response.status_code == 401
    assert "Invalid username or password." in response.text


def test_unknown_user_gets_the_same_message(world):
    response = login(_client(world["app"]), "nobody-here", ALICE_PW)
    assert response.status_code == 401 and "Invalid username or password." in response.text


def test_account_sessions_are_isolated_from_each_other(world):
    assert world["alice"].get("/api/settings").json()["username"] == "alice"
    assert world["bob"].get("/api/settings").json()["username"] == "bob"
    assert world["alice"].get("/api/settings").json()["role"] == "user"


def test_csrf_tokens_are_per_session(world):
    alice_token = _token(world["alice"])
    response = world["bob"].post("/api/entries", json={**SAMPLE_ENTRY, "fields": []},
                                 headers={"X-CSRF-Token": alice_token})
    assert response.status_code == 403


def test_offline_packages_from_the_owner_still_open(world):
    owner = world["owner"]
    response = owner.post("/api/packages/export", json={
        "entry_ids": [entry(owner, "Packaged")], "name": "owner pkg", "password": "package password 2026",
        "access": "offline", "allow_copy": False, "expires_in_minutes": 60}, headers=write_headers(owner))
    assert response.status_code == 200
    header, entries = pk.open_package(response.content, "package password 2026")
    assert [e["name"] for e in entries] == ["Packaged"]
