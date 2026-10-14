"""Regression tests for the findings of the separate-context review of the sharing code."""
import threading
import time

from tests.conftest import write_headers
from pastry.web import create_app
from tests.test_multiuser import ALICE_PW, BOB_PW, _client, entry, join, login
from tests.test_sharing import put_entry, recipient_id, share
import pytest


@pytest.fixture
def w(provisioned, clock):
    clock.now = time.time()
    provisioned.public_url = "https://pastry.example.ts.net"
    app = create_app(provisioned, clock=clock, wall_clock=clock)
    owner = _client(app)
    assert login(owner).status_code == 303
    alice = join(app, owner, "alice", ALICE_PW)
    bob = join(app, owner, "bob", BOB_PW)
    return {"app": app, "owner": owner, "alice": alice, "bob": bob, "clock": clock, "db": provisioned.db_path}


SEP = "entry-pass-long-1"
SEP2 = "entry-pass-long-2"


def unlock(client, eid, password, base="/api/entries"):
    return client.post(f"{base}/{eid}/unlock", json={"password": password}, headers=write_headers(client))


# Finding 1: a stale cached separate-password key must not be used to seal new content.


def test_stale_key_after_password_change_elsewhere_is_refused_and_content_survives(w):
    alice = w["alice"]
    eid = entry(alice, "Stale key", password="stale-secret", separate_password=SEP)
    assert unlock(alice, eid, SEP).status_code == 200
    second = _client(w["app"])
    assert login(second, "alice", ALICE_PW).status_code == 303
    assert unlock(second, eid, SEP).status_code == 200
    changed = second.post(f"/api/entries/{eid}/protect/change", json={"password": SEP2}, headers=write_headers(second))
    assert changed.status_code == 204
    # The first session still holds the old key. Saving through it must be refused, not corrupt.
    stale = put_entry(alice, "/api/entries", eid, password="written-with-stale-key")
    assert stale.status_code == 409
    assert unlock(alice, eid, SEP2).json()["password"] == "stale-secret"  # content intact under the new password
    assert alice.get(f"/api/entries/{eid}").json()["password"] == "stale-secret"


def test_stale_key_on_a_shared_entry_is_refused_for_the_editor(w):
    alice, owner = w["alice"], w["owner"]
    eid = entry(alice, "Shared stale", password="shared-stale", separate_password=SEP)
    share(alice, eid, "owner", can_edit=True)
    assert unlock(owner, eid, SEP, base="/api/shared").status_code == 200
    assert unlock(alice, eid, SEP).status_code == 200
    assert alice.post(f"/api/entries/{eid}/protect/change", json={"password": SEP2},
                      headers=write_headers(alice)).status_code == 204
    assert put_entry(owner, "/api/shared", eid, password="sabotage").status_code == 409
    assert unlock(alice, eid, SEP2).json()["password"] == "shared-stale"
    assert owner.get(f"/api/shared/{eid}").json()["unlocked"] is False  # the stale key was dropped


# Finding 2: revoking a protected entry says plainly that its separate password is unchanged.


def test_revoking_a_protected_entry_warns_that_the_separate_password_is_unchanged(w):
    alice = w["alice"]
    eid = entry(alice, "Warned", separate_password=SEP)
    share(alice, eid, "owner")
    rid = recipient_id(w, w["owner"], "owner")
    response = alice.delete(f"/api/entries/{eid}/shares/{rid}", headers=write_headers(alice))
    assert response.status_code == 200
    body = response.json()
    assert body["protected_layer_unchanged"] is True and "separate password" in body["message"]
    plain = entry(alice, "Plain")
    share(alice, plain, "owner")
    assert alice.delete(f"/api/entries/{plain}/shares/{rid}", headers=write_headers(alice)).status_code == 204


def test_changing_the_separate_password_after_revocation_locks_out_the_old_password(w):
    alice = w["alice"]
    eid = entry(alice, "Rekeyed", password="rekey-secret", separate_password=SEP)
    share(alice, eid, "owner")
    alice.delete(f"/api/entries/{eid}/shares", headers=write_headers(alice))
    assert unlock(alice, eid, SEP).status_code == 200
    alice.post(f"/api/entries/{eid}/protect/change", json={"password": SEP2}, headers=write_headers(alice))
    alice.post(f"/api/entries/{eid}/lock", headers=write_headers(alice))
    assert unlock(alice, eid, SEP).status_code == 403
    assert unlock(alice, eid, SEP2).json()["password"] == "rekey-secret"


# Finding 3: unlock attempts are limited per account, with a ceiling across accounts.


def test_a_recipients_wrong_guesses_do_not_lock_the_owner_out(w):
    alice, owner = w["alice"], w["owner"]
    eid = entry(alice, "Limiter", password="limiter-secret", separate_password=SEP)
    share(alice, eid, "owner")
    for _ in range(5):
        assert unlock(owner, eid, "wrong password here", base="/api/shared").status_code == 403
    assert unlock(owner, eid, SEP, base="/api/shared").status_code == 429       # the guesser is blocked
    assert unlock(alice, eid, SEP).status_code == 200                           # the entry's owner is not


def test_a_success_by_one_account_does_not_reset_another_accounts_failures(w):
    alice, owner = w["alice"], w["owner"]
    eid = entry(alice, "No reset", separate_password=SEP)
    share(alice, eid, "owner")
    for _ in range(4):
        unlock(owner, eid, "wrong password here", base="/api/shared")
    assert unlock(alice, eid, SEP).status_code == 200
    assert unlock(owner, eid, "wrong password here", base="/api/shared").status_code == 403  # 5th failure
    assert unlock(owner, eid, SEP, base="/api/shared").status_code == 429


def test_the_ceiling_applies_across_accounts(w):
    alice, owner, bob = w["alice"], w["owner"], w["bob"]
    eid = entry(alice, "Ceiling", separate_password=SEP)
    share(alice, eid, "owner")
    share(alice, eid, "bob")
    for client in (owner, bob):
        for _ in range(5):
            unlock(client, eid, "wrong password here", base="/api/shared")
    for _ in range(5):
        unlock(alice, eid, "wrong password here")
    # 15 failures across three accounts reached the ceiling: even the right password waits.
    assert unlock(alice, eid, SEP).status_code == 429


# Finding 4: the revocation error points to the recovery path.


def test_unverifiable_key_error_explains_the_recovery_path(w):
    import sqlite3

    alice, owner = w["alice"], w["owner"]
    eid = entry(alice, "Hint")
    share(alice, eid, "owner")
    share(alice, eid, "bob")
    with sqlite3.connect(w["db"]) as conn:
        conn.execute("UPDATE account_keys SET public_mac = ?", (b"\x00" * 32,))
    response = alice.delete(f"/api/entries/{eid}/shares/{recipient_id(w, owner, 'owner')}",
                            headers=write_headers(alice))
    assert response.status_code == 422 and "rebind-keys" in response.json()["detail"]
    assert alice.delete(f"/api/entries/{eid}/shares", headers=write_headers(alice)).status_code == 204  # fallback


# Finding 6: a held separate-password key does not carry over a revoke and re-share.


def test_resharing_does_not_resurrect_a_cached_separate_password_key(w):
    alice, owner = w["alice"], w["owner"]
    eid = entry(alice, "Reshare", password="reshare-secret", separate_password=SEP)
    share(alice, eid, "owner")
    assert unlock(owner, eid, SEP, base="/api/shared").status_code == 200
    alice.delete(f"/api/entries/{eid}/shares", headers=write_headers(alice))
    share(alice, eid, "owner")
    seen = owner.get(f"/api/shared/{eid}").json()
    assert seen["locked"] is True and seen["unlocked"] is False and "password" not in seen


# Finding 7: protection changes and edits cannot overwrite each other.


def test_protection_change_and_concurrent_edits_stay_consistent(w):
    alice = w["alice"]
    eid = entry(alice, "Race", password="race-0")
    share(alice, eid, "owner", can_edit=True)
    statuses, lock, stop = [], threading.Lock(), threading.Event()
    values = []

    def editor():
        client = _client(w["app"])
        login(client)
        n = 0
        while not stop.is_set():
            n += 1
            value = f"race-edit-{n}"
            code = put_entry(client, "/api/shared", eid, password=value).status_code
            with lock:
                statuses.append(code)
                if code == 200:
                    values.append(value)

    thread = threading.Thread(target=editor)
    thread.start()
    time.sleep(0.15)
    enabled = alice.post(f"/api/entries/{eid}/protect/enable", json={"password": SEP}, headers=write_headers(alice))
    time.sleep(0.15)
    stop.set()
    thread.join()
    assert enabled.status_code == 204
    assert 500 not in statuses and set(statuses) <= {200, 423, 404, 409}
    final = unlock(alice, eid, SEP).json()
    assert final["password"] in values + ["race-0"]  # a real edit survived; nothing was lost or garbled
