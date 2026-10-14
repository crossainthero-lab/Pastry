"""Entry sharing with three accounts (owner, alice, bob), over real HTTP routes."""
import sqlite3
import threading
import time

import pytest

from pastry import account_keys, crypto
from pastry import package as pk
from pastry import sharing_crypto as sc
from pastry.web import create_app
from tests.conftest import PASSWORD, write_headers
from tests.test_multiuser import ALICE_PW, BOB_PW, _client, entry, join, login

PKG_PW = "package password 2026"


@pytest.fixture
def w(provisioned, clock):
    clock.now = time.time()
    provisioned.public_url = "https://pastry.example.ts.net"
    app = create_app(provisioned, clock=clock, wall_clock=clock)
    owner = _client(app)
    assert login(owner).status_code == 303
    alice = join(app, owner, "alice", ALICE_PW)
    bob = join(app, owner, "bob", BOB_PW)
    return {"app": app, "owner": owner, "alice": alice, "bob": bob, "clock": clock, "settings": provisioned,
            "db": provisioned.db_path}


def share(client, entry_id, username, can_edit=False, can_export=False):
    return client.post(f"/api/entries/{entry_id}/shares",
                       json={"username": username, "can_edit": can_edit, "can_export": can_export},
                       headers=write_headers(client))


def recipient_id(w, client, username):
    for a in w["owner"].get("/api/users").json()["accounts"]:
        if a["username"] == username:
            return a["id"]


def put_entry(client, base, entry_id, **fields):
    body = {"name": "Edited name", "url": "", "category": "", "favourite": False, "username": "u",
            "password": "new-password-value", "notes": "", "fields": [], **fields}
    return client.put(f"{base}/{entry_id}", json=body, headers=write_headers(client))


# ----- the practical workflow ---------------------------------------------------------


def test_full_sharing_workflow(w):
    owner, alice = w["owner"], w["alice"]
    # 2-3. Alice creates a credential and shares it with the owner (view only).
    eid = entry(alice, "Ubuntu AI Server", password="alice-server-pw-1")
    assert share(alice, eid, "owner").status_code == 201
    # 4. The owner sees it under Shared With Me and can reveal what is returned.
    listing = owner.get("/api/shared").json()["entries"]
    assert [(e["name"], e["owner"], e["can_edit"], e["can_export"]) for e in listing] == \
        [("Ubuntu AI Server", "alice", False, False)]
    assert owner.get(f"/api/shared/{eid}").json()["password"] == "alice-server-pw-1"
    assert put_entry(owner, "/api/shared", eid).status_code == 403  # view-only
    # 5-6. Alice upgrades the owner to edit; the owner edits.
    rid = recipient_id(w, owner, "owner")
    assert alice.put(f"/api/entries/{eid}/shares/{rid}", json={"can_edit": True, "can_export": False},
                     headers=write_headers(alice)).status_code == 204
    assert put_entry(owner, "/api/shared", eid, name="Renamed by owner", password="edited-by-owner-9").status_code == 200
    # 7. Alice sees the edit.
    seen = alice.get(f"/api/entries/{eid}").json()
    assert seen["name"] == "Renamed by owner" and seen["password"] == "edited-by-owner-9"
    # 8-9. Alice revokes; the owner can no longer retrieve it.
    assert alice.delete(f"/api/entries/{eid}/shares/{rid}", headers=write_headers(alice)).status_code == 204
    assert owner.get(f"/api/shared/{eid}").status_code == 404
    assert owner.get("/api/shared").json()["entries"] == []
    # 10. Alice exports it as a .pastry package.
    response = alice.post("/api/packages/export", json={
        "entry_ids": [eid], "name": "alice share", "password": PKG_PW, "access": "offline",
        "allow_copy": True, "expires_in_minutes": 60}, headers=write_headers(alice))
    assert response.status_code == 200
    _, entries = pk.open_package(response.content, PKG_PW)
    assert entries[0]["password"] == "edited-by-owner-9"
    # 12. A timed package: release works, then expiry stops new releases.
    from pastry.release_client import ReleaseRefused, open_server_package
    from tests.test_release_api import HttpTestTransport

    created = alice.post("/api/packages", json={"entry_ids": [eid], "name": "timed", "password": PKG_PW,
                                                "policy": "after_open", "duration_minutes": 5},
                         headers=write_headers(alice))
    assert created.status_code == 200
    anon = _client(w["app"])
    release = open_server_package(created.content, PKG_PW, HttpTestTransport(anon))
    assert release.entries[0]["name"] == "Renamed by owner"
    w["clock"].advance(5 * 60 + 1)
    with pytest.raises(ReleaseRefused) as info:
        open_server_package(created.content, PKG_PW, HttpTestTransport(anon))
    assert info.value.code == "expired"


# ----- permissions ----------------------------------------------------------------------


def test_recipient_cannot_edit_delete_share_or_export_without_permission(w):
    alice, owner = w["alice"], w["owner"]
    eid = entry(alice, "Alice Item")
    share(alice, eid, "owner")
    headers = write_headers(owner)
    assert put_entry(owner, "/api/shared", eid).status_code == 403
    assert owner.put(f"/api/entries/{eid}", json={"name": "x", "fields": []}, headers=headers).status_code == 404
    assert owner.delete(f"/api/entries/{eid}", headers=headers).status_code == 404
    assert share(owner, eid, "bob").status_code == 404                    # cannot re-share
    assert owner.get(f"/api/entries/{eid}/shares").status_code == 404    # cannot see who else has access
    export = owner.post("/api/packages/export", json={"entry_ids": [eid], "name": "x", "password": PKG_PW,
                                                       "access": "offline"}, headers=headers)
    assert export.status_code == 403
    timed = owner.post("/api/packages", json={"entry_ids": [eid], "name": "x", "password": PKG_PW,
                                              "policy": "one_time"}, headers=headers)
    assert timed.status_code == 403


def test_export_permission_is_separate_and_explicit(w):
    alice, owner = w["alice"], w["owner"]
    eid = entry(alice, "Exportable", password="exportable-secret-1")
    share(alice, eid, "owner", can_edit=True, can_export=False)
    body = {"entry_ids": [eid], "name": "p", "password": PKG_PW, "access": "offline", "allow_copy": True}
    assert owner.post("/api/packages/export", json=body, headers=write_headers(owner)).status_code == 403
    rid = recipient_id(w, owner, "owner")
    alice.put(f"/api/entries/{eid}/shares/{rid}", json={"can_edit": False, "can_export": True},
              headers=write_headers(alice))
    ok = owner.post("/api/packages/export", json=body, headers=write_headers(owner))
    assert ok.status_code == 200
    assert pk.open_package(ok.content, PKG_PW)[1][0]["password"] == "exportable-secret-1"
    assert put_entry(owner, "/api/shared", eid).status_code == 403  # export does not imply edit


def test_editor_cannot_change_category_favourite_or_protection(w):
    alice, owner = w["alice"], w["owner"]
    eid = entry(alice, "Keep Meta", category="Servers", favourite=True)
    share(alice, eid, "owner", can_edit=True)
    put_entry(owner, "/api/shared", eid, name="New name", category="Hijacked", favourite=False)
    seen = alice.get(f"/api/entries/{eid}").json()
    assert seen["name"] == "New name" and seen["category"] == "Servers" and seen["favourite"] is True
    assert owner.post(f"/api/entries/{eid}/protect/enable", json={"password": "x" * 14},
                      headers=write_headers(owner)).status_code == 404


def test_only_the_owner_can_manage_access(w):
    alice, owner, bob = w["alice"], w["owner"], w["bob"]
    eid = entry(alice, "Managed")
    share(alice, eid, "owner", can_edit=True)
    rid = recipient_id(w, owner, "owner")
    headers = write_headers(owner)
    assert owner.put(f"/api/entries/{eid}/shares/{rid}", json={"can_edit": True, "can_export": True},
                     headers=headers).status_code == 404
    assert owner.delete(f"/api/entries/{eid}/shares/{rid}", headers=headers).status_code == 404
    assert owner.delete(f"/api/entries/{eid}/shares", headers=headers).status_code == 404
    assert bob.get(f"/api/entries/{eid}/shares").status_code == 404


def test_users_without_a_grant_cannot_reach_a_shared_entry_by_id(w):
    alice, bob = w["alice"], w["bob"]
    eid = entry(alice, "Private to alice and owner")
    share(alice, eid, "owner")
    headers = write_headers(bob)
    assert bob.get(f"/api/shared/{eid}").status_code == 404
    assert bob.get(f"/api/entries/{eid}").status_code == 404
    assert put_entry(bob, "/api/shared", eid).status_code == 404
    assert bob.post(f"/api/shared/{eid}/unlock", json={"password": "x" * 12}, headers=headers).status_code == 404
    assert bob.get("/api/shared").json()["entries"] == []


def test_cannot_share_with_self_unknown_or_disabled_accounts(w):
    alice, owner = w["alice"], w["owner"]
    eid = entry(alice, "Edge")
    assert share(alice, eid, "alice").status_code == 422
    assert share(alice, eid, "nobody").status_code == 404
    owner.post(f"/api/users/{recipient_id(w, owner, 'bob')}/disable", headers=write_headers(owner))
    assert share(alice, eid, "bob").status_code == 404


def test_shared_endpoints_require_authentication_and_csrf(w):
    alice = w["alice"]
    eid = entry(alice, "Auth")
    anon = _client(w["app"])
    for method, path in (("get", "/api/shared"), ("get", f"/api/shared/{eid}"), ("get", "/api/directory"),
                         ("get", f"/api/entries/{eid}/shares")):
        assert getattr(anon, method)(path).status_code == 401
    assert alice.post(f"/api/entries/{eid}/shares", json={"username": "owner"}).status_code == 403  # no CSRF


# ----- revocation and rotation ------------------------------------------------------------


def _share_rows(w):
    with sqlite3.connect(w["db"]) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM shares ORDER BY id").fetchall()


def _entry_row(w, eid):
    with sqlite3.connect(w["db"]) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM entries WHERE id = ?", (eid,)).fetchone()


def test_revocation_rotates_the_entry_key_and_keeps_other_recipients(w):
    alice, owner, bob = w["alice"], w["owner"], w["bob"]
    eid = entry(alice, "Rotating", password="rotation-secret-1")
    share(alice, eid, "owner")
    share(alice, eid, "bob", can_edit=True)
    before = _entry_row(w, eid)
    old_envelopes = {r["recipient_id"]: bytes(r["envelope"]) for r in _share_rows(w)}
    assert before["key_version"] == 0
    assert alice.delete(f"/api/entries/{eid}/shares/{recipient_id(w, owner, 'owner')}",
                        headers=write_headers(alice)).status_code == 204
    after = _entry_row(w, eid)
    assert after["key_version"] == 1
    assert bytes(after["key_blob"]) != bytes(before["key_blob"])
    assert bytes(after["meta_blob"]) != bytes(before["meta_blob"])      # re-sealed under the new key
    assert bytes(after["content_blob"]) != bytes(before["content_blob"])
    rows = _share_rows(w)
    assert [r["recipient_id"] for r in rows] == [recipient_id(w, bob, "bob")]
    assert rows[0]["key_version"] == 1 and bytes(rows[0]["envelope"]) != old_envelopes[rows[0]["recipient_id"]]
    assert bob.get(f"/api/shared/{eid}").json()["password"] == "rotation-secret-1"  # bob unaffected
    assert owner.get(f"/api/shared/{eid}").status_code == 404
    assert alice.get(f"/api/entries/{eid}").json()["password"] == "rotation-secret-1"


def test_an_old_key_generation_cannot_open_the_rotated_entry(w):
    """What a revoked recipient kept (the old entry key) must not open the entry after rotation."""
    alice = w["alice"]
    eid = entry(alice, "Old key", password="old-key-secret")
    share(alice, eid, "owner")
    row = _entry_row(w, eid)
    share_row = _share_rows(w)[0]
    # What the recipient could have kept: the entry key unwrapped from the old envelope.
    store = w["app"].state.ctx.store
    from pastry import auth as authmod
    owner_dek = authmod.try_unlock(authmod.read_auth(w["settings"].auth_path), PASSWORD)
    private = account_keys.ensure_keys(store, 0, owner_dek, w["app"].state.ctx.binding_key(), 0.0)
    old_key = sc.unwrap_key(bytes(private), bytes(share_row["envelope"]),
                            sc.context(row["uid"], row["owner_id"], 0, 0))
    alice.delete(f"/api/entries/{eid}/shares", headers=write_headers(alice))
    rotated = _entry_row(w, eid)
    from pastry.vault import content_aad_entry, meta_aad_entry
    with pytest.raises(crypto.CryptoError):
        crypto.open_sealed(old_key, bytes(rotated["meta_blob"]), meta_aad_entry(rotated["uid"]))
    with pytest.raises(crypto.CryptoError):
        crypto.open_sealed(old_key, bytes(rotated["content_blob"]), content_aad_entry(rotated["uid"]))


def test_replaying_an_old_envelope_after_rotation_fails_closed(w):
    alice, owner, bob = w["alice"], w["owner"], w["bob"]
    eid = entry(alice, "Replay")
    share(alice, eid, "owner")
    share(alice, eid, "bob")
    stale = {r["recipient_id"]: bytes(r["envelope"]) for r in _share_rows(w)}
    alice.delete(f"/api/entries/{eid}/shares/{recipient_id(w, owner, 'owner')}", headers=write_headers(alice))
    bob_id = recipient_id(w, bob, "bob")
    with sqlite3.connect(w["db"]) as conn:  # attacker restores bob's old envelope
        conn.execute("UPDATE shares SET envelope = ? WHERE recipient_id = ?", (stale[bob_id], bob_id))
    assert bob.get(f"/api/shared/{eid}").status_code == 404
    assert bob.get("/api/shared").json()["entries"] == []


def test_revoke_all_removes_everyone_and_leaves_the_owner_intact(w):
    alice, owner, bob = w["alice"], w["owner"], w["bob"]
    eid = entry(alice, "Everyone", password="everyone-secret")
    share(alice, eid, "owner")
    share(alice, eid, "bob")
    assert alice.delete(f"/api/entries/{eid}/shares", headers=write_headers(alice)).status_code == 204
    assert owner.get(f"/api/shared/{eid}").status_code == 404 and bob.get(f"/api/shared/{eid}").status_code == 404
    assert alice.get(f"/api/entries/{eid}").json()["password"] == "everyone-secret"
    assert alice.get(f"/api/entries/{eid}/shares").json()["access"] == []


def test_deleting_an_entry_removes_its_shares(w):
    alice, owner = w["alice"], w["owner"]
    eid = entry(alice, "Gone")
    share(alice, eid, "owner")
    alice.delete(f"/api/entries/{eid}", headers=write_headers(alice))
    assert owner.get(f"/api/shared/{eid}").status_code == 404
    assert _share_rows(w) == []


def test_revoke_fails_closed_if_a_remaining_recipients_key_is_untrustworthy(w):
    alice, owner, bob = w["alice"], w["owner"], w["bob"]
    eid = entry(alice, "Blocked rotation")
    share(alice, eid, "owner")
    share(alice, eid, "bob")
    with sqlite3.connect(w["db"]) as conn:  # corrupt bob's binding MAC
        conn.execute("UPDATE account_keys SET public_mac = ? WHERE account_id = ?", (b"\x00" * 32, recipient_id(w, bob, "bob")))
    response = alice.delete(f"/api/entries/{eid}/shares/{recipient_id(w, owner, 'owner')}",
                            headers=write_headers(alice))
    assert response.status_code == 422
    assert len(_share_rows(w)) == 2                       # nothing was changed
    assert _entry_row(w, eid)["key_version"] == 0


def test_concurrent_edits_and_revocation_never_produce_server_errors(w):
    alice, owner = w["alice"], w["owner"]
    eid = entry(alice, "Race", password="race-secret")
    share(alice, eid, "owner", can_edit=True)
    statuses, lock = [], threading.Lock()
    stop = threading.Event()

    def editor():
        client = _client(w["app"])
        login(client)
        while not stop.is_set():
            code = put_entry(client, "/api/shared", eid, password="from-editor").status_code
            with lock:
                statuses.append(code)

    thread = threading.Thread(target=editor)
    thread.start()
    time.sleep(0.2)
    assert alice.delete(f"/api/entries/{eid}/shares", headers=write_headers(alice)).status_code == 204
    time.sleep(0.2)
    stop.set()
    thread.join()
    assert set(statuses) <= {200, 404}
    assert owner.get(f"/api/shared/{eid}").status_code == 404
    assert put_entry(owner, "/api/shared", eid).status_code == 404  # the revoked editor is out


# ----- separate-password entries ------------------------------------------------------------


def test_shared_protected_entry_still_needs_its_separate_password(w):
    alice, owner = w["alice"], w["owner"]
    eid = entry(alice, "Protected", password="protected-secret-77", separate_password="entry-pass-long-1")
    assert share(alice, eid, "owner", can_edit=True, can_export=True).status_code == 201
    seen = owner.get(f"/api/shared/{eid}").json()
    assert seen["locked"] is True and "password" not in seen
    wrong = owner.post(f"/api/shared/{eid}/unlock", json={"password": "wrong-entry-password"},
                       headers=write_headers(owner))
    assert wrong.status_code == 403
    assert put_entry(owner, "/api/shared", eid).status_code == 423          # edit needs the unlock too
    export = owner.post("/api/packages/export", json={"entry_ids": [eid], "name": "x", "password": PKG_PW,
                                                       "access": "offline"}, headers=write_headers(owner))
    assert export.status_code == 423                                         # export needs the unlock too
    ok = owner.post(f"/api/shared/{eid}/unlock", json={"password": "entry-pass-long-1"}, headers=write_headers(owner))
    assert ok.status_code == 200 and ok.json()["password"] == "protected-secret-77"


def test_entry_key_alone_cannot_open_protected_content(w):
    """Even holding the entry key from a valid envelope, protected content stays sealed."""
    alice = w["alice"]
    eid = entry(alice, "Sealed", password="sealed-secret-xyz", separate_password="entry-pass-long-1")
    share(alice, eid, "owner")
    row = _entry_row(w, eid)
    share_row = _share_rows(w)[0]
    store = w["app"].state.ctx.store
    from pastry import auth as authmod
    dek = authmod.try_unlock(authmod.read_auth(w["settings"].auth_path), PASSWORD)
    private = account_keys.ensure_keys(store, 0, dek, w["app"].state.ctx.binding_key(), 0.0)
    k_e = sc.unwrap_key(bytes(private), bytes(share_row["envelope"]),
                        sc.context(row["uid"], row["owner_id"], 0, row["key_version"]))
    from pastry.vault import content_aad, content_aad_entry
    for aad in (content_aad(row["uid"], True), content_aad_entry(row["uid"]), content_aad(row["uid"], False)):
        with pytest.raises(crypto.CryptoError):
            crypto.open_sealed(k_e, bytes(row["content_blob"]), aad)


def test_revoking_drops_a_held_separate_password_key(w):
    alice, owner = w["alice"], w["owner"]
    eid = entry(alice, "Locked then revoked", separate_password="entry-pass-long-1")
    share(alice, eid, "owner")
    owner.post(f"/api/shared/{eid}/unlock", json={"password": "entry-pass-long-1"}, headers=write_headers(owner))
    assert owner.get(f"/api/shared/{eid}").json()["unlocked"] is True
    alice.delete(f"/api/entries/{eid}/shares", headers=write_headers(alice))
    assert owner.get(f"/api/shared/{eid}").status_code == 404
    sessions = [s for s in w["app"].state.ctx.sessions._sessions.values() if s.account_id == 0]
    assert all(eid not in s.unlocked for s in sessions)


# ----- key binding and malformed envelopes ----------------------------------------------------


def test_substituted_public_key_is_refused(w):
    alice, bob = w["alice"], w["bob"]
    eid = entry(alice, "Substitution")
    attacker_private, attacker_public = sc.generate_keypair()
    with sqlite3.connect(w["db"]) as conn:  # someone with database access swaps bob's public key
        conn.execute("UPDATE account_keys SET public_key = ? WHERE account_id = ?",
                     (attacker_public, recipient_id(w, bob, "bob")))
    response = share(alice, eid, "bob")
    assert response.status_code == 422
    assert "failed verification" in response.json()["detail"]
    assert _share_rows(w) == []


def test_malformed_envelope_fails_closed_without_a_server_error(w):
    alice, owner = w["alice"], w["owner"]
    eid = entry(alice, "Corrupt envelope")
    share(alice, eid, "owner")
    with sqlite3.connect(w["db"]) as conn:
        conn.execute("UPDATE shares SET envelope = ?", (b"\x01" + b"\x00" * 90,))
    assert owner.get(f"/api/shared/{eid}").status_code == 404
    assert owner.get("/api/shared").status_code == 200 and owner.get("/api/shared").json()["entries"] == []


def test_envelope_cannot_be_moved_to_another_recipient_or_entry(w):
    alice, owner = w["alice"], w["owner"]
    first = entry(alice, "First")
    second = entry(alice, "Second")
    share(alice, first, "owner")
    share(alice, second, "owner")
    rows = _share_rows(w)
    with sqlite3.connect(w["db"]) as conn:  # copy first's envelope onto second's share row
        conn.execute("UPDATE shares SET envelope = ? WHERE id = ?", (bytes(rows[0]["envelope"]), rows[1]["id"]))
    assert owner.get(f"/api/shared/{second}").status_code == 404
    assert owner.get(f"/api/shared/{first}").status_code == 200


def test_envelope_primitive_round_trip_and_context_binding():
    private, public = sc.generate_keypair()
    key = b"k" * 32
    ctx = sc.context("a" * 32, 1, 2, 0)
    envelope = sc.wrap_key(public, key, ctx)
    assert sc.unwrap_key(private, envelope, ctx) == key
    for bad in (sc.context("b" * 32, 1, 2, 0), sc.context("a" * 32, 9, 2, 0), sc.context("a" * 32, 1, 3, 0),
                sc.context("a" * 32, 1, 2, 1)):
        with pytest.raises(sc.EnvelopeError):
            sc.unwrap_key(private, envelope, bad)
    other_private, _ = sc.generate_keypair()
    with pytest.raises(sc.EnvelopeError):
        sc.unwrap_key(other_private, envelope, ctx)
    tampered = bytearray(envelope)
    tampered[-1] ^= 1
    with pytest.raises(sc.EnvelopeError):
        sc.unwrap_key(private, bytes(tampered), ctx)
    assert len({sc.wrap_key(public, key, ctx) for _ in range(50)}) == 50  # fresh ephemeral key and nonce


def test_low_order_public_key_is_rejected():
    with pytest.raises(sc.EnvelopeError):
        sc.wrap_key(bytes(32), b"k" * 32, b"ctx")


# ----- isolation of the public surface -------------------------------------------------------


def test_directory_lists_only_active_account_names(w):
    owner = w["owner"]
    names = {a["username"] for a in w["alice"].get("/api/directory").json()["accounts"]}
    assert names == {"owner", "bob"}
    text = w["alice"].get("/api/directory").text
    assert "key" not in text.lower() and "fingerprint" not in text.lower()
    owner.post(f"/api/users/{recipient_id(w, owner, 'bob')}/disable", headers=write_headers(owner))
    assert {a["username"] for a in w["alice"].get("/api/directory").json()["accounts"]} == {"owner"}


def test_access_listing_shows_recipients_with_fingerprints(w):
    alice = w["alice"]
    eid = entry(alice, "Listed")
    share(alice, eid, "bob", can_edit=True)
    data = alice.get(f"/api/entries/{eid}/shares").json()
    assert [(a["username"], a["can_edit"], a["can_export"]) for a in data["access"]] == [("bob", True, False)]
    assert data["access"][0]["fingerprint"] and data["own_fingerprint"]
    assert data["access"][0]["fingerprint"] != data["own_fingerprint"]
    assert alice.get("/api/entries").json()["entries"][0]["shared_with"] == 1


def test_sharing_keeps_each_accounts_database_free_of_plaintext(w):
    alice = w["alice"]
    eid = entry(alice, "Plaintext check", password="MARK-share-plaintext-31")
    share(alice, eid, "owner")
    raw = w["db"].read_bytes()
    assert b"MARK-share-plaintext-31" not in raw and b"Plaintext check" not in raw
