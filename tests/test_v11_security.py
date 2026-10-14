"""v1.1 hardening: persistent throttling, sessions, password change, re-lock, encrypted timestamps."""
import re

import pytest
from fastapi.testclient import TestClient

from pastry import auth as authmod
from pastry.web import create_app
from tests.conftest import BASE_URL, PASSWORD, SAMPLE_ENTRY, USERNAME, login, write_headers

NEW_PASSWORD = "a brand new master password"


def new_client(app):
    return TestClient(app, base_url=BASE_URL)


def make_entry(client, **overrides):
    response = client.post("/api/entries", json={**SAMPLE_ENTRY, **overrides}, headers=write_headers(client))
    assert response.status_code == 201, response.text
    return response.json()["id"]


# ----- persistent login throttling -------------------------------------------


def test_login_lockout_survives_a_restart(provisioned, clock):
    app1 = create_app(provisioned, clock=clock, wall_clock=clock)
    first = new_client(app1)
    for _ in range(5):
        assert login(first, password="wrong password here").status_code == 401
    # A fresh process (new app object) over the same database is still locked out.
    app2 = create_app(provisioned, clock=clock, wall_clock=clock)
    assert login(new_client(app2)).status_code == 429


def test_lockout_expires_on_the_persisted_clock(provisioned, clock):
    app = create_app(provisioned, clock=clock, wall_clock=clock)
    client = new_client(app)
    for _ in range(5):
        login(client, password="wrong password here")
    assert login(client).status_code == 429
    clock.advance(15 * 60 + 1)
    assert login(client).status_code == 303


def test_forwarded_headers_cannot_reset_the_limit(client):
    for index in range(5):
        response = client.post(
            "/login",
            data={"username": USERNAME, "password": "wrong password here"},
            headers={"X-Forwarded-For": f"10.0.0.{index}", "X-Real-IP": f"10.1.0.{index}"},
        )
        assert response.status_code == 401
    spoofed = client.post(
        "/login", data={"username": USERNAME, "password": PASSWORD},
        headers={"X-Forwarded-For": "203.0.113.99"},
    )
    assert spoofed.status_code == 429  # same socket peer, so still locked


def test_entry_unlock_throttle_survives_restart(provisioned, clock):
    app1 = create_app(provisioned, clock=clock, wall_clock=clock)
    client = new_client(app1)
    login(client)
    entry_id = client.post("/api/entries", json={**SAMPLE_ENTRY, "separate_password": "entry-pass-long-1"},
                           headers=write_headers(client)).json()["id"]
    for _ in range(5):
        client.post(f"/api/entries/{entry_id}/unlock", json={"password": "guess-guess-guess"},
                    headers=write_headers(client))
    app2 = create_app(provisioned, clock=clock, wall_clock=clock)
    client2 = new_client(app2)
    login(client2)
    response = client2.post(f"/api/entries/{entry_id}/unlock", json={"password": "entry-pass-long-1"},
                            headers=write_headers(client2))
    assert response.status_code == 429


# ----- sessions ---------------------------------------------------------------


def test_session_ids_are_random_and_not_the_token(signed_in, provisioned):
    sessions = signed_in.get("/api/sessions").json()["sessions"]
    assert len(sessions) == 1 and sessions[0]["current"] is True
    cookie = signed_in.cookies.get("__Host-pastry_session")
    assert cookie not in str(sessions)
    assert re.fullmatch(r"[0-9a-f]{16}", sessions[0]["id"])


def test_revoking_another_device_signs_it_out(provisioned, clock):
    app = create_app(provisioned, clock=clock, wall_clock=clock)
    laptop = new_client(app)
    phone = new_client(app)
    login(laptop)
    login(phone)
    listed = laptop.get("/api/sessions").json()["sessions"]
    assert len(listed) == 2
    phone_id = next(s["id"] for s in listed if not s["current"])
    assert laptop.delete(f"/api/sessions/{phone_id}", headers=write_headers(laptop)).status_code == 204
    assert phone.get("/api/entries").status_code == 401
    assert laptop.get("/api/entries").status_code == 200


def test_log_out_other_sessions_keeps_current(provisioned, clock):
    app = create_app(provisioned, clock=clock, wall_clock=clock)
    a, b, c = new_client(app), new_client(app), new_client(app)
    for client in (a, b, c):
        login(client)
    result = a.post("/api/sessions/revoke-others", headers=write_headers(a))
    assert result.json()["revoked"] == 2
    assert b.get("/api/entries").status_code == 401
    assert c.get("/api/entries").status_code == 401
    assert a.get("/api/entries").status_code == 200


def test_revoking_current_session_is_sign_out(signed_in):
    sid = signed_in.get("/api/sessions").json()["sessions"][0]["id"]
    assert signed_in.delete(f"/api/sessions/{sid}", headers=write_headers(signed_in)).status_code == 204
    assert signed_in.get("/api/entries").status_code == 401


def test_revoke_rejects_malformed_and_unknown_ids(signed_in):
    headers = write_headers(signed_in)
    assert signed_in.delete("/api/sessions/not-a-real-id", headers=headers).status_code == 422
    assert signed_in.delete("/api/sessions/0123456789abcdef", headers=headers).status_code == 404


def test_session_endpoints_require_authentication_and_csrf(app, signed_in):
    anonymous = new_client(app)  # separate cookie jar: not signed in
    assert anonymous.get("/api/sessions").status_code == 401
    assert anonymous.post("/api/sessions/revoke-others").status_code == 401
    assert signed_in.post("/api/sessions/revoke-others").status_code == 403


# ----- password change through the API -------------------------------------


def test_password_change_requires_the_current_password(signed_in, provisioned):
    headers = write_headers(signed_in)
    response = signed_in.post("/api/account/password", json={"current": "wrong current pass", "new": NEW_PASSWORD},
                              headers=headers)
    assert response.status_code == 403
    assert authmod.try_unlock(authmod.read_auth(provisioned.auth_path), PASSWORD) is not None


def test_password_change_keeps_entries_and_signs_out_everywhere(provisioned, clock):
    app = create_app(provisioned, clock=clock, wall_clock=clock)
    client = new_client(app)
    other = new_client(app)
    login(client)
    login(other)
    entry_id = make_entry(client, name="Survivor")
    response = client.post("/api/account/password", json={"current": PASSWORD, "new": NEW_PASSWORD},
                           headers=write_headers(client))
    assert response.status_code == 204
    assert client.get("/api/entries").status_code == 401
    assert other.get("/api/entries").status_code == 401
    assert login(new_client(app), password=PASSWORD).status_code == 401
    fresh = new_client(app)
    assert login(fresh, password=NEW_PASSWORD).status_code == 303
    assert fresh.get(f"/api/entries/{entry_id}").json()["name"] == "Survivor"


def test_password_change_is_throttled(signed_in):
    headers = write_headers(signed_in)
    for _ in range(5):
        signed_in.post("/api/account/password", json={"current": "wrong current pass", "new": NEW_PASSWORD},
                       headers=headers)
    response = signed_in.post("/api/account/password", json={"current": PASSWORD, "new": NEW_PASSWORD},
                              headers=headers)
    assert response.status_code == 429


def test_password_change_rejects_short_new_password(signed_in):
    response = signed_in.post("/api/account/password", json={"current": PASSWORD, "new": "short"},
                              headers=write_headers(signed_in))
    assert response.status_code == 422


def test_auth_file_write_is_atomic_when_interrupted(provisioned, monkeypatch):
    import os as os_module

    before = provisioned.auth_path.read_bytes()

    def boom(src, dst):
        raise OSError("simulated power loss during rename")

    monkeypatch.setattr(os_module, "replace", boom)
    with pytest.raises(OSError):
        authmod.change_password(provisioned.auth_path, PASSWORD, NEW_PASSWORD)
    monkeypatch.undo()
    assert provisioned.auth_path.read_bytes() == before
    assert authmod.try_unlock(authmod.read_auth(provisioned.auth_path), PASSWORD) is not None


# ----- entry re-lock after inactivity ---------------------------------------


def test_separate_password_entry_relocks_after_idle_period(signed_in, clock):
    entry_id = make_entry(signed_in, name="Idle Test", separate_password="entry-pass-long-1")
    signed_in.post(f"/api/entries/{entry_id}/unlock", json={"password": "entry-pass-long-1"},
                   headers=write_headers(signed_in))
    assert "password" in signed_in.get(f"/api/entries/{entry_id}").json()

    clock.advance(4 * 60)
    assert "password" in signed_in.get(f"/api/entries/{entry_id}").json()  # access refreshes the timer
    clock.advance(4 * 60)
    assert "password" in signed_in.get(f"/api/entries/{entry_id}").json()
    clock.advance(5 * 60 + 1)  # now idle for longer than the limit
    data = signed_in.get(f"/api/entries/{entry_id}").json()
    assert data["locked"] is True and data["unlocked"] is False
    assert "password" not in data


def test_listing_does_not_refresh_an_entry_unlock(signed_in, clock):
    entry_id = make_entry(signed_in, separate_password="entry-pass-long-1")
    signed_in.post(f"/api/entries/{entry_id}/unlock", json={"password": "entry-pass-long-1"},
                   headers=write_headers(signed_in))
    for _ in range(3):
        clock.advance(2 * 60)
        signed_in.get("/api/entries")  # touching the session alone must not keep the entry open
    assert signed_in.get(f"/api/entries/{entry_id}").json()["unlocked"] is False


def test_writes_to_relocked_entry_are_refused(signed_in, clock):
    entry_id = make_entry(signed_in, separate_password="entry-pass-long-1")
    signed_in.post(f"/api/entries/{entry_id}/unlock", json={"password": "entry-pass-long-1"},
                   headers=write_headers(signed_in))
    clock.advance(5 * 60 + 1)
    response = signed_in.put(f"/api/entries/{entry_id}", json=SAMPLE_ENTRY, headers=write_headers(signed_in))
    assert response.status_code == 423


# ----- encryption of metadata ------------------------------------------------


def test_timestamps_and_lock_state_are_not_plaintext(provisioned, signed_in):
    make_entry(signed_in, name="Timed", separate_password="entry-pass-long-1")
    raw = provisioned.db_path.read_bytes()
    assert not re.search(rb"\d{4}-\d{2}-\d{2}T\d{2}", raw)
    assert b"Timed" not in raw
    assert b"entry-pass-long-1" not in raw


def test_nonces_are_unique_across_many_seals():
    from pastry import crypto

    key = crypto.new_key()
    nonces = {crypto.seal(key, b"x", b"aad")[1:13] for _ in range(5000)}
    assert len(nonces) == 5000


def test_entry_ciphertext_cannot_be_moved_between_entries(provisioned, signed_in):
    import sqlite3

    first = make_entry(signed_in, name="First")
    second = make_entry(signed_in, name="Second")
    with sqlite3.connect(provisioned.db_path) as conn:
        blob_first = conn.execute("SELECT meta_blob FROM entries WHERE id=?", (first,)).fetchone()[0]
        conn.execute("UPDATE entries SET meta_blob=? WHERE id=?", (blob_first, second))
    assert signed_in.get("/api/entries").status_code == 500  # decryption fails: swapped blob is rejected


# ----- web hardening -------------------------------------------------------


def test_script_in_entry_name_is_returned_as_data_not_markup(signed_in):
    payload = "<img src=x onerror=alert(1)>"
    entry_id = make_entry(signed_in, name=payload)
    assert signed_in.get(f"/api/entries/{entry_id}").json()["name"] == payload
    page = signed_in.get("/").text
    assert payload not in page


def test_all_api_routes_refuse_anonymous_callers(app):
    client = new_client(app)
    checks = [
        ("get", "/api/entries"), ("get", "/api/settings"), ("get", "/api/sessions"),
        ("get", "/api/entries/1"), ("post", "/api/export"), ("post", "/api/import"),
        ("post", "/api/account/password"), ("post", "/api/entries"),
    ]
    for method, path in checks:
        response = client.request(method.upper(), path, json={})
        assert response.status_code in (401, 403), (method, path, response.status_code)


def test_backup_status_is_reported_in_settings(signed_in):
    data = signed_in.get("/api/settings").json()
    assert data["backups"] == {"latest": None, "count": 0}


def test_frontend_renders_user_data_with_text_nodes_only():
    from pathlib import Path

    source = (Path(__file__).resolve().parent.parent / "pastry" / "static" / "app.js").read_text()
    code_lines = [line for line in source.splitlines() if "innerHTML" in line and not line.strip().startswith("*")]
    assert code_lines == []
    assert "eval(" not in source and "new Function(" not in source
