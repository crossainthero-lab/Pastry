"""Owner package API and public release routes, through the real HTTP stack (TestClient)."""
import base64
import sqlite3

import pytest
from fastapi.testclient import TestClient

from pastry import package as pk
from pastry.release_client import ReleaseRefused, open_server_package
from pastry.web import create_app
from tests.conftest import BASE_URL, SAMPLE_ENTRY, login, write_headers

URL = "https://pastry.example.ts.net"
PKG_PW = "package password 2026"
SECRET_PW = "SERVER-ONLY-SECRET-77"


class HttpTestTransport:
    """The recipient client talking to the real app through TestClient (no session cookies)."""

    def __init__(self, client):
        self.client = client

    def _post(self, path, body):
        response = self.client.post(path, json=body)
        if response.status_code >= 400:
            data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
            code = data.get("code") or ("rate_limited" if response.status_code == 429 else "server")
            raise ReleaseRefused(response.status_code, code, data.get("detail", "refused"))
        return response.json()

    def status(self, capability):
        return self._post("/release/v1/status", {"capability": capability})

    def challenge(self, capability):
        return self._post("/release/v1/challenge", {"capability": capability})["nonce"]

    def redeem(self, capability, nonce, proof_b64):
        return self._post("/release/v1/redeem", {"capability": capability, "nonce": nonce, "proof": proof_b64})


@pytest.fixture
def rel_app(provisioned, clock):
    provisioned.public_url = URL
    return create_app(provisioned, clock=clock, wall_clock=clock)


@pytest.fixture
def owner(rel_app):
    client = TestClient(rel_app, base_url=BASE_URL)
    assert login(client).status_code == 303
    return client


@pytest.fixture
def anon(rel_app):
    return TestClient(rel_app, base_url=BASE_URL)


def _entry(owner_client, password=SECRET_PW):
    body = {**SAMPLE_ENTRY, "name": "Ubuntu AI Server", "password": password, "fields": []}
    response = owner_client.post("/api/entries", json=body, headers=write_headers(owner_client))
    assert response.status_code == 201
    return response.json()["id"]


def _create(owner_client, ids, **overrides):
    body = {"entry_ids": ids, "name": "server access", "password": PKG_PW, "allow_copy": False,
            "policy": "after_open", "duration_minutes": 5, **overrides}
    return owner_client.post("/api/packages", json=body, headers=write_headers(owner_client))


def _package_id(response):
    return int(response.headers["x-pastry-package-id"])


# ----- creation and listing -----------------------------------------------------------


def test_create_returns_a_server_enforced_file_without_secrets(owner):
    entry = _entry(owner)
    response = _create(owner, [entry])
    assert response.status_code == 200
    assert response.content.startswith(b"PSTRYPKG\x01")
    header, _ = pk.read_header(response.content)
    assert header.is_server and header.release_url == URL
    assert header.policy == {"type": "after_open", "seconds": 300}
    assert SECRET_PW.encode() not in response.content
    with pytest.raises(pk.PackageError, match="server-enforced"):
        pk.open_package(response.content, PKG_PW)


def test_timed_packages_need_a_public_address(provisioned, clock):
    provisioned.public_url = ""
    client = TestClient(create_app(provisioned, clock=clock, wall_clock=clock), base_url=BASE_URL)
    login(client)
    response = _create(client, [_entry(client)])
    assert response.status_code == 422
    assert "public_url" in response.json()["detail"]


def test_creation_validates_policy_inputs(owner):
    entry = _entry(owner)
    assert _create(owner, [entry], duration_minutes=7).status_code == 422
    assert _create(owner, [entry], policy="sometimes").status_code == 422
    assert _create(owner, [entry], policy="absolute", absolute_minutes=None).status_code == 422
    assert _create(owner, [entry], policy="absolute", absolute_minutes=60 * 24 * 60).status_code == 422
    assert _create(owner, [entry], policy="one_time", duration_minutes=None).status_code == 200


def test_locked_entries_need_unlocking_before_a_package_is_made(owner):
    locked = owner.post("/api/entries", json={**SAMPLE_ENTRY, "name": "Bank", "separate_password": "bank-pass-long-1"},
                        headers=write_headers(owner)).json()["id"]
    assert _create(owner, [locked]).status_code == 423


def test_list_shows_status_and_never_the_capability(owner):
    response = _create(owner, [_entry(owner)])
    listing = owner.get("/api/packages")
    body = listing.text
    package = listing.json()["packages"][0]
    assert package["name"] == "server access" and package["state"] == "active"
    assert package["entry_count"] == 1 and package["policy"] == "after_open"
    header, _ = pk.read_header(response.content)
    assert base64.urlsafe_b64encode(header.capability).rstrip(b"=").decode() not in body
    assert "cap_hash" not in body


def test_download_returns_the_stored_encrypted_copy(owner):
    created = _create(owner, [_entry(owner)])
    downloaded = owner.get(f"/api/packages/{_package_id(created)}/file")
    assert downloaded.status_code == 200
    assert downloaded.content == created.content


def test_database_holds_no_plaintext_entry_data(owner, provisioned):
    _create(owner, [_entry(owner)])
    raw = provisioned.db_path.read_bytes()
    assert SECRET_PW.encode() not in raw
    assert b"Ubuntu AI Server" not in raw


# ----- release over HTTP --------------------------------------------------------------


def test_recipient_opens_a_server_package_over_the_release_api(owner, anon):
    created = _create(owner, [_entry(owner)])
    release = open_server_package(created.content, PKG_PW, HttpTestTransport(anon))
    assert release.entries[0]["password"] == SECRET_PW
    assert release.expires_at is not None


def test_release_api_needs_no_vault_session_and_returns_no_vault_material(owner, anon):
    created = _create(owner, [_entry(owner)])
    header, _ = pk.read_header(created.content)
    cap = base64.urlsafe_b64encode(header.capability).rstrip(b"=").decode()
    nonce = anon.post("/release/v1/challenge", json={"capability": cap}).json()["nonce"]
    proof = base64.b64encode(pk.proof_for(pk.derive_keys(PKG_PW, header.salt, header.kdf)[1], header.package_id, nonce)).decode()
    answer = anon.post("/release/v1/redeem", json={"capability": cap, "nonce": nonce, "proof": proof})
    assert answer.status_code == 200
    assert set(answer.json()) == {"package_id", "wrapped_key", "expires_at"}
    assert "dek" not in answer.text.lower() and "session" not in answer.text.lower()


def test_wrong_password_over_http_is_refused_and_counted(owner, anon):
    created = _create(owner, [_entry(owner)])
    transport = HttpTestTransport(anon)
    for _ in range(5):
        with pytest.raises(ReleaseRefused) as info:
            open_server_package(created.content, "wrong password 99999", transport)
        assert info.value.code == "bad_password"
    with pytest.raises(ReleaseRefused) as info:  # now blocked, even with the right password
        open_server_package(created.content, PKG_PW, transport)
    assert info.value.status == 429


def test_failure_lockout_expires_on_the_server_clock(owner, anon, clock):
    created = _create(owner, [_entry(owner)])
    transport = HttpTestTransport(anon)
    for _ in range(5):
        with pytest.raises(ReleaseRefused):
            open_server_package(created.content, "wrong password 99999", transport)
    clock.advance(15 * 60 + 1)
    assert open_server_package(created.content, PKG_PW, transport).entries


def test_request_volume_is_rate_limited_per_client(anon):
    for _ in range(30):
        anon.post("/release/v1/status", json={"capability": "A" * 43})
    response = anon.post("/release/v1/status", json={"capability": "A" * 43})
    assert response.status_code == 429


def test_malformed_release_requests_are_rejected(anon):
    assert anon.post("/release/v1/status", json={"capability": "short"}).status_code == 422
    assert anon.post("/release/v1/status", json={"capability": "B" * 43}).status_code == 404
    # "A"*43 is canonical base64url for 32 zero bytes; it is well-formed but unknown.
    assert anon.post("/release/v1/redeem", json={"capability": "A" * 43, "nonce": "n", "proof": "!!"}).status_code == 422  # malformed proof is refused before lookup


def test_release_routes_ignore_forwarded_headers_for_rate_limits(anon):
    for index in range(31):
        response = anon.post("/release/v1/status", json={"capability": "C" * 43},
                             headers={"X-Forwarded-For": f"198.51.100.{index}"})
    assert response.status_code == 429


def test_one_time_package_over_http_releases_once(owner, anon):
    created = _create(owner, [_entry(owner)], policy="one_time")
    transport = HttpTestTransport(anon)
    open_server_package(created.content, PKG_PW, transport)
    with pytest.raises(ReleaseRefused) as info:
        open_server_package(created.content, PKG_PW, transport)
    assert info.value.code == "consumed"


# ----- revocation, deletion and isolation ----------------------------------------------


def test_revoke_via_api_stops_release_immediately(owner, anon):
    created = _create(owner, [_entry(owner)])
    package_id = _package_id(created)
    assert owner.post(f"/api/packages/{package_id}/revoke", headers=write_headers(owner)).status_code == 204
    with pytest.raises(ReleaseRefused) as info:
        open_server_package(created.content, PKG_PW, HttpTestTransport(anon))
    assert info.value.code == "revoked"
    assert owner.get("/api/packages").json()["packages"][0]["state"] == "revoked"


def test_delete_via_api_removes_the_package_and_its_copy(owner):
    created = _create(owner, [_entry(owner)])
    package_id = _package_id(created)
    assert owner.delete(f"/api/packages/{package_id}", headers=write_headers(owner)).status_code == 204
    assert owner.get(f"/api/packages/{package_id}/file").status_code == 404
    assert owner.get("/api/packages").json()["packages"] == []


def test_package_endpoints_refuse_anonymous_callers(anon, owner):
    created = _create(owner, [_entry(owner)])
    pid = _package_id(created)
    assert anon.get("/api/packages").status_code == 401
    assert anon.get(f"/api/packages/{pid}/file").status_code == 401
    assert anon.post(f"/api/packages/{pid}/revoke").status_code == 401
    assert anon.delete(f"/api/packages/{pid}").status_code == 401


def test_package_writes_need_csrf(owner):
    created = _create(owner, [_entry(owner)])
    pid = _package_id(created)
    assert owner.post(f"/api/packages/{pid}/revoke").status_code == 403
    assert owner.delete(f"/api/packages/{pid}").status_code == 403


def test_another_owners_package_cannot_be_reached_by_id(owner, rel_app, provisioned, clock):
    """Simulates a second account's package. Its id must yield 404 for this owner everywhere."""
    svc = owner.app.state.ctx.release_service()
    from pastry.release import NewPackage
    import secrets as _secrets

    foreign = svc.create(NewPackage("mallory", _secrets.token_bytes(32), "one_time", None, None, 1,
                                    b"x" * 40, b"f" * 60, _secrets.token_bytes(32), _secrets.token_bytes(32)),
                         clock.now)
    assert owner.get(f"/api/packages/{foreign}/file").status_code == 404
    assert owner.post(f"/api/packages/{foreign}/revoke", headers=write_headers(owner)).status_code == 404
    assert owner.delete(f"/api/packages/{foreign}", headers=write_headers(owner)).status_code == 404
    listed = [p["id"] for p in owner.get("/api/packages").json()["packages"]]
    assert foreign not in listed


def test_expired_session_cannot_create_packages(owner, clock):
    headers = write_headers(owner)  # token captured while the session was still valid
    clock.advance(11 * 60)
    response = owner.post("/api/packages", json={"entry_ids": [1], "name": "x", "password": PKG_PW,
                                                 "policy": "one_time"}, headers=headers)
    assert response.status_code == 401


def test_sweep_runs_on_listing_and_erases_expired_release_material(owner, clock, provisioned):
    created = _create(owner, [_entry(owner)])
    anon = TestClient(owner.app, base_url=BASE_URL)
    open_server_package(created.content, PKG_PW, HttpTestTransport(anon))
    clock.advance(301)
    owner.get("/api/packages")
    with sqlite3.connect(provisioned.db_path) as conn:
        row = conn.execute("SELECT state, release_blob, auth_blob FROM packages").fetchone()
    assert row == ("expired", None, None)
