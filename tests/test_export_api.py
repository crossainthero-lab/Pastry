"""Export as Pastry: API authorisation, separate-password enforcement, and no plaintext on disk."""
from pathlib import Path

from fastapi.testclient import TestClient

from pastry import package as pk
from tests.conftest import BASE_URL, write_headers

PACKAGE_PW = "package password 123"
PLAIN = {"name": "Ubuntu AI Server", "url": "https://ai.example.internal", "username": "admin",
         "password": "MARKER-plain-pw-1", "notes": "MARKER-plain-note",
         "fields": [{"name": "API Key", "value": "MARKER-api-key", "secret": True}]}
PROTECTED = {"name": "Bank Login", "username": "saver", "password": "MARKER-bank-pw",
             "separate_password": "bank secret pass 1"}
OTHER = {"name": "Unrelated", "username": "other", "password": "MARKER-other-pw"}


def _client(app):
    return TestClient(app, base_url=BASE_URL)


def _make(client, body):
    response = client.post("/api/entries", json=body, headers=write_headers(client))
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _export(client, ids, **overrides):
    body = {"entry_ids": ids, "name": "server access", "password": PACKAGE_PW, "allow_copy": False,
            "access": "offline", "expires_in_minutes": 60, **overrides}
    return client.post("/api/packages/export", json=body, headers=write_headers(client))


def test_export_produces_a_package_with_only_the_selected_entries(provisioned, signed_in):
    plain_id = _make(signed_in, PLAIN)
    _make(signed_in, OTHER)
    response = _export(signed_in, [plain_id])
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"] == 'attachment; filename="server-access.pastry"'
    assert response.content.startswith(b"PSTRYPKG\x01")
    header, entries = pk.open_package(response.content, PACKAGE_PW)
    assert header.name == "server access" and header.allow_copy is False
    assert [e["name"] for e in entries] == ["Ubuntu AI Server"]
    assert entries[0]["password"] == "MARKER-plain-pw-1"
    assert entries[0]["fields"][0]["secret"] is True


def test_export_response_contains_no_plaintext(signed_in):
    plain_id = _make(signed_in, PLAIN)
    response = _export(signed_in, [plain_id])
    for marker in (b"MARKER-plain-pw-1", b"MARKER-plain-note", b"MARKER-api-key", PACKAGE_PW.encode()):
        assert marker not in response.content


def test_protected_entry_needs_its_separate_password_to_export(signed_in):
    protected_id = _make(signed_in, PROTECTED)
    refused = _export(signed_in, [protected_id])
    assert refused.status_code == 423
    assert "Unlock" in refused.json()["detail"]

    signed_in.post(f"/api/entries/{protected_id}/unlock", json={"password": "bank secret pass 1"},
                   headers=write_headers(signed_in))
    allowed = _export(signed_in, [protected_id])
    assert allowed.status_code == 200
    _, entries = pk.open_package(allowed.content, PACKAGE_PW)
    assert entries[0]["password"] == "MARKER-bank-pw"


def test_relocking_removes_export_permission_for_protected_entries(signed_in, clock):
    protected_id = _make(signed_in, PROTECTED)
    signed_in.post(f"/api/entries/{protected_id}/unlock", json={"password": "bank secret pass 1"},
                   headers=write_headers(signed_in))
    signed_in.post(f"/api/entries/{protected_id}/lock", headers=write_headers(signed_in))
    assert _export(signed_in, [protected_id]).status_code == 423


def test_timed_and_one_time_packages_are_refused_not_faked(signed_in):
    plain_id = _make(signed_in, PLAIN)
    for mode in ("timed", "one_time", "server_enforced"):
        response = _export(signed_in, [plain_id], access=mode)
        assert response.status_code == 501, mode
        assert "not implemented" in response.json()["detail"]


def test_export_validates_inputs(signed_in):
    plain_id = _make(signed_in, PLAIN)
    assert _export(signed_in, [plain_id], password="short").status_code == 422
    assert _export(signed_in, [plain_id], expires_in_minutes=0).status_code == 422
    assert _export(signed_in, [plain_id], expires_in_minutes=10**6).status_code == 422
    assert _export(signed_in, []).status_code == 422
    assert _export(signed_in, [plain_id], name="").status_code == 422


def test_export_of_missing_entry_is_404(signed_in):
    assert _export(signed_in, [424242]).status_code == 404


def test_expiry_is_written_into_the_package_header(signed_in):
    plain_id = _make(signed_in, PLAIN)
    response = _export(signed_in, [plain_id], expires_in_minutes=15)
    header, _ = pk.open_package(response.content, PACKAGE_PW)
    assert header.expires_at is not None


def test_export_requires_authentication_and_csrf(app, signed_in):
    plain_id = _make(signed_in, PLAIN)
    anonymous = _client(app)
    response = anonymous.post("/api/packages/export", json={
        "entry_ids": [plain_id], "name": "x", "password": PACKAGE_PW}, headers={})
    assert response.status_code == 401
    no_csrf = signed_in.post("/api/packages/export", json={
        "entry_ids": [plain_id], "name": "x", "password": PACKAGE_PW})
    assert no_csrf.status_code == 403


def test_export_writes_nothing_to_disk(signed_in, provisioned):
    before = sorted(str(p.relative_to(provisioned.home)) for p in provisioned.home.rglob("*") if p.is_file())
    plain_id = _make(signed_in, PLAIN)
    _export(signed_in, [plain_id])
    after = sorted(str(p.relative_to(provisioned.home)) for p in provisioned.home.rglob("*") if p.is_file())
    new_files = [name for name in after if name not in before]
    assert all(not name.endswith(".pastry") for name in new_files)
    assert not any("MARKER" in Path(provisioned.home / name).read_bytes().decode("latin-1")
                   for name in new_files if name.endswith((".json", ".txt")))


def test_other_entries_remain_private_to_the_session_after_export(signed_in):
    plain_id = _make(signed_in, PLAIN)
    other_id = _make(signed_in, OTHER)
    _export(signed_in, [plain_id])
    assert signed_in.get(f"/api/entries/{other_id}").json()["password"] == "MARKER-other-pw"
