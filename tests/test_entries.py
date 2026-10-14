"""CRUD, custom fields, search, categories and favourites."""
from tests.conftest import SAMPLE_ENTRY, write_headers


def create(client, **overrides):
    body = {**SAMPLE_ENTRY, **overrides}
    response = client.post("/api/entries", json=body, headers=write_headers(client))
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_create_and_read_back_all_fields(signed_in):
    entry_id = create(signed_in)
    data = signed_in.get(f"/api/entries/{entry_id}").json()
    assert data["name"] == "My Server"
    assert data["url"] == "https://example.com/admin"
    assert data["category"] == "Servers"
    assert data["favourite"] is True
    assert data["username"] == "admin"
    assert data["password"] == "p4ss-VERY-unique-value"
    assert data["notes"] == "Rotate quarterly"
    assert data["fields"][0] == {"name": "SSH Password", "value": "ssh-secret-value", "secret": True}
    assert data["fields"][1]["secret"] is False
    assert data["locked"] is False and data["unlocked"] is True
    assert data["created_at"] and data["updated_at"]


def test_update_replaces_fields_and_preserves_order(signed_in):
    entry_id = create(signed_in)
    updated = {
        **SAMPLE_ENTRY,
        "name": "Renamed",
        "fields": [
            {"name": "Recovery Code", "value": "abc-123", "secret": True},
            {"name": "SSH Password", "value": "ssh-secret-value", "secret": True},
        ],
    }
    response = signed_in.put(f"/api/entries/{entry_id}", json=updated, headers=write_headers(signed_in))
    assert response.status_code == 200
    data = signed_in.get(f"/api/entries/{entry_id}").json()
    assert data["name"] == "Renamed"
    assert [f["name"] for f in data["fields"]] == ["Recovery Code", "SSH Password"]


def test_delete_removes_entry(signed_in):
    entry_id = create(signed_in)
    assert signed_in.delete(f"/api/entries/{entry_id}", headers=write_headers(signed_in)).status_code == 204
    assert signed_in.get(f"/api/entries/{entry_id}").status_code == 404


def test_missing_entry_returns_404(signed_in):
    assert signed_in.get("/api/entries/9999").status_code == 404


def test_list_supports_search_by_name_and_username(signed_in):
    create(signed_in, name="GitHub", username="octocat", category="Dev", favourite=False)
    create(signed_in, name="Google", username="person@example.org", category="Email", favourite=True)

    names = lambda q: sorted(e["name"] for e in signed_in.get("/api/entries", params={"q": q}).json()["entries"])
    assert names("git") == ["GitHub"]
    assert names("octo") == ["GitHub"]
    assert names("person@") == ["Google"]
    assert names("email") == ["Google"]
    assert names("no-such-thing") == []


def test_search_never_matches_on_passwords(signed_in):
    create(signed_in, name="Plain", password="hidden-needle-xyz")
    assert signed_in.get("/api/entries", params={"q": "hidden-needle"}).json()["entries"] == []


def test_list_reports_categories_favourites_and_sorting(signed_in):
    create(signed_in, name="Zeta", category="Work", favourite=False)
    create(signed_in, name="alpha", category="Home", favourite=True)
    entries = signed_in.get("/api/entries").json()["entries"]
    assert [e["name"] for e in entries] == ["alpha", "Zeta"]
    assert entries[0]["favourite"] is True
    assert {e["category"] for e in entries} == {"Work", "Home"}


def test_list_never_contains_passwords(signed_in):
    create(signed_in, name="Quiet", password="never-in-the-list")
    body = signed_in.get("/api/entries").text
    assert "never-in-the-list" not in body
    assert "ssh-secret-value" not in body


def test_validation_rejects_bad_input(signed_in):
    headers = write_headers(signed_in)
    assert signed_in.post("/api/entries", json={**SAMPLE_ENTRY, "name": "   "}, headers=headers).status_code == 422
    assert signed_in.post("/api/entries", json={**SAMPLE_ENTRY, "url": "javascript:alert(1)"}, headers=headers).status_code == 422
    too_many = [{"name": f"f{i}", "value": "", "secret": False} for i in range(201)]
    assert signed_in.post("/api/entries", json={**SAMPLE_ENTRY, "fields": too_many}, headers=headers).status_code == 422


def test_unlocked_entries_can_be_updated_by_the_session(signed_in):
    entry_id = create(signed_in)
    response = signed_in.put(f"/api/entries/{entry_id}", json={**SAMPLE_ENTRY, "notes": "new"}, headers=write_headers(signed_in))
    assert response.status_code == 200
    assert signed_in.get(f"/api/entries/{entry_id}").json()["notes"] == "new"
