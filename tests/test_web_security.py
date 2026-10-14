"""Login, sessions, CSRF, origin policy, caching and headers."""
from pastry import auth as authmod
from tests.conftest import PASSWORD, USERNAME, login, write_headers


def test_correct_login_sets_hardened_cookie(client):
    response = login(client)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    cookie = response.headers["set-cookie"].lower()
    assert "__host-pastry_session=" in cookie
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=strict" in cookie
    assert "path=/" in cookie


def test_correct_login_opens_vault_page(signed_in):
    page = signed_in.get("/")
    assert page.status_code == 200
    assert USERNAME in page.text
    assert 'data-csrf="' in page.text


def test_incorrect_password_gives_generic_error(client):
    response = login(client, password="wrong password here")
    assert response.status_code == 401
    assert "Invalid username or password." in response.text


def test_unknown_username_gives_the_same_generic_error(client):
    unknown = login(client, username="nobody-here")
    wrong_password = login(client, password="wrong password here")
    assert unknown.status_code == wrong_password.status_code == 401
    assert "Invalid username or password." in unknown.text
    assert "Invalid username or password." in wrong_password.text


def test_unauthenticated_access_is_refused(client):
    assert client.get("/", follow_redirects=False).status_code == 303
    assert client.get("/api/entries").status_code == 401
    assert client.get("/api/settings").status_code == 401


def test_login_rate_limit_blocks_even_the_correct_password(client, clock):
    for _ in range(5):
        assert login(client, password="wrong password here").status_code == 401
    blocked = login(client)
    assert blocked.status_code == 429
    assert "Try again" in blocked.text

    clock.advance(15 * 60 + 1)
    assert login(client).status_code == 303


def test_session_expires_after_inactivity(signed_in, clock):
    assert signed_in.get("/api/entries").status_code == 200
    clock.advance(9 * 60)
    assert signed_in.get("/api/entries").status_code == 200  # activity extends the session
    clock.advance(10 * 60 + 1)
    assert signed_in.get("/api/entries").status_code == 401


def test_status_polling_does_not_extend_session(signed_in, clock):
    clock.advance(9 * 60)
    assert signed_in.get("/api/session/status").status_code == 200
    clock.advance(2 * 60)
    assert signed_in.get("/api/session/status").status_code == 401


def test_sign_out_destroys_session(signed_in):
    headers = write_headers(signed_in)
    assert signed_in.post("/api/logout", headers=headers).status_code == 204
    assert signed_in.get("/api/entries").status_code == 401


def test_unsafe_request_without_csrf_token_is_refused(signed_in):
    response = signed_in.post("/api/entries", json={"name": "x"})
    assert response.status_code == 403


def test_unsafe_request_with_wrong_csrf_token_is_refused(signed_in):
    response = signed_in.post("/api/entries", json={"name": "x"}, headers={"X-CSRF-Token": "forged"})
    assert response.status_code == 403


def test_cross_site_origin_is_refused_even_with_a_valid_token(signed_in):
    headers = {**write_headers(signed_in), "Origin": "https://evil.example"}
    response = signed_in.post("/api/entries", json={"name": "x"}, headers=headers)
    assert response.status_code == 403


def test_fetch_metadata_cross_site_is_refused(signed_in):
    headers = {**write_headers(signed_in), "Sec-Fetch-Site": "cross-site"}
    response = signed_in.post("/api/entries", json={"name": "x"}, headers=headers)
    assert response.status_code == 403


def test_same_origin_write_is_accepted(signed_in):
    headers = {**write_headers(signed_in), "Origin": "https://testserver", "Sec-Fetch-Site": "same-origin"}
    response = signed_in.post("/api/entries", json={"name": "x"}, headers=headers)
    assert response.status_code == 201


def test_unknown_host_header_is_refused(client):
    response = client.get("/login", headers={"host": "evil.example"})
    assert response.status_code == 400


def test_sensitive_responses_are_not_cached(signed_in):
    for path in ("/", "/api/entries", "/login"):
        response = signed_in.get(path, follow_redirects=False)
        assert "no-store" in response.headers["cache-control"]
        assert response.headers["pragma"] == "no-cache"


def test_security_headers_are_present(client):
    response = client.get("/login")
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "same-origin"


def test_no_external_resources_are_referenced(signed_in):
    html = signed_in.get("/").text
    assert "http://" not in html and "https://" not in html.replace("https://testserver", "")
    assert "googleapis" not in html and "cdn" not in html


def test_password_change_invalidates_existing_sessions(signed_in, provisioned):
    assert signed_in.get("/api/entries").status_code == 200
    authmod.change_password(provisioned.auth_path, PASSWORD, "a brand new password 2")
    assert signed_in.get("/api/entries").status_code == 401
    assert login(signed_in, password=PASSWORD).status_code == 401
    assert login(signed_in, password="a brand new password 2").status_code == 303


def test_settings_endpoint_changes_idle_timeout(signed_in, clock):
    headers = write_headers(signed_in)
    response = signed_in.put("/api/settings", json={"session_timeout_minutes": 2}, headers=headers)
    assert response.status_code == 200
    clock.advance(2 * 60 + 1)
    assert signed_in.get("/api/entries").status_code == 401


def test_settings_rejects_out_of_range_timeout(signed_in):
    response = signed_in.put("/api/settings", json={"session_timeout_minutes": 0}, headers=write_headers(signed_in))
    assert response.status_code == 422


def test_null_origin_is_refused(signed_in):
    headers = {**write_headers(signed_in), "Origin": "null"}
    assert signed_in.post("/api/entries", json={"name": "x"}, headers=headers).status_code == 403


def test_login_form_post_with_same_origin_is_accepted(client):
    response = client.post(
        "/login",
        data={"username": USERNAME, "password": PASSWORD},
        headers={"Origin": "https://testserver", "Sec-Fetch-Site": "same-origin"},
        follow_redirects=False,
    )
    assert response.status_code == 303
