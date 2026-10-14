"""Every route is accounted for: anything that is not explicitly public must refuse anonymous callers."""
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from tests.conftest import BASE_URL

# Routes that are public on purpose, each with the reason.
PUBLIC = {
    ("GET", "/login"): "sign-in page",
    ("POST", "/login"): "sign-in (origin checked, rate limited)",
    ("GET", "/invite/{token}"): "invitation page (token is the credential)",
    ("POST", "/invite/{token}"): "invitation acceptance (single-use token)",
    ("POST", "/release/v1/status"): "package release: capability required",
    ("POST", "/release/v1/challenge"): "package release: capability required",
    ("POST", "/release/v1/redeem"): "package release: capability and password proof required",
    ("GET", "/"): "redirects to sign-in when anonymous",
}


@pytest.fixture
def anon(app):
    return TestClient(app, base_url=BASE_URL), app


def _concrete(path: str) -> str:
    out = path
    for name in ("{entry_id}", "{package_id}", "{account_id}", "{recipient_id}", "{share_id}"):
        out = out.replace(name, "1")
    return out.replace("{sid}", "0123456789abcdef").replace("{token}", "x")


def test_every_non_public_route_refuses_anonymous_requests(anon):
    client, app = anon
    checked = 0
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods - {"HEAD", "OPTIONS"}:
            if (method, route.path) in PUBLIC:
                continue
            response = client.request(method, _concrete(route.path), json={})
            assert response.status_code in (401, 403), (method, route.path, response.status_code)
            checked += 1
    assert checked >= 30  # the inventory is large; this guards against the loop silently matching nothing


def test_public_routes_are_exactly_the_documented_set(anon):
    _, app = anon
    seen = {(m, r.path) for r in app.routes if isinstance(r, APIRoute) for m in r.methods - {"HEAD", "OPTIONS"}}
    documented_public = set(PUBLIC)
    unauthenticated_candidates = {(m, p) for (m, p) in seen if p.startswith("/release/") or p.startswith("/invite/")
                                  or p in ("/login", "/")}
    assert unauthenticated_candidates == documented_public


def test_state_changing_routes_all_check_csrf(app, signed_in):
    """With a valid session but no CSRF token, every state-changing API route must refuse."""
    checked = 0
    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/api/"):
            continue
        for method in route.methods & {"POST", "PUT", "DELETE", "PATCH"}:
            response = signed_in.request(method, _concrete(route.path), json={})
            assert response.status_code == 403, (method, route.path, response.status_code)
            checked += 1
    assert checked >= 20
