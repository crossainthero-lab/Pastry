"""Shared fixtures. Tests use a temporary Pastry home, a fake clock and cheap Argon2
parameters so the suite stays fast. Production defaults are unchanged."""

import re

import pytest
from fastapi.testclient import TestClient

from pastry import auth as authmod
from pastry.config import Settings
from pastry.crypto import KdfParams
from pastry.db import Store
from pastry.web import create_app

FAST_KDF = KdfParams(time_cost=1, memory_cost=8192, parallelism=1)
USERNAME = "owner"
PASSWORD = "correct horse battery"
BASE_URL = "https://testserver"  # https so Secure cookies are sent by the test client


class FakeClock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def settings(tmp_path):
    return Settings(home=tmp_path, kdf=FAST_KDF, allowed_hosts=["testserver", "127.0.0.1", "localhost"])


@pytest.fixture
def provisioned(settings):
    """Equivalent of `pastry setup` without the interactive prompts."""
    Store(settings.db_path).init()
    authmod.create_auth(settings.auth_path, USERNAME, PASSWORD, FAST_KDF)
    return settings


@pytest.fixture
def app(provisioned, clock):
    return create_app(provisioned, clock=clock, wall_clock=clock)


@pytest.fixture
def client(app):
    return TestClient(app, base_url=BASE_URL)


def login(client, username=USERNAME, password=PASSWORD):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def csrf_token(client):
    html = client.get("/").text
    match = re.search(r'data-csrf="([^"]+)"', html)
    assert match, "CSRF token missing from the vault page"
    return match.group(1)


@pytest.fixture
def signed_in(client):
    response = login(client)
    assert response.status_code == 303
    return client


def write_headers(client):
    return {"X-CSRF-Token": csrf_token(client)}


SAMPLE_ENTRY = {
    "name": "My Server",
    "url": "https://example.com/admin",
    "category": "Servers",
    "favourite": True,
    "username": "admin",
    "password": "p4ss-VERY-unique-value",
    "notes": "Rotate quarterly",
    "fields": [
        {"name": "SSH Password", "value": "ssh-secret-value", "secret": True},
        {"name": "Custom Note", "value": "plain text value", "secret": False},
    ],
}
