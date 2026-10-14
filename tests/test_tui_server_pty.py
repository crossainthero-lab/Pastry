"""Real `pastry open` against a live release server, driven in a pseudo-terminal."""
import os
import socket
import sys
from pathlib import Path

import pytest

pexpect = pytest.importorskip("pexpect")
pytestmark = pytest.mark.skipif(os.name != "posix", reason="pseudo-terminals need POSIX")

from fastapi.testclient import TestClient  # noqa: E402

from pastry.web import create_app  # noqa: E402
from tests.conftest import BASE_URL, login, write_headers  # noqa: E402
from tests.netserver import ServerThread, free_port  # noqa: E402

PKG_PW = "package password 2026"
SECRET = "SERVER-PTY-SECRET-5150"


def _spawn(cwd: Path, *args):
    env = {**os.environ, "TERM": "xterm-256color", "PASTRY_VIEWER_POLL_SECONDS": "1", "PYTHONUNBUFFERED": "1"}
    return pexpect.spawn(sys.executable, ["-m", "pastry", *args], cwd=str(cwd), env=env,
                         encoding="utf-8", timeout=20, dimensions=(40, 120))


@pytest.fixture
def world(provisioned, clock):
    """A running app on a known port, and a package created in-process that points at it."""
    import time

    clock.now = time.time()  # the viewer compares server expiries with the machine clock, so match it
    port = free_port()
    provisioned.public_url = f"http://127.0.0.1:{port}"
    app = create_app(provisioned, clock=clock, wall_clock=clock)
    owner = TestClient(app, base_url=BASE_URL)
    assert login(owner).status_code == 303
    entry = owner.post("/api/entries", json={"name": "Ubuntu AI Server", "username": "admin", "password": SECRET,
                                             "notes": "", "url": "", "fields": []},
                       headers=write_headers(owner)).json()["id"]
    return {"app": app, "owner": owner, "port": port, "entry": entry, "clock": clock}


def _package(world, policy="after_open", minutes=5, name="server-access"):
    body = {"entry_ids": [world["entry"]], "name": name, "password": PKG_PW, "allow_copy": False,
            "policy": policy, "duration_minutes": minutes if policy == "after_open" else None,
            "absolute_minutes": minutes if policy == "absolute" else None}
    response = world["owner"].post("/api/packages", json=body, headers=write_headers(world["owner"]))
    assert response.status_code == 200, response.text
    return int(response.headers["x-pastry-package-id"]), response.content


def _write(tmp_path, data, name="server-access.pastry"):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_open_releases_from_the_server_and_hides_secrets_until_revealed(world, tmp_path):
    _, data = _package(world)
    path = _write(tmp_path, data)
    with ServerThread(world["app"], port=world["port"]):
        child = _spawn(tmp_path, "open", str(path))
        try:
            child.expect("Package password")
            child.send(PKG_PW + "\r")
            child.expect("This package asks for its key from")
            child.send("y")
            child.expect("Ubuntu AI Server")
            child.send("\r")
            child.expect("Password")
            assert SECRET not in child.before
            child.send("r")
            child.expect(SECRET)
            child.send("q")
            child.expect(pexpect.EOF)
        finally:
            child.close(force=True)


def test_declining_the_server_sends_nothing_and_shows_nothing(world, tmp_path):
    _, data = _package(world)
    path = _write(tmp_path, data)
    with ServerThread(world["app"], port=world["port"]):
        child = _spawn(tmp_path, "open", str(path))
        try:
            child.expect("Package password")
            child.send(PKG_PW + "\r")
            child.expect("This package asks for its key from")
            child.send("n")
            child.expect(pexpect.EOF)
            assert SECRET not in child.before
        finally:
            child.close(force=True)
    assert world["app"].state.ctx.store.entry_count() == 1  # nothing consumed by the decline


def test_wrong_password_is_reported_without_showing_contents(world, tmp_path):
    _, data = _package(world)
    path = _write(tmp_path, data)
    with ServerThread(world["app"], port=world["port"]):
        child = _spawn(tmp_path, "open", str(path))
        try:
            child.expect("Package password")
            child.send("definitely not the password\r")
            child.expect("This package asks for its key from")
            child.send("y")
            child.expect("not accepted")
            assert SECRET not in child.before + (child.after if isinstance(child.after, str) else "")
            child.send("x")
            child.expect(pexpect.EOF)
        finally:
            child.close(force=True)


def test_revoked_package_is_refused_with_a_clear_message(world, tmp_path):
    package_id, data = _package(world)
    world["owner"].post(f"/api/packages/{package_id}/revoke", headers=write_headers(world["owner"]))
    path = _write(tmp_path, data)
    with ServerThread(world["app"], port=world["port"]):
        child = _spawn(tmp_path, "open", str(path))
        try:
            child.expect("Package password")
            child.send(PKG_PW + "\r")
            child.expect("This package asks for its key from")
            child.send("y")
            child.expect("revoked")
            child.send("x")  # the message waits for a key press
            child.expect(pexpect.EOF)
            assert SECRET not in child.before
        finally:
            child.close(force=True)


def test_unreachable_server_says_so_and_does_not_fall_back(world, tmp_path):
    _, data = _package(world)  # the server is never started on that port
    path = _write(tmp_path, data)
    child = _spawn(tmp_path, "open", str(path))
    try:
        child.expect("Package password")
        child.send(PKG_PW + "\r")
        child.expect("This package asks for its key from")
        child.send("y")
        child.expect("could not be reached")
        child.expect("cannot be opened offline")
        child.send("x")
        child.expect(pexpect.EOF)
        assert SECRET not in child.before
    finally:
        child.close(force=True)


def test_viewer_closes_when_the_server_clock_passes_the_window(world, tmp_path):
    """The window is measured by the server clock. Advancing that clock closes the open viewer."""
    _, data = _package(world, minutes=5)
    path = _write(tmp_path, data)
    with ServerThread(world["app"], port=world["port"]):
        child = _spawn(tmp_path, "open", str(path))
        try:
            child.expect("Package password")
            child.send(PKG_PW + "\r")
            child.expect("This package asks for its key from")
            child.send("y")
            child.expect("Ubuntu AI Server")
            world["clock"].advance(5 * 60 + 1)  # the server's clock, not the viewer's
            child.expect("expired", timeout=15)
            child.send("x")
            child.expect(pexpect.EOF)
            assert SECRET not in child.before
        finally:
            child.close(force=True)


def test_delete_on_expiry_removes_only_the_opened_file(world, tmp_path):
    _, data = _package(world, minutes=5)
    path = _write(tmp_path, data)
    bystander = _write(tmp_path, b"not mine", name="notes.txt")
    with ServerThread(world["app"], port=world["port"]):
        child = _spawn(tmp_path, "open", str(path), "--delete-on-expiry")
        try:
            child.expect("Package password")
            child.send(PKG_PW + "\r")
            child.expect("This package asks for its key from")
            child.send("y")
            child.expect("Ubuntu AI Server")
            world["clock"].advance(5 * 60 + 1)
            child.expect("expired", timeout=15)
            child.send("x")
            child.expect(pexpect.EOF)
        finally:
            child.close(force=True)
    assert not path.exists()
    assert bystander.exists()
