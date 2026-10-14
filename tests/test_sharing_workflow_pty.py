"""Steps 10 to 12 of the sharing workflow with the real terminal viewer and a live release server."""
import os
import sys
import time

import pytest

pexpect = pytest.importorskip("pexpect")
pytestmark = pytest.mark.skipif(os.name != "posix", reason="pseudo-terminals need POSIX")

from tests.conftest import write_headers  # noqa: E402
from tests.netserver import ServerThread, free_port  # noqa: E402
from tests.test_multiuser import ALICE_PW, _client, entry, join, login  # noqa: E402
from pastry.web import create_app  # noqa: E402

PKG_PW = "package password 2026"
SECRET = "SHARED-PTY-SECRET-8841"


def _spawn(cwd, *args):
    env = {**os.environ, "TERM": "xterm-256color", "PASTRY_VIEWER_POLL_SECONDS": "1", "PYTHONUNBUFFERED": "1"}
    return pexpect.spawn(sys.executable, ["-m", "pastry", *args], cwd=str(cwd), env=env,
                         encoding="utf-8", timeout=25, dimensions=(40, 120))


def test_edited_shared_entry_is_packaged_and_opened_in_the_terminal(provisioned, clock, tmp_path):
    clock.now = time.time()
    port = free_port()
    provisioned.public_url = f"http://127.0.0.1:{port}"
    app = create_app(provisioned, clock=clock, wall_clock=clock)
    owner = _client(app)
    assert login(owner).status_code == 303
    alice = join(app, owner, "alice", ALICE_PW)

    eid = entry(alice, "Ubuntu AI Server", password="first-password-1")
    assert alice.post(f"/api/entries/{eid}/shares", json={"username": "owner", "can_edit": True, "can_export": False},
                      headers=write_headers(alice)).status_code == 201
    edit = owner.put(f"/api/shared/{eid}", json={"name": "Ubuntu AI Server", "url": "", "category": "",
                                                 "favourite": False, "username": "admin", "password": SECRET,
                                                 "notes": "", "fields": []}, headers=write_headers(owner))
    assert edit.status_code == 200
    created = alice.post("/api/packages", json={"entry_ids": [eid], "name": "ai-server", "password": PKG_PW,
                                                "policy": "after_open", "duration_minutes": 5},
                         headers=write_headers(alice))
    assert created.status_code == 200
    path = tmp_path / "ai-server.pastry"
    path.write_bytes(created.content)

    with ServerThread(app, port=port):
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
            # Step 12: the server clock passes the window; the open viewer closes.
            clock.advance(5 * 60 + 1)
            child.expect("expired", timeout=15)
            child.send("x")
            child.expect(pexpect.EOF)
        finally:
            child.close(force=True)

    # After expiry no new release is possible.
    from pastry.release_client import HttpTransport, ReleaseRefused, open_server_package

    with ServerThread(app, port=port):
        with pytest.raises(ReleaseRefused) as info:
            open_server_package(path.read_bytes(), PKG_PW, HttpTransport(f"http://127.0.0.1:{port}"))
    assert info.value.code == "expired"
