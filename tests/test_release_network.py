"""The release protocol over real sockets: TLS verification, plain-HTTP refusal, races."""
import ssl
import threading

import pytest
from fastapi.testclient import TestClient

from pastry.release_client import HttpTransport, ReleaseRefused, TransportError, open_server_package
from pastry.web import create_app
from tests.conftest import BASE_URL, SAMPLE_ENTRY, login, write_headers
from tests.netserver import ServerThread, make_self_signed
from tests.test_release_api import PKG_PW, SECRET_PW

PUBLIC = "http://127.0.0.1:0"  # replaced once the port is known


@pytest.fixture
def net_app(provisioned, clock):
    return create_app(provisioned, clock=clock, wall_clock=clock)


@pytest.fixture
def package_file(net_app, provisioned, clock):
    """Create a package in-process; release happens later over the network."""
    provisioned.public_url = "http://127.0.0.1:0"  # any loopback URL, rewritten per test below
    owner = TestClient(net_app, base_url=BASE_URL)
    assert login(owner).status_code == 303
    entry = owner.post("/api/entries", json={**SAMPLE_ENTRY, "password": SECRET_PW, "fields": []},
                       headers=write_headers(owner)).json()["id"]
    body = {"entry_ids": [entry], "name": "server access", "password": PKG_PW, "allow_copy": False,
            "policy": "one_time"}
    created = owner.post("/api/packages", json=body, headers=write_headers(owner))
    assert created.status_code == 200
    return owner, created.content


def test_full_release_over_a_real_socket(net_app, package_file):
    owner, data = package_file
    with ServerThread(net_app) as server:
        release = open_server_package(data, PKG_PW, HttpTransport(server.base))
    assert release.entries[0]["password"] == SECRET_PW


def test_plain_http_to_a_remote_host_is_refused_before_any_request():
    with pytest.raises(TransportError, match="secure"):
        HttpTransport("http://pastry.example.internal")


def test_https_package_is_not_silently_downgraded_to_http(net_app, package_file, tmp_path):
    """A plain-HTTP server cannot answer an https:// address: the client reports failure."""
    owner, data = package_file
    with ServerThread(net_app) as server:
        https_url = server.base.replace("http://", "https://")
        with pytest.raises(TransportError):
            open_server_package(data, PKG_PW, HttpTransport(https_url, timeout=3))


def test_self_signed_certificate_is_rejected_by_default(net_app, package_file, tmp_path):
    """TLS verification stays on: a certificate the system does not trust must fail."""
    owner, data = package_file
    cert, key, _ = make_self_signed(tmp_path)
    with ServerThread(net_app, certfile=cert, keyfile=key) as server:
        url = f"https://127.0.0.1:{server.port}"
        with pytest.raises(TransportError):
            open_server_package(data, PKG_PW, HttpTransport(url, timeout=5))


def test_self_signed_certificate_works_only_when_explicitly_trusted(net_app, package_file, tmp_path):
    owner, data = package_file
    cert, key, cert_pem = make_self_signed(tmp_path)
    trust = ssl.create_default_context(cadata=cert_pem.decode())
    with ServerThread(net_app, certfile=cert, keyfile=key) as server:
        release = open_server_package(data, PKG_PW, HttpTransport(f"https://127.0.0.1:{server.port}",
                                                                  timeout=5, context=trust))
    assert release.entries[0]["password"] == SECRET_PW


def test_unreachable_server_reports_clearly_and_never_falls_back(package_file):
    owner, data = package_file
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        closed_port = sock.getsockname()[1]  # nothing listens here
    with pytest.raises(TransportError) as info:
        open_server_package(data, PKG_PW, HttpTransport(f"http://127.0.0.1:{closed_port}", timeout=2))
    from pastry.release_client import message_for

    text = message_for(info.value)
    assert "could not be reached" in text and "cannot be opened offline" in text


def test_concurrent_network_redemptions_of_a_one_time_package_succeed_once(net_app, package_file):
    owner, data = package_file
    outcomes = []
    lock = threading.Lock()
    barrier = threading.Barrier(6)

    def attempt(server):
        barrier.wait()
        try:
            open_server_package(data, PKG_PW, HttpTransport(server.base))
            result = "released"
        except ReleaseRefused as exc:
            result = exc.code
        with lock:
            outcomes.append(result)

    with ServerThread(net_app) as server:
        threads = [threading.Thread(target=attempt, args=(server,)) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert outcomes.count("released") == 1
    assert all(code in ("consumed", "released") for code in outcomes)
