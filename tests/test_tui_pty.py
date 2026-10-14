"""Drives the real `pastry` terminal viewer inside a pseudo-terminal (POSIX only)."""
import os
import sys
from pathlib import Path

import pytest

pexpect = pytest.importorskip("pexpect")
pytestmark = pytest.mark.skipif(os.name != "posix", reason="pseudo-terminals need POSIX")

from pastry import package as pk  # noqa: E402
from pastry.crypto import KdfParams  # noqa: E402

PW = "correct horse battery"
SECRET = "SECRET-PW-VALUE-4242"
ENTRY = {"name": "Ubuntu AI Server", "username": "admin", "password": SECRET,
         "fields": [{"name": "Host", "value": "example.internal", "secret": False}]}
FAST = KdfParams(time_cost=1, memory_cost=8192, parallelism=1)


def _spawn(cwd: Path, *args):
    env = {**os.environ, "TERM": "xterm-256color", "COLUMNS": "120", "LINES": "40", "PYTHONUNBUFFERED": "1"}
    return pexpect.spawn(sys.executable, ["-m", "pastry", *args], cwd=str(cwd), env=env,
                         encoding="utf-8", timeout=15, dimensions=(40, 120))


def _package(directory: Path, name="server-access.pastry", allow_copy=False):
    data = pk.build_package([ENTRY], PW, "Server access", allow_copy=allow_copy, expires_at=None, kdf=FAST)
    path = directory / name
    path.write_bytes(data)
    return path


def test_picker_lists_packages_and_opens_with_masked_password(tmp_path):
    _package(tmp_path)
    child = _spawn(tmp_path)
    try:
        child.expect("Available packages")
        child.expect("server-access.pastry")
        child.send("\r")
        child.expect("Package password")
        child.send(PW + "\r")
        child.expect("Ubuntu AI Server")
        child.send("\r")
        child.expect("Password")
        # The secret must not be on screen before the user reveals it.
        assert SECRET not in child.before
        child.send("r")
        child.expect(SECRET)
        child.send("q")
        child.expect(pexpect.EOF)
    finally:
        child.close(force=True)


def test_wrong_password_is_reported_and_secret_stays_hidden(tmp_path):
    _package(tmp_path)
    child = _spawn(tmp_path)
    try:
        child.expect("server-access.pastry")
        child.send("\r")
        child.expect("Package password")
        child.send("definitely-wrong-pass\r")
        child.expect("password is wrong")
        output = child.before + child.after
        assert SECRET not in output
        child.send("x")
        child.expect("server-access.pastry")
        child.send("q")
        child.expect(pexpect.EOF)
    finally:
        child.close(force=True)


def test_copy_is_disabled_when_sender_disabled_it(tmp_path):
    _package(tmp_path, allow_copy=False)
    child = _spawn(tmp_path)
    try:
        child.expect("server-access.pastry")
        child.send("\r")
        child.expect("Package password")
        child.send(PW + "\r")
        child.expect("Ubuntu AI Server")
        child.send("\r")
        child.expect("copy off")
        child.send("c")  # must not copy: the viewer refuses
        child.send("q")
        child.expect(pexpect.EOF)
    finally:
        child.close(force=True)


def test_empty_directory_shows_informative_state(tmp_path):
    child = _spawn(tmp_path)
    try:
        child.expect("No .pastry files were found")
        child.send("q")
        child.expect(pexpect.EOF)
    finally:
        child.close(force=True)


def test_open_subcommand_opens_a_named_file(tmp_path):
    path = _package(tmp_path, name="direct.pastry")
    child = _spawn(tmp_path, "open", str(path))
    try:
        child.expect("Package password")
        child.send(PW + "\r")
        child.expect("Ubuntu AI Server")
        child.send("q")
        child.expect(pexpect.EOF)
    finally:
        child.close(force=True)


def test_inspect_prints_metadata_without_secrets(tmp_path):
    path = _package(tmp_path)
    child = _spawn(tmp_path, "inspect", str(path))
    child.expect(pexpect.EOF)
    output = child.before
    assert "Server access" in output
    assert "Copy allowed     : no" in output
    assert "encrypted" in output
    assert SECRET not in output and "admin" not in output
