"""Single-entry `.pastry` files: format, web export button endpoint, terminal UI helpers."""
import json
import os
import select
import sys
import time

import pytest

from pastry import entryfile
from pastry.entryfile import EntryFileError
from pastry.tui import list_dir, render_entry
from tests.conftest import FAST_KDF, SAMPLE_ENTRY, write_headers
from tests.test_entries import create

FILE_PASSWORD = "file-password-123"
ENTRY = {**SAMPLE_ENTRY, "created_at": "2026-01-01T00:00:00+00:00", "updated_at": "2026-01-02T00:00:00+00:00"}


def test_round_trip_keeps_every_field():
    document = entryfile.seal_entry(ENTRY, FILE_PASSWORD, FAST_KDF)
    opened = entryfile.open_entry(document, FILE_PASSWORD)
    for key in ("name", "url", "category", "favourite", "username", "password", "notes", "fields"):
        assert opened[key] == ENTRY[key]
    assert opened["exported_at"]


def test_file_contains_no_plaintext():
    text = json.dumps(entryfile.seal_entry(ENTRY, FILE_PASSWORD, FAST_KDF))
    for secret in ("p4ss-VERY-unique-value", "My Server", "ssh-secret-value", "admin"):
        assert secret not in text


def test_wrong_password_and_tampering_are_rejected():
    document = entryfile.seal_entry(ENTRY, FILE_PASSWORD, FAST_KDF)
    with pytest.raises(EntryFileError) as exc:
        entryfile.open_entry(document, "not-the-password!")
    assert exc.value.code == "bad_password"
    tampered = {**document, "data": document["data"][:-6] + "AAAAAA"}
    with pytest.raises(EntryFileError):
        entryfile.open_entry(tampered, FILE_PASSWORD)


def test_short_password_refused():
    with pytest.raises(EntryFileError) as exc:
        entryfile.seal_entry(ENTRY, "short", FAST_KDF)
    assert exc.value.code == "weak_password"


def test_vault_export_and_garbage_are_told_apart():
    with pytest.raises(EntryFileError) as exc:
        entryfile.open_entry({"format": "pastry-export", "version": 1}, FILE_PASSWORD)
    assert exc.value.code == "whole_vault"
    with pytest.raises(EntryFileError) as exc:
        entryfile.open_entry({"nope": 1}, FILE_PASSWORD)
    assert exc.value.code == "invalid"


def test_absurd_kdf_cost_in_file_is_refused():
    document = entryfile.seal_entry(ENTRY, FILE_PASSWORD, FAST_KDF)
    document["kdf"]["memory_cost"] = 50_000_000
    with pytest.raises(EntryFileError) as exc:
        entryfile.open_entry(document, FILE_PASSWORD)
    assert exc.value.code == "invalid"


def test_write_file_is_private_and_refuses_overwrite(tmp_path):
    document = entryfile.seal_entry(ENTRY, FILE_PASSWORD, FAST_KDF)
    path = entryfile.write_file(tmp_path / "a.pastry", document)
    if os.name == "posix":
        assert (path.stat().st_mode & 0o777) == 0o600
    with pytest.raises(EntryFileError) as exc:
        entryfile.write_file(path, document)
    assert exc.value.code == "exists"
    entryfile.write_file(path, document, overwrite=True)
    assert entryfile.open_entry(entryfile.load_file(path), FILE_PASSWORD)["name"] == "My Server"


def test_suggested_filename_is_safe():
    assert entryfile.suggested_filename("../../etc/passwd") == "pastry-etc-passwd.pastry"
    assert entryfile.suggested_filename("???") == "pastry-entry.pastry"


# ----- web endpoint ---------------------------------------------------------


def test_web_export_downloads_a_openable_file(signed_in):
    entry_id = create(signed_in)
    response = signed_in.post(
        f"/api/entries/{entry_id}/export", json={"passphrase": FILE_PASSWORD}, headers=write_headers(signed_in)
    )
    assert response.status_code == 200
    assert 'filename="pastry-My-Server.pastry"' in response.headers["content-disposition"]
    opened = entryfile.open_entry(response.json(), FILE_PASSWORD)
    assert opened["password"] == "p4ss-VERY-unique-value"
    assert opened["fields"][0]["value"] == "ssh-secret-value"


def test_web_export_requires_a_long_enough_password(signed_in):
    entry_id = create(signed_in)
    response = signed_in.post(
        f"/api/entries/{entry_id}/export", json={"passphrase": "short"}, headers=write_headers(signed_in)
    )
    assert response.status_code == 422


def test_protected_entry_needs_unlock_before_export(signed_in):
    entry_id = create(signed_in, separate_password="separate-pass-123")
    url = f"/api/entries/{entry_id}/export"
    body = {"passphrase": FILE_PASSWORD}
    assert signed_in.post(url, json=body, headers=write_headers(signed_in)).status_code >= 400
    unlocked = signed_in.post(
        f"/api/entries/{entry_id}/unlock", json={"password": "separate-pass-123"}, headers=write_headers(signed_in)
    )
    assert unlocked.status_code == 200
    ok = signed_in.post(url, json=body, headers=write_headers(signed_in))
    assert ok.status_code == 200
    assert entryfile.open_entry(ok.json(), FILE_PASSWORD)["username"] == "admin"


def test_export_requires_sign_in(client):
    assert client.post("/api/entries/1/export", json={"passphrase": FILE_PASSWORD}).status_code in (401, 403)


# ----- terminal UI helpers --------------------------------------------------


def test_render_entry_masks_secrets_until_revealed():
    entry = entryfile.open_entry(entryfile.seal_entry(ENTRY, FILE_PASSWORD, FAST_KDF), FILE_PASSWORD)
    hidden = " ".join(value for _, value in render_entry(entry, False, 80))
    assert "p4ss-VERY-unique-value" not in hidden and "ssh-secret-value" not in hidden
    assert "admin" in hidden and "Rotate quarterly" in hidden
    shown = " ".join(value for _, value in render_entry(entry, True, 80))
    assert "p4ss-VERY-unique-value" in shown and "ssh-secret-value" in shown


def test_render_entry_strips_terminal_escape_codes():
    entry = {**ENTRY, "notes": "evil \x1b[2J\x1b]0;pwned\x07 text", "exported_at": ""}
    rows = render_entry(entryfile._normalize(entry) | {"exported_at": ""}, True, 80)
    assert not any("\x1b" in value or "\x07" in value for _, value in rows)


def test_list_dir_shows_folders_and_pastry_files_only(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / ".hidden").mkdir()
    (tmp_path / "a.pastry").write_text("{}")
    (tmp_path / "notes.txt").write_text("x")
    labels = [label for label, _, _ in list_dir(tmp_path)]
    assert labels == ["..", "sub/", "a.pastry"]


# ----- the real curses UI through a pseudo-terminal -------------------------


@pytest.mark.skipif(os.name != "posix", reason="needs a pseudo-terminal")
def test_terminal_ui_opens_and_re_exports(tmp_path):
    import fcntl
    import pty
    import struct
    import termios

    source = entryfile.write_file(tmp_path / "in.pastry", entryfile.seal_entry(ENTRY, FILE_PASSWORD, FAST_KDF))
    pid, fd = pty.fork()
    if pid == 0:  # child
        os.chdir(tmp_path)
        os.environ.update(TERM="xterm-256color", LINES="40", COLUMNS="120")
        os.execv(sys.executable, [sys.executable, "-m", "pastry", "open", str(source)])
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    seen = b""

    def read_until(text: bytes, timeout: float = 20.0) -> None:
        nonlocal seen
        end = time.time() + timeout
        while text not in seen:
            assert time.time() < end, f"timed out waiting for {text!r}; saw {seen[-400:]!r}"
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                try:
                    seen += os.read(fd, 65536)
                except OSError:
                    break

    def send(text: str) -> None:
        os.write(fd, text.encode())

    read_until(b"Password for in.pastry")
    send("wrong-password-123\r")
    read_until(b"Wrong password")
    send("\x1b")  # cancel -> picker
    read_until(b"open a .pastry file")
    send("\x1b")  # quit
    _, status = os.waitpid(pid, 0)
    assert os.WEXITSTATUS(status) == 0

    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(tmp_path)
        os.environ.update(TERM="xterm-256color", LINES="40", COLUMNS="120")
        os.execv(sys.executable, [sys.executable, "-m", "pastry", "open", str(source)])
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    seen = b""
    read_until(b"Password for in.pastry")
    send(FILE_PASSWORD + "\r")
    read_until(b"My Server")
    assert b"p4ss-VERY-unique-value" not in seen
    send("r")
    read_until(b"p4ss-VERY-unique-value")
    send("e")
    read_until(b"New password for the exported file")
    send("another-file-pass-1\r")
    read_until(b"Repeat the password")
    send("another-file-pass-1\r")
    read_until(b"Save as")
    target = tmp_path / "copy.pastry"
    for _ in range(len(str(tmp_path / "pastry-My-Server.pastry")) + 8):
        send("\x7f")
    send(str(target) + "\r")
    read_until(b"Saved")
    send("q")
    _, status = os.waitpid(pid, 0)
    assert os.WEXITSTATUS(status) == 0
    copy = entryfile.open_entry(entryfile.load_file(target), "another-file-pass-1")
    assert copy["password"] == "p4ss-VERY-unique-value"
    with pytest.raises(EntryFileError):
        entryfile.open_entry(entryfile.load_file(target), FILE_PASSWORD)
