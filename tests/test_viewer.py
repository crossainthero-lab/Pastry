"""Viewer state, clipboard handling and the package picker. No terminal is needed."""
import subprocess
from datetime import datetime, timedelta, timezone

from pastry import clipboard
from pastry import package as pk
from pastry import tui
from pastry.crypto import KdfParams
from pastry.viewer import REVEAL_SECONDS, Viewer

FAST = KdfParams(time_cost=1, memory_cost=8192, parallelism=1)
PW = "correct horse battery"
T0 = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
ENTRY = {"name": "Ubuntu AI Server", "url": "https://ai.example.internal", "username": "admin",
         "password": "pw-VALUE-1", "notes": "", "fields": [
             {"name": "API Key", "value": "key-VALUE-2", "secret": True},
             {"name": "Host", "value": "example.internal", "secret": False}]}


class Clock:
    def __init__(self):
        self.now = T0
        self.mono_t = 0.0

    def wall(self):
        return self.now

    def mono(self):
        return self.mono_t

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)
        self.mono_t += seconds


def viewer_for(allow_copy=True, expires_at=None, clip=None):
    data = pk.build_package([ENTRY], PW, "server-access", allow_copy=allow_copy,
                            expires_at=expires_at, kdf=FAST, now=T0)
    header, entries = pk.open_package(data, PW)
    clock = Clock()
    copied = []
    v = Viewer(header=header, entries=entries, clip=clip or (lambda value: copied.append(value) or True),
               now=clock.wall, mono=clock.mono, clear_after=0)
    return v, clock, copied


# ----- display and reveal -------------------------------------------------------


def test_secrets_are_masked_until_revealed(monkeypatch):
    v, clock, _ = viewer_for()
    secret = next(r for r in v.rows() if r.label == "API Key")
    assert v.display(secret) == "•" * 14
    assert "key-VALUE-2" not in v.display(secret)
    v.reveal()
    assert v.display(secret) == "key-VALUE-2"


def test_reveal_lapses_after_the_window():
    v, clock, _ = viewer_for()
    v.reveal()
    clock.advance(REVEAL_SECONDS - 1)
    assert v.is_revealed()
    clock.advance(2)
    assert not v.is_revealed()


def test_navigation_wraps_and_hides_reveals():
    v, clock, _ = viewer_for()
    v.reveal()
    v.next_row()
    assert not v.is_revealed()
    count = len(v.rows())
    for _ in range(count):
        v.next_row()
    assert v.row_index == 1  # wrapped around past the end, one step after the start


def test_non_secret_fields_are_shown_plainly():
    v, _, _ = viewer_for()
    host = next(r for r in v.rows() if r.label == "Host")
    assert v.display(host) == "example.internal"


# ----- copy -----------------------------------------------------------------------


def test_copy_is_refused_when_sender_disabled_it():
    v, _, copied = viewer_for(allow_copy=False)
    message = v.copy_current()
    assert "turned off" in message
    assert copied == []


def test_copy_sends_only_the_selected_value():
    v, _, copied = viewer_for()
    v.select_entry(0)
    v.row_index = 0
    v.copy_current()
    assert copied == ["admin"]
    assert "pw-VALUE-1" not in v.message and "admin" not in v.message


def test_copy_reports_missing_clipboard_tool():
    v, _, _ = viewer_for(clip=lambda value: False)
    assert "No clipboard tool" in v.copy_current()


def test_copy_message_never_echoes_the_value():
    v, _, _ = viewer_for()
    v.row_index = 1
    v.copy_current()
    assert "pw-VALUE-1" not in v.message


# ----- expiry -----------------------------------------------------------------------


def test_expiry_is_checked_against_the_clock():
    v, clock, _ = viewer_for(expires_at=T0 + timedelta(minutes=5))
    assert not v.expired()
    assert "Expires in" in v.expiry_text()
    clock.advance(5 * 60)
    assert v.expired()
    assert v.expiry_text() == "Expired"


def test_package_without_expiry_never_expires():
    v, clock, _ = viewer_for()
    clock.advance(10 * 365 * 24 * 3600)
    assert not v.expired()
    assert v.expiry_text() == "No expiry set"


# ----- clipboard adapter (subprocess mocked, nothing touches a real clipboard) -----


class FakeRun:
    def __init__(self, paste_value=None):
        self.calls = []
        self.paste_value = paste_value

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if "-o" in cmd or cmd[0] in ("wl-paste", "pbpaste") or cmd[-1] == "--output":
            return subprocess.CompletedProcess(cmd, 0, stdout=(self.paste_value or "").encode(), stderr=b"")
        return subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")


def test_copy_passes_value_on_stdin_not_arguments(monkeypatch):
    fake = FakeRun()
    monkeypatch.setattr(clipboard.subprocess, "run", fake)
    tool = clipboard.Tool("xclip", ("xclip", "-selection", "clipboard", "-i"), ("xclip", "-selection", "clipboard", "-o"))
    assert clipboard.copy("s3cret-value", tool) is True
    cmd, kwargs = fake.calls[0]
    assert "s3cret-value" not in cmd
    assert kwargs["input"] == b"s3cret-value"


def test_clear_only_when_clipboard_still_holds_our_value(monkeypatch):
    tool = clipboard.Tool("xclip", ("xclip", "-selection", "clipboard", "-i"), ("xclip", "-selection", "clipboard", "-o"))
    fake = FakeRun(paste_value="someone else's text")
    monkeypatch.setattr(clipboard.subprocess, "run", fake)
    assert clipboard.clear_if_unchanged("our value", tool) is False
    assert not any(call[1].get("input") == b"" for call in fake.calls)  # no write happened

    fake2 = FakeRun(paste_value="our value")
    monkeypatch.setattr(clipboard.subprocess, "run", fake2)
    assert clipboard.clear_if_unchanged("our value", tool) is True
    assert fake2.calls[-1][1]["input"] == b""  # cleared


def test_no_clipboard_tool_means_copy_is_unavailable(monkeypatch):
    monkeypatch.setattr(clipboard.shutil, "which", lambda name: None)
    assert clipboard.find_tool() is None
    assert clipboard.copy("value") is False


def test_clipboard_failure_is_reported_not_raised(monkeypatch):
    def boom(*a, **k):
        raise subprocess.CalledProcessError(1, "xclip")
    monkeypatch.setattr(clipboard.subprocess, "run", boom)
    tool = clipboard.Tool("xclip", ("xclip", "-i"), ("xclip", "-o"))
    assert clipboard.copy("x", tool) is False


# ----- picker: current directory only ------------------------------------------------


def test_picker_lists_only_top_level_pastry_files(tmp_path):
    pk_bytes = pk.build_package([ENTRY], PW, "p", allow_copy=True, expires_at=None, kdf=FAST)
    (tmp_path / "server-access.pastry").write_bytes(pk_bytes)
    (tmp_path / "notes.txt").write_text("not a package")
    sub = tmp_path / "subdir"
    sub.mkdir()
    (sub / "hidden.pastry").write_bytes(pk_bytes)
    outside = tmp_path.parent / "outside-target.pastry"
    outside.write_bytes(pk_bytes)
    try:
        (tmp_path / "linked.pastry").symlink_to(outside)
        names = [p.name for p in tui.list_packages(tmp_path)]
    finally:
        outside.unlink()
    assert names == ["server-access.pastry"]  # no recursion, no symlinks


def test_picker_handles_empty_directory(tmp_path):
    assert tui.list_packages(tmp_path) == []


def test_picker_label_for_corrupt_file(tmp_path):
    bad = tmp_path / "broken.pastry"
    bad.write_bytes(b"garbage")
    assert tui._label(bad) == "(not a valid package)"


def test_picker_label_shows_package_name_only(tmp_path):
    data = pk.build_package([ENTRY], PW, "Visible label", allow_copy=True, expires_at=None, kdf=FAST)
    path = tmp_path / "x.pastry"
    path.write_bytes(data)
    assert tui._label(path) == "Visible label"
    assert b"pw-VALUE-1" not in data
