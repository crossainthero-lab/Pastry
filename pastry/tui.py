"""Terminal UI for `.pastry` entry files. Run `pastry` (no arguments) in a terminal.

Pick a .pastry file, enter its password, view the entry, and optionally export it
again as a new .pastry file under a new password. It needs only the Pastry package
and works without the server or the vault.
"""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

from . import entryfile
from .entryfile import EntryFileError

MASK = "********"
LABEL_WIDTH = 14
HELP_BROWSE = "Enter open · Up/Down move · Backspace parent folder · p type a path · q quit"
HELP_ENTRY = "r show/hide secrets · e export as .pastry · Up/Down scroll · b back · q quit"


# ----- pure helpers (unit-tested without a terminal) -------------------------


def list_dir(path: Path) -> list[tuple[str, Path, bool]]:
    """Folder entries for the picker: parent, sub-folders, then .pastry files."""
    items: list[tuple[str, Path, bool]] = []
    if path.parent != path:
        items.append(("..", path.parent, True))
    try:
        children = sorted(path.iterdir(), key=lambda p: p.name.lower())
    except OSError:
        return items
    for child in children:
        try:
            if child.is_dir() and not child.name.startswith("."):
                items.append((child.name + "/", child, True))
        except OSError:
            continue
    for child in children:
        try:
            if child.is_file() and child.suffix.lower() == entryfile.EXTENSION:
                items.append((child.name, child, False))
        except OSError:
            continue
    return items


def _printable(text: str) -> str:
    """Replace control characters so entry text cannot drive the terminal."""
    return "".join(c if c.isprintable() else "?" for c in text)


def render_entry(entry: dict, reveal: bool, width: int) -> list[tuple[str, str]]:
    """Entry as (label, value) display rows, wrapped to `width`. Secrets are masked
    unless `reveal`."""
    value_width = max(10, width - LABEL_WIDTH - 2)
    rows: list[tuple[str, str]] = []

    def add(label: str, value: str, secret: bool = False) -> None:
        shown = value if (reveal or not secret) else (MASK if value else "")
        lines: list[str] = []
        for part in (shown.splitlines() or [""]):
            part = _printable(part)
            lines.extend(textwrap.wrap(part, value_width, replace_whitespace=False, drop_whitespace=False) or [""])
        for index, line in enumerate(lines):
            rows.append((label if index == 0 else "", line))

    add("Name", entry["name"])
    add("URL", entry["url"])
    add("Category", entry["category"])
    if entry["favourite"]:
        add("Favourite", "yes")
    add("Username", entry["username"])
    add("Password", entry["password"], secret=True)
    add("Notes", entry["notes"])
    for field in entry["fields"]:
        add(field["name"][: LABEL_WIDTH - 1], field["value"], secret=field["secret"])
    rows.append(("", ""))
    add("Created", entry["created_at"])
    add("Updated", entry["updated_at"])
    if entry.get("exported_at"):
        add("Exported", entry["exported_at"])
    return rows


# ----- curses application ---------------------------------------------------


def run(start: str | None = None) -> int:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("error: pastry needs an interactive terminal.", file=sys.stderr)
        return 1
    try:
        import curses
    except ImportError:
        print("error: the terminal UI needs Python's curses module (Linux or macOS).", file=sys.stderr)
        return 1
    os.environ.setdefault("ESCDELAY", "25")
    begin = Path(start).expanduser() if start else None
    return curses.wrapper(lambda scr: _App(scr, curses).main(begin))


class _App:
    def __init__(self, scr, curses_module):
        self.scr = scr
        self.c = curses_module
        self.error_attr = self.c.A_BOLD
        self.ok_attr = self.c.A_BOLD
        self.c.curs_set(0)
        self.scr.keypad(True)
        if self.c.has_colors():
            self.c.start_color()
            self.c.use_default_colors()
            self.c.init_pair(1, self.c.COLOR_RED, -1)
            self.c.init_pair(2, self.c.COLOR_GREEN, -1)
            self.error_attr = self.c.color_pair(1) | self.c.A_BOLD
            self.ok_attr = self.c.color_pair(2) | self.c.A_BOLD

    # -- drawing / input primitives --

    def put(self, y: int, x: int, text: str, attr: int = 0) -> None:
        height, width = self.scr.getmaxyx()
        if y < 0 or y >= height or x >= width - 1:
            return
        try:
            self.scr.addstr(y, x, text[: width - x - 1], attr)
        except self.c.error:
            pass

    def frame(self, title: str, footer: str, footer_attr: int = 0) -> tuple[int, int]:
        self.scr.erase()
        height, width = self.scr.getmaxyx()
        self.put(0, 0, (" " + title).ljust(width - 1), self.c.A_REVERSE | self.c.A_BOLD)
        self.put(height - 1, 0, footer, footer_attr or self.c.A_DIM)
        return height, width

    def key(self) -> str:
        failures = 0
        while True:
            try:
                raw = self.scr.get_wch()
            except self.c.error:
                failures += 1
                if failures > 200:
                    raise EOFError("terminal input closed")
                continue
            if isinstance(raw, str):
                if raw in ("\n", "\r"):
                    return "enter"
                if raw == "\x1b":
                    return "esc"
                if raw in ("\x7f", "\b"):
                    return "backspace"
                return raw
            names = {
                self.c.KEY_ENTER: "enter", self.c.KEY_BACKSPACE: "backspace", self.c.KEY_UP: "up",
                self.c.KEY_DOWN: "down", self.c.KEY_LEFT: "left", self.c.KEY_RIGHT: "right",
                self.c.KEY_PPAGE: "pgup", self.c.KEY_NPAGE: "pgdn", self.c.KEY_HOME: "home",
                self.c.KEY_END: "end", self.c.KEY_RESIZE: "resize",
            }
            return names.get(raw, "")

    def read_line(self, prompt: str, *, secret: bool = False, initial: str = "",
                  message: str = "", ok: bool = False) -> str | None:
        buf = list(initial)
        while True:
            height, width = self.frame("Pastry", "Enter to confirm · Esc to cancel")
            self.put(3, 2, prompt, self.c.A_BOLD)
            shown = ("*" * len(buf)) if secret else "".join(buf)
            visible = shown[-(max(1, width - 8)):]
            self.put(5, 2, "> " + visible)
            if message:
                self.put(7, 2, message, self.ok_attr if ok else self.error_attr)
            self.scr.move(min(5, height - 1), min(4 + len(visible), width - 2))
            self.c.curs_set(1)
            self.scr.refresh()
            k = self.key()
            self.c.curs_set(0)
            if k == "enter":
                return "".join(buf)
            if k == "esc":
                return None
            if k == "backspace":
                if buf:
                    buf.pop()
            elif len(k) == 1 and k.isprintable():
                buf.append(k)

    def confirm(self, prompt: str) -> bool:
        while True:
            self.frame("Pastry", "y yes · n no")
            self.put(3, 2, prompt, self.c.A_BOLD)
            self.scr.refresh()
            k = self.key()
            if k in ("y", "Y"):
                return True
            if k in ("n", "N", "esc"):
                return False

    def status(self, text: str) -> None:
        self.frame("Pastry", "")
        self.put(3, 2, text, self.c.A_BOLD)
        self.scr.refresh()

    # -- screens --

    def main(self, start: Path | None) -> int:
        cwd = Path.cwd()
        message = ""
        if start is not None:
            if start.is_dir():
                cwd = start.resolve()
            else:
                result = self.open_path(start)
                if result == "quit":
                    return 0
                message = result if isinstance(result, str) else ""
                cwd = start.resolve().parent
        while True:
            picked, cwd, message = self.pick_file(cwd, message)
            if picked is None:
                return 0
            result = self.open_path(picked)
            if result == "quit":
                return 0
            message = result or ""

    def pick_file(self, cwd: Path, message: str) -> tuple[Path | None, Path, str]:
        sel = 0
        top = 0
        while True:
            items = list_dir(cwd)
            sel = max(0, min(sel, len(items) - 1))
            height, width = self.frame("Pastry · open a .pastry file", HELP_BROWSE)
            self.put(2, 2, str(cwd), self.c.A_BOLD)
            rows = max(1, height - 6)
            if sel < top:
                top = sel
            if sel >= top + rows:
                top = sel - rows + 1
            has_files = any(not is_dir for _, _, is_dir in items)
            for index in range(top, min(len(items), top + rows)):
                label, path, is_dir = items[index]
                text = label
                if not is_dir:
                    try:
                        text = f"{label}   ({path.stat().st_size} bytes)"
                    except OSError:
                        pass
                self.put(4 + index - top, 2, text, self.c.A_REVERSE if index == sel else 0)
            if not has_files:
                self.put(height - 3, 2, "No .pastry files in this folder.", self.c.A_DIM)
            if message:
                self.put(height - 2, 2, message, self.error_attr)
            self.scr.refresh()
            message = ""
            k = self.key()
            if k in ("q", "Q", "esc"):
                return None, cwd, ""
            if k in ("up", "k"):
                sel -= 1
            elif k in ("down", "j"):
                sel += 1
            elif k == "pgup":
                sel -= rows
            elif k == "pgdn":
                sel += rows
            elif k == "home":
                sel = 0
            elif k == "end":
                sel = len(items) - 1
            elif k in ("backspace", "left") and cwd.parent != cwd:
                cwd, sel, top = cwd.parent, 0, 0
            elif k in ("p", "/"):
                typed = self.read_line("Path to a .pastry file or a folder", initial=str(cwd) + os.sep)
                if typed:
                    target = Path(typed).expanduser()
                    if target.is_dir():
                        cwd, sel, top = target.resolve(), 0, 0
                    elif target.is_file():
                        return target, cwd, ""
                    else:
                        message = f"Not found: {target}"
            elif k in ("enter", "right") and items:
                _, path, is_dir = items[sel]
                if is_dir:
                    cwd, sel, top = path.resolve(), 0, 0
                else:
                    return path, cwd, ""

    def open_path(self, path: Path) -> str | None:
        """Open a file: ask for the password, then show the entry. Returns "quit",
        an error message for the picker, or None to go back."""
        try:
            document = entryfile.load_file(path)
        except EntryFileError as exc:
            return exc.message
        error = ""
        while True:
            password = self.read_line(f"Password for {path.name}", secret=True, message=error)
            if password is None:
                return None
            self.status("Decrypting...")
            try:
                entry = entryfile.open_entry(document, password)
                break
            except EntryFileError as exc:
                if exc.code != "bad_password":
                    return exc.message
                error = exc.message
        return self.view_entry(path, entry)

    def view_entry(self, path: Path, entry: dict) -> str | None:
        reveal = False
        scroll = 0
        message, ok = "", True
        while True:
            height, width = self.frame(f"{path.name}", HELP_ENTRY)
            rows = render_entry(entry, reveal, width - 4)
            visible = max(1, height - 4)
            scroll = max(0, min(scroll, max(0, len(rows) - visible)))
            for index, (label, value) in enumerate(rows[scroll: scroll + visible]):
                self.put(2 + index, 2, label, self.c.A_BOLD)
                self.put(2 + index, 2 + LABEL_WIDTH, value)
            if len(rows) > visible:
                info = f"lines {scroll + 1}-{min(len(rows), scroll + visible)} of {len(rows)}"
                self.put(height - 2, max(2, width - len(info) - 3), info, self.c.A_DIM)
            if message:
                self.put(height - 2, 2, message, self.ok_attr if ok else self.error_attr)
            self.scr.refresh()
            message = ""
            k = self.key()
            if k in ("q", "Q"):
                return "quit"
            if k in ("b", "B", "esc", "backspace", "left"):
                return None
            if k in ("r", "R"):
                reveal = not reveal
            elif k in ("up", "k"):
                scroll -= 1
            elif k in ("down", "j"):
                scroll += 1
            elif k == "pgup":
                scroll -= visible
            elif k == "pgdn":
                scroll += visible
            elif k == "home":
                scroll = 0
            elif k == "end":
                scroll = len(rows)
            elif k in ("e", "E"):
                message, ok = self.export_flow(path, entry)

    def export_flow(self, source: Path, entry: dict) -> tuple[str, bool]:
        error = ""
        while True:
            first = self.read_line(
                f"New password for the exported file (at least {entryfile.MIN_PASSWORD_LEN} characters)",
                secret=True, message=error)
            if first is None:
                return "Export cancelled", False
            if len(first) < entryfile.MIN_PASSWORD_LEN:
                error = f"Use at least {entryfile.MIN_PASSWORD_LEN} characters."
                continue
            second = self.read_line("Repeat the password", secret=True)
            if second is None:
                return "Export cancelled", False
            if second != first:
                error = "The passwords did not match. Try again."
                continue
            break
        default = str(source.resolve().parent / entryfile.suggested_filename(entry["name"]))
        target_text = self.read_line("Save as", initial=default)
        if not target_text:
            return "Export cancelled", False
        target = Path(target_text).expanduser()
        if target.suffix.lower() != entryfile.EXTENSION:
            target = target.with_name(target.name + entryfile.EXTENSION)
        overwrite = False
        if target.exists():
            if not self.confirm(f"{target} exists. Overwrite it?"):
                return "Export cancelled", False
            overwrite = True
        self.status("Encrypting...")
        try:
            document = entryfile.seal_entry(entry, first)
            entryfile.write_file(target, document, overwrite=overwrite)
        except EntryFileError as exc:
            return exc.message, False
        return f"Saved {target}", True
