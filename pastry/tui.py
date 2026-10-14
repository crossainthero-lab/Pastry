"""Full-screen terminal viewer for `.pastry` packages (Python curses, standard library only)."""

from __future__ import annotations

import curses
import os
from pathlib import Path

from . import package
from .viewer import Viewer

KEY_ESC = 27
KEY_ENTER = (10, 13, curses.KEY_ENTER)
TICK_MS = 500


def list_packages(directory: str | os.PathLike) -> list[Path]:
    """Regular `.pastry` files directly inside `directory`. Never recursive, never follows symlinks."""
    found = []
    with os.scandir(directory) as entries:
        for entry in entries:
            if entry.name.endswith(".pastry") and entry.is_file(follow_symlinks=False):
                found.append(Path(entry.path))
    return sorted(found, key=lambda p: p.name.lower())


def _label(path: Path) -> str:
    try:
        header = package.inspect_package(package.read_package_file(path))
        return header.name
    except package.PackageError:
        return "(not a valid package)"


def _addstr(win, y: int, x: int, text: str, attr: int = 0) -> None:
    height, width = win.getmaxyx()
    if 0 <= y < height and x < width:
        try:
            win.addnstr(y, x, text, max(0, width - x - 1), attr)
        except curses.error:
            pass


def _chrome(win, crumb: str, footer: str) -> None:
    win.erase()
    _addstr(win, 0, 2, "PASTRY", curses.A_BOLD)
    _addstr(win, 1, 2, crumb, curses.A_DIM)
    height, _ = win.getmaxyx()
    _addstr(win, height - 1, 2, footer, curses.A_DIM)


def _password_prompt(stdscr, title: str) -> str | None:
    """Masked input. Returns None if cancelled with Esc. The value is never echoed."""
    chars: list[str] = []
    curses.noecho()
    curses.curs_set(1)
    try:
        while True:
            _chrome(stdscr, title, "Enter Unlock   Esc Cancel")
            _addstr(stdscr, 4, 2, "Package password: " + "*" * len(chars))
            stdscr.move(4, 2 + len("Package password: ") + len(chars))
            stdscr.refresh()
            key = stdscr.getch()
            if key == KEY_ESC:
                return None
            if key in KEY_ENTER:
                return "".join(chars)
            if key in (curses.KEY_BACKSPACE, 127, 8):
                if chars:
                    chars.pop()
            elif 32 <= key < 127:
                chars.append(chr(key))
    finally:
        curses.curs_set(0)


def _picker(stdscr, directory: str) -> Path | None:
    packages = list_packages(directory)
    index = 0
    while True:
        _chrome(stdscr, "Secure Credential Viewer", "Up/Down Navigate   Enter Open   Q Quit")
        _addstr(stdscr, 3, 2, f"Available packages in {directory}")
        if not packages:
            _addstr(stdscr, 5, 2, "No .pastry files were found in this directory.")
            _addstr(stdscr, 6, 2, "Put a package here, or run: pastry open FILE.pastry")
        for row, path in enumerate(packages):
            marker = ">" if row == index else " "
            attr = curses.A_REVERSE if row == index else 0
            _addstr(stdscr, 5 + row, 2, f"{marker} {path.name}   ({_label(path)})", attr)
        stdscr.refresh()
        key = stdscr.getch()
        if key in (ord("q"), ord("Q")):
            return None
        if key == curses.KEY_UP and packages:
            index = (index - 1) % len(packages)
        elif key == curses.KEY_DOWN and packages:
            index = (index + 1) % len(packages)
        elif key in KEY_ENTER and packages:
            return packages[index]


def _run_viewer(stdscr, viewer: Viewer, path: Path, delete_on_expiry: bool) -> str:
    """Returns 'back' or 'quit'."""
    title = f"{viewer.header.name}"
    entry_index = 0
    mode = "list"
    stdscr.timeout(TICK_MS)
    while True:
        if viewer.expired():
            if delete_on_expiry:
                _delete_exact(path)
            _chrome(stdscr, title, "Closed")
            _addstr(stdscr, 4, 2, "This package has expired. Secrets were closed.")
            stdscr.refresh()
            stdscr.timeout(-1)
            stdscr.getch()
            return "quit"
        footer_status = viewer.expiry_text()
        if mode == "list":
            _chrome(stdscr, f"{title}", "Up/Down Choose   Enter Open   Q Quit")
            for row, entry in enumerate(viewer.entries):
                marker = ">" if row == entry_index else " "
                attr = curses.A_REVERSE if row == entry_index else 0
                _addstr(stdscr, 3 + row, 2, f"{marker} {entry['name']}", attr)
            _addstr(stdscr, 4 + len(viewer.entries), 2, footer_status, curses.A_DIM)
        else:
            viewer.entry_index = entry_index
            entry = viewer.entries[entry_index]
            hint = ("R Reveal   C Copy   Tab Next   Esc Back   Q Quit" if viewer.copy_allowed()
                    else "R Reveal   Tab Next   Esc Back   Q Quit   (copy off)")
            _chrome(stdscr, f"{title} / {entry['name']}", hint)
            _addstr(stdscr, 3, 2, entry["name"], curses.A_BOLD)
            rows = viewer.rows(entry)
            for row_i, row in enumerate(rows):
                selected = row_i == viewer.row_index
                prefix = ">" if selected else " "
                value = viewer.display(row)
                attr = curses.A_REVERSE if selected else 0
                _addstr(stdscr, 5 + row_i, 2, f"{prefix} {row.label:<14}{value}", attr)
            _addstr(stdscr, 7 + len(rows), 2, viewer.message or footer_status, curses.A_DIM)
        stdscr.refresh()

        key = stdscr.getch()
        if key == -1:
            continue  # tick: loop re-checks expiry and reveal timers
        if mode == "list":
            if key in (ord("q"), ord("Q")):
                return "quit"
            if key == curses.KEY_UP:
                entry_index = (entry_index - 1) % len(viewer.entries)
            elif key == curses.KEY_DOWN:
                entry_index = (entry_index + 1) % len(viewer.entries)
            elif key in KEY_ENTER:
                viewer.select_entry(entry_index)
                viewer.message = ""
                mode = "entry"
        else:
            if key in (ord("q"), ord("Q")):
                return "quit"
            if key == KEY_ESC:
                viewer.hide()
                viewer.message = ""
                mode = "list"
            elif key in (ord("r"), ord("R")):
                viewer.reveal()
            elif key in (ord("c"), ord("C")):
                viewer.copy_current()
            elif key == 9:  # Tab
                viewer.next_row()
            elif key == curses.KEY_DOWN:
                viewer.next_row()
            elif key == curses.KEY_UP:
                viewer.prev_row()


def _delete_exact(path: Path) -> None:
    """Delete only the file the user explicitly opened."""
    try:
        os.remove(path)
    except OSError:
        pass


def run(directory: str | None, open_path: Path | None, delete_on_expiry: bool, clear_seconds: float) -> int:
    """Entry point used by `pastry` and `pastry open`."""
    def main(stdscr):
        curses.curs_set(0)
        path = open_path
        while True:
            if path is None:
                path = _picker(stdscr, directory or os.getcwd())
                if path is None:
                    return 0
            try:
                data = package.read_package_file(path)
            except (package.PackageError, OSError) as exc:
                _chrome(stdscr, "Error", "Press any key")
                _addstr(stdscr, 4, 2, str(exc))
                stdscr.getch()
                if open_path is not None:
                    return 1
                path = None
                continue
            password = _password_prompt(stdscr, f"Opening {path.name}")
            if password is None:
                if open_path is not None:
                    return 0
                path = None
                continue
            try:
                header, entries = package.open_package(data, password)
            except package.PackageError as exc:
                password = None
                _chrome(stdscr, f"Opening {path.name}", "Press any key")
                _addstr(stdscr, 4, 2, str(exc))
                stdscr.getch()
                if open_path is not None:
                    return 1
                path = None
                continue
            password = None
            viewer = Viewer(header=header, entries=entries, clear_after=clear_seconds)
            if viewer.expired():
                if delete_on_expiry:
                    _delete_exact(path)
                _chrome(stdscr, header.name, "Press any key")
                _addstr(stdscr, 4, 2, "This package has expired and cannot be opened.")
                stdscr.getch()
                return 1
            if not entries:
                return 1
            outcome = _run_viewer(stdscr, viewer, path, delete_on_expiry)
            if outcome == "quit" or open_path is not None:
                return 0
            path = None

    return curses.wrapper(main)
