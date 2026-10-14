"""Best-effort OS clipboard access for the viewer.

Values go to the clipboard tool on stdin, never on the command line. If no tool
is installed, copying is reported as unavailable instead of pretending to work.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import threading
from dataclasses import dataclass


@dataclass(frozen=True)
class Tool:
    name: str
    copy_cmd: tuple[str, ...]
    paste_cmd: tuple[str, ...]


TOOLS = (
    Tool("wl-copy", ("wl-copy",), ("wl-paste", "--no-newline")),
    Tool("xclip", ("xclip", "-selection", "clipboard", "-i"), ("xclip", "-selection", "clipboard", "-o")),
    Tool("xsel", ("xsel", "--clipboard", "--input"), ("xsel", "--clipboard", "--output")),
    Tool("pbcopy", ("pbcopy",), ("pbpaste",)),
)


def find_tool() -> Tool | None:
    for tool in TOOLS:
        if tool.copy_cmd[0] == "pbcopy" and platform.system() != "Darwin":
            continue
        if shutil.which(tool.copy_cmd[0]):
            return tool
    return None


def copy(value: str, tool: Tool | None = None) -> bool:
    tool = tool or find_tool()
    if tool is None:
        return False
    try:
        subprocess.run(list(tool.copy_cmd), input=value.encode("utf-8"), check=True, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (subprocess.SubprocessError, OSError):
        return False
    return True


def _paste(tool: Tool) -> str | None:
    try:
        result = subprocess.run(list(tool.paste_cmd), capture_output=True, timeout=5, check=True)
    except (subprocess.SubprocessError, OSError):
        return None
    return result.stdout.decode("utf-8", errors="replace")


def clear_if_unchanged(value: str, tool: Tool | None = None) -> bool:
    """Clear the clipboard only if it still holds `value`. Returns True if cleared."""
    tool = tool or find_tool()
    if tool is None or _paste(tool) != value:
        return False
    return copy("", tool)


class DelayedClear:
    """Schedule a conditional clear. Cancel it when the viewer closes if you prefer to wait."""

    def __init__(self, value: str, seconds: float, tool: Tool | None = None):
        self._timer = threading.Timer(seconds, clear_if_unchanged, args=(value, tool))
        self._timer.daemon = True

    def start(self) -> None:
        self._timer.start()

    def cancel(self) -> None:
        self._timer.cancel()
