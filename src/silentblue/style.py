"""One accent color for the session prompt. Body text stays the terminal default."""

from __future__ import annotations

import os
import re
import sys

_BLUE = "\033[38;2;79;125;176m"
_RESET = "\033[0m"
_STAGE = re.compile(r"^(  )(d\d+)(  .+)$")
_FINDING = re.compile(r"^(\d+)(  .+)$")
_DISPLAY_ROW = re.compile(r"^([a-z]{1,3}-\d+)(  .+)$")
_DISPLAY_HEAD = re.compile(r"^(## )([a-z]{1,3}-\d+)$")
_FIELD = re.compile(
    r"^(\*\*)(Title|CVSS|Description|Why it matters|Impact|Evidence|Threat model|Remediation)(:\*\*)(.*)$"
)
_COMMAND = re.compile(r"^(/\S+)(\s+.*)$")
_STATE = re.compile(r"^(working|done|waiting)(  .*)$")
_LABELS = (
    "repo",
    "report",
    "findings",
    "html",
    "pdf",
    "markdown",
    "threat model",
    "case",
    "Draft written",
    "Accepted hash",
    "scan",
    "profile",
    "stage",
    "units",
    "source files",
    "model calls",
    "deployment files",
    "url",
    "account",
)
_enabled: bool | None = None


def color_enabled() -> bool:
    """Blue is used on a terminal. NO_COLOR and a pipe leave the text plain."""

    global _enabled
    if _enabled is not None:
        return _enabled
    if os.environ.get("NO_COLOR"):
        _enabled = False
        return False
    stream = sys.stdout
    if not hasattr(stream, "isatty") or not stream.isatty():
        _enabled = False
        return False
    _enable_windows_vt()
    _enabled = True
    return True


def paint(text: str) -> str:
    """Color the prompt, labels, stage ids, finding numbers, and slash commands."""

    if not text or not color_enabled():
        return text
    if text in {"silentblue>", "silentblue> ", "yes/no>", "yes/no> "}:
        return _blue(text)
    state = _STATE.match(text)
    if state is not None:
        return _blue(state.group(1)) + state.group(2)
    if text.startswith("silentblue "):
        return _blue("silentblue") + text[len("silentblue") :]
    if text == "Type /help":
        return "Type " + _blue("/help")
    if text == "Continue? yes/no":
        return "Continue? " + _blue("yes") + "/" + _blue("no")
    if text in {"detect", "assess"}:
        return _blue(text)
    stage = _STAGE.match(text)
    if stage is not None:
        return stage.group(1) + _blue(stage.group(2)) + stage.group(3)
    finding = _FINDING.match(text)
    if finding is not None:
        return _blue(finding.group(1)) + finding.group(2)
    shown = _DISPLAY_ROW.match(text)
    if shown is not None:
        return _blue(shown.group(1)) + shown.group(2)
    head = _DISPLAY_HEAD.match(text)
    if head is not None:
        return head.group(1) + _blue(head.group(2))
    field = _FIELD.match(text)
    if field is not None:
        return _blue(field.group(1) + field.group(2) + field.group(3)) + field.group(4)
    command = _COMMAND.match(text)
    if command is not None:
        return _blue(command.group(1)) + command.group(2)
    for label in _LABELS:
        prefix = f"{label}  "
        if text.startswith(prefix):
            return _blue(label) + text[len(label) :]
    return text


def _blue(text: str) -> str:
    return f"{_BLUE}{text}{_RESET}"


def _enable_windows_vt() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel = ctypes.windll.kernel32
        handle = kernel.GetStdHandle(-11)
        mode = ctypes.c_uint()
        if kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel.SetConsoleMode(handle, mode.value | 0x0004)
    except (AttributeError, OSError):
        return
