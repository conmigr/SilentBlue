"""Exit-coded errors for the harness."""

from __future__ import annotations


class SilentBlueError(Exception):
    """Base error that maps to a process exit code."""

    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class UsageError(SilentBlueError):
    """Bad input, empty scope, or an unsafe path. Exit 2."""

    def __init__(self, message: str) -> None:
        super().__init__(message, 2)


class RunError(SilentBlueError):
    """The scan could not finish its report. Exit 1."""

    def __init__(self, message: str) -> None:
        super().__init__(message, 1)
