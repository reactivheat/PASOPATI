"""Explicit installation errors and process exit codes."""

from enum import IntEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    FAILURE = 1
    USAGE = 2


class InstallationError(RuntimeError):
    """The installed distribution metadata is unavailable."""


class PolicyError(Exception):
    """A stable, non-sensitive reason code, never raw target/configuration input."""

    def __init__(self, code: str, exit_code: int = 1) -> None:
        self.code = code
        self.exit_code = exit_code
        super().__init__(code)
