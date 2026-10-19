"""Explicit installation errors and process exit codes."""

from enum import IntEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    FAILURE = 1
    USAGE = 2


class InstallationError(RuntimeError):
    """The installed distribution metadata is unavailable."""
