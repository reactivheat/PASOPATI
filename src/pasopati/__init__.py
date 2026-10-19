"""PASOPATI's public package identity."""

from importlib.metadata import PackageNotFoundError, version

from pasopati.core.errors import InstallationError

DISTRIBUTION = "pasopati-recon"


def get_version() -> str:
    """Read installed metadata; never invent a version for an uninstalled checkout."""
    try:
        return version(DISTRIBUTION)
    except PackageNotFoundError as exc:
        raise InstallationError(DISTRIBUTION) from exc
