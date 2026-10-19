"""Offline environment checks. Detect executables without executing them."""

import os
import platform
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from pasopati import get_version
from pasopati.core.errors import InstallationError
from pasopati.i18n import Language, tr

Status = Literal["pass", "warn", "fail"]


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    required: bool
    details: str
    recommendation: str = ""


@dataclass(frozen=True)
class DoctorReport:
    language: Language
    checks: tuple[Check, ...]

    @property
    def ok(self) -> bool:
        return all(check.status != "fail" for check in self.checks if check.required)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1",
            "language": self.language.value,
            "ok": self.ok,
            "checks": [asdict(check) for check in self.checks],
        }


def default_config_dir() -> Path:
    """Follow APPDATA on Windows and XDG_CONFIG_HOME on Unix, without creating paths."""
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME", "")
        base = Path(xdg) if xdg and Path(xdg).is_absolute() else Path.home() / ".config"
    return base / "pasopati"


def _filesystem_checks(path: Path, language: Language) -> tuple[Check, Check]:
    fix = tr(language, "config_fix")
    try:
        path = path.expanduser().absolute()
        parent = path
        while not parent.exists() and parent.parent != parent:
            parent = parent.parent
        if not parent.is_dir():
            return (
                Check("config_dir", "fail", True, tr(language, "config_invalid", path=parent), fix),
                Check("filesystem", "fail", True, tr(language, "write_blocked"), fix),
            )
        exists = path.is_dir()
        config = Check(
            "config_dir",
            "pass",
            True,
            tr(language, "config_exists", path=path)
            if exists
            else tr(language, "config_pending", path=path, parent=parent),
        )
    except (OSError, RuntimeError) as exc:
        return (
            Check(
                "config_dir", "fail", True, tr(language, "config_error", path=path, error=exc), fix
            ),
            Check("filesystem", "fail", True, tr(language, "write_blocked"), fix),
        )
    try:
        # Probe the existing directory/ancestor, never create persistent config files.
        with tempfile.TemporaryFile(prefix=".pasopati-doctor-", dir=parent) as probe:
            probe.write(b"pasopati doctor\n")
            probe.flush()
        write = Check("filesystem", "pass", True, tr(language, "write_ok", path=parent))
    except OSError as exc:
        write = Check(
            "filesystem", "fail", True, tr(language, "write_error", path=parent, error=exc), fix
        )
    return config, write


def run_doctor(language: Language = Language.EN, config_dir: Path | None = None) -> DoctorReport:
    """Inspect local state with no networking, installations, or integration execution."""
    python_ok = sys.version_info >= (3, 12)
    checks = [
        Check(
            "python",
            "pass" if python_ok else "fail",
            True,
            tr(language, "python_details", version=platform.python_version()),
            "" if python_ok else tr(language, "python_fix"),
        )
    ]
    system = platform.system()
    supported = system in {"Linux", "Windows"}
    checks.append(
        Check(
            "platform",
            "pass" if supported else "warn",
            False,
            tr(
                language,
                "platform_details",
                system=system,
                release=platform.release(),
                machine=platform.machine(),
            ),
            "" if supported else tr(language, "platform_fix"),
        )
    )
    try:
        checks.append(
            Check("package", "pass", True, tr(language, "package_details", version=get_version()))
        )
    except InstallationError:
        checks.append(
            Check(
                "package",
                "fail",
                True,
                tr(language, "package_missing"),
                tr(language, "package_fix"),
            )
        )
    for tool in ("git", "pipx", "nmap", "nuclei", "subfinder"):
        location = shutil.which(tool)
        recommendation = (
            tr(language, f"{tool}_fix")
            if tool in {"git", "pipx"}
            else tr(language, "integration_fix", tool=tool)
        )
        checks.append(
            Check(
                tool,
                "pass" if location else "warn",
                False,
                tr(language, "tool_found", path=location)
                if location
                else tr(language, "tool_missing"),
                "" if location else recommendation,
            )
        )
    try:
        path = config_dir if config_dir is not None else default_config_dir()
    except (OSError, RuntimeError) as exc:
        fix = tr(language, "config_fix")
        checks.extend(
            (
                Check(
                    "config_dir",
                    "fail",
                    True,
                    tr(language, "config_error", path="?", error=exc),
                    fix,
                ),
                Check("filesystem", "fail", True, tr(language, "write_blocked"), fix),
            )
        )
    else:
        checks.extend(_filesystem_checks(path, language))
    return DoctorReport(language, tuple(checks))
