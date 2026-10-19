import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

import pytest

import pasopati.doctor as doctor
from pasopati.doctor import default_config_dir
from pasopati.i18n import Language


def test_optional_binaries_absent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)

    def no_execution(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("Doctor must not execute tools")

    monkeypatch.setattr(subprocess, "run", no_execution)
    report = doctor.run_doctor(config_dir=tmp_path)
    assert report.ok
    checks = {check.name: check for check in report.checks}
    for name in ("git", "pipx", "nmap", "nuclei", "subfinder"):
        assert checks[name].status == "warn"
        assert not checks[name].required
        assert checks[name].recommendation


def test_optional_tools_present(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/example/bin/{name}")
    report = doctor.run_doctor(config_dir=tmp_path)
    assert report.ok
    for check in report.checks:
        if check.name in {"git", "pipx", "nmap", "nuclei", "subfinder"}:
            assert check.status == "pass"
            assert check.recommendation == ""


def test_missing_config_uses_ancestor_without_persistent_writes(tmp_path: Path) -> None:
    path = tmp_path / "missing" / "nested"
    before = list(tmp_path.iterdir())
    report = doctor.run_doctor(config_dir=path)
    assert report.ok
    assert not path.exists()
    assert list(tmp_path.iterdir()) == before
    checks = {check.name: check for check in report.checks}
    assert "does not exist" in checks["config_dir"].details
    assert checks["filesystem"].status == "pass"


@pytest.mark.parametrize("nested", [False, True])
def test_config_file_collision(tmp_path: Path, nested: bool) -> None:
    path = tmp_path / "config"
    path.write_text("untouched", encoding="utf-8")
    report = doctor.run_doctor(config_dir=path / "child" if nested else path)
    assert not report.ok
    assert path.read_text(encoding="utf-8") == "untouched"
    assert [check.status for check in report.checks[-2:]] == ["fail", "fail"]


def test_write_permission_denied(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def denied(*args: object, **kwargs: object) -> NoReturn:
        raise PermissionError("denied")

    monkeypatch.setattr(tempfile, "TemporaryFile", denied)
    report = doctor.run_doctor(Language.ID, tmp_path)
    assert not report.ok
    assert report.checks[-1].status == "fail"
    assert "Uji tulis sementara gagal" in report.checks[-1].details
    assert report.checks[-1].recommendation


def test_unsupported_python(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sys, "version_info", (3, 11, 0))
    report = doctor.run_doctor(config_dir=tmp_path)
    assert not report.ok
    assert report.checks[0].status == "fail"
    assert report.checks[0].recommendation


def test_other_platform_warning(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(platform, "system", lambda: "OtherOS")
    report = doctor.run_doctor(config_dir=tmp_path)
    assert report.ok
    assert report.checks[1].status == "warn"


@pytest.mark.parametrize("xdg", [None, "relative", "absolute"])
def test_unix_config_defaults(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, xdg: str | None
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    if xdg is None:
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    else:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg") if xdg == "absolute" else xdg)
    expected = tmp_path / "xdg" if xdg == "absolute" else tmp_path / ".config"
    assert default_config_dir() == expected / "pasopati"


@pytest.mark.parametrize("appdata", [True, False])
def test_windows_config_defaults(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, appdata: bool
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    if appdata:
        monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    else:
        monkeypatch.delenv("APPDATA", raising=False)
    expected = tmp_path / "roaming" if appdata else tmp_path / "AppData" / "Roaming"
    assert default_config_dir() == expected / "pasopati"
