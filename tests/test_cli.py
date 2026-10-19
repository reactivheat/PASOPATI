import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from collections.abc import Iterator
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pytest
from typer.testing import CliRunner

import pasopati
from pasopati.branding import BANNER
from pasopati.cli import app

runner = CliRunner()


@pytest.fixture
def outside_checkout() -> Iterator[Path]:
    # POSIX TMPDIR may deliberately point into .local; this check must be outside.
    with tempfile.TemporaryDirectory(
        prefix="pasopati-entry-", dir="/tmp" if os.name == "posix" else None
    ) as directory:
        path = Path(directory)
        assert not path.resolve().is_relative_to(Path(__file__).resolve().parents[1])
        yield path


def test_root_and_banner_suppression() -> None:
    result = runner.invoke(app, [], env={"COLUMNS": "100"})
    assert result.exit_code == 0, result.output
    assert BANNER in result.output
    assert "Reconnaissance & Exposure Analysis Framework" in result.output
    assert "Quick start" in result.output
    assert version("pasopati-recon") in result.output
    suppressed = runner.invoke(app, ["--no-banner"])
    assert suppressed.exit_code == 0
    assert BANNER not in suppressed.output
    assert "Quick start" in suppressed.output


@pytest.mark.parametrize("args", [["--help"], ["doctor", "--help"]])
def test_help(args: list[str]) -> None:
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    assert "doctor" in result.output
    assert "--help" in result.output
    assert "--> PASOPATI" not in result.output


def test_version_matches_metadata() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"PASOPATI {version('pasopati-recon')}"


@pytest.mark.parametrize("args", [["--lang", "xx", "doctor"], ["scan"], ["--unknown"]])
def test_invalid_usage(args: list[str]) -> None:
    result = runner.invoke(app, args)
    assert result.exit_code == 2


@pytest.mark.parametrize(
    "language,title", [("en", "Environment doctor"), ("id", "Pemeriksaan lingkungan")]
)
def test_doctor_human(language: str, title: str) -> None:
    result = runner.invoke(app, ["--lang", language, "doctor"])
    assert result.exit_code == 0, result.output
    assert title in result.output
    assert "--> PASOPATI" in result.output
    suppressed = runner.invoke(app, ["--lang", language, "--no-banner", "doctor"])
    assert suppressed.exit_code == 0
    assert "--> PASOPATI" not in suppressed.output
    assert title in suppressed.output


@pytest.mark.parametrize("language", ["en", "id"])
def test_json_is_clean_even_when_colors_forced(language: str) -> None:
    result = runner.invoke(
        app,
        ["--lang", language, "doctor", "--json"],
        env={"FORCE_COLOR": "1", "CLICOLOR_FORCE": "1"},
    )
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.stdout
    assert "--> PASOPATI" not in result.stdout
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "1"
    assert payload["language"] == language
    assert payload["ok"] is True
    assert len(payload["checks"]) == 10


def test_required_failure_is_valid_json_and_exit_one(tmp_path: Path) -> None:
    invalid = tmp_path / "file"
    invalid.write_text("keep", encoding="utf-8")
    result = runner.invoke(app, ["doctor", "--json", "--config-dir", str(invalid)])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["ok"] is False
    assert invalid.read_text(encoding="utf-8") == "keep"


def test_missing_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(_: str) -> str:
        raise PackageNotFoundError("pasopati-recon")

    monkeypatch.setattr(pasopati, "version", missing)
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 1
    assert "metadata" in result.stderr
    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 1
    checks = {check["name"]: check for check in json.loads(result.stdout)["checks"]}
    assert checks["package"]["status"] == "fail"


@pytest.mark.parametrize("module", [False, True], ids=["executable", "module"])
def test_installed_entry_points_outside_checkout(outside_checkout: Path, module: bool) -> None:
    tmp_path = outside_checkout
    executable = shutil.which("pasopati", path=sysconfig.get_path("scripts"))
    assert executable is not None, "Install the package before running tests"
    command = [sys.executable, "-m", "pasopati"] if module else [executable]
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    for arguments in (
        ["--help"],
        ["--version"],
        ["doctor", "--json", "--config-dir", str(tmp_path / "config")],
        ["init", "--path", str(tmp_path / "policy.toml"), "--json"],
        ["config", "validate", "--config", str(tmp_path / "policy.toml"), "--json"],
        ["scope", "check", "example.invalid", "--config", str(tmp_path / "policy.toml"), "--json"],
        ["profiles", "list", "--json"],
        ["profiles", "show", "safe", "--json"],
    ):
        process = subprocess.run(
            command + arguments,
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
            check=False,
        )
        assert process.returncode == 0, process.stdout + process.stderr
        assert not process.stderr
        if "--json" in arguments:
            assert json.loads(process.stdout)["ok"] is True
            assert "\x1b" not in process.stdout
