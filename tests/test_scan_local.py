import json
import threading
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from typer.testing import CliRunner

import pasopati.recon as recon
from pasopati.cli import app
from pasopati.lab import LabHandler

runner = CliRunner()


@pytest.fixture
def recon_lab(local_sockets: None) -> Iterator[tuple[ThreadingHTTPServer, list[str]]]:
    records: list[str] = []

    class RecordingHandler(LabHandler):
        def do_GET(self) -> None:
            records.append(self.path)
            super().do_GET()

    server = ThreadingHTTPServer(("127.0.0.1", 0), RecordingHandler)
    worker = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    worker.start()
    try:
        yield server, records
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        assert not worker.is_alive()


def lab_config(path: Path, port: int) -> Path:
    path.write_text(
        'schema_version = 1\nprofile = "safe"\nauthorized = true\n'
        f'[scope]\nallow_cidrs = ["127.0.0.1/32"]\nports = [{port}]\nallow_private = true\n',
        encoding="utf-8",
    )
    return path


def test_scan_cli_real_lab_and_matching_reports(
    recon_lab: tuple[ThreadingHTTPServer, list[str]], tmp_path: Path
) -> None:
    server, records = recon_lab
    config = lab_config(tmp_path / "lab.toml", server.server_port)
    base = f"http://127.0.0.1:{server.server_port}"
    targets = tmp_path / "targets.txt"
    targets.write_text(f"{base}/\n{base}/redirect\n{base}/missing\n{base}/\n", encoding="utf-8")
    output = tmp_path / "new-report"
    result = runner.invoke(
        app,
        [
            "--lang",
            "id",
            "scan",
            "--targets-file",
            str(targets),
            "--config",
            str(config),
            "--output",
            str(output),
            "--include-titles",
            "--json",
        ],
        env={"FORCE_COLOR": "1"},
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["ok"] and payload["summary"]["completed"] == 3
    assert payload["requests_used"] == 4 and records == ["/", "/redirect", "/", "/missing"]
    assert payload["assets"][0]["evidence"][0]["source"] == "ip_literal"
    assert payload["assets"][2]["evidence"][-1]["http_status"] == 404
    assert any(
        o["kind"] == "http.title" and o["value"] == "PASOPATI local lab"
        for o in payload["assets"][0]["observations"]
    )
    assert json.loads((output / "report.json").read_text(encoding="utf-8")) == payload
    text = (output / "report.txt").read_text(encoding="utf-8")
    assert "BUKAN berarti aman" in text
    assert "DO_NOT_PERSIST" not in result.stdout + text
    assert "\x1b" not in result.stdout + text


@pytest.mark.parametrize(
    "path,reason,requests",
    [
        ("/outside", "not_allowlisted", ["/outside"]),
        ("/large", "body_sampled", ["/large"]),
    ],
)
def test_scan_partial_real_lab(
    recon_lab: tuple[ThreadingHTTPServer, list[str]],
    tmp_path: Path,
    path: str,
    reason: str,
    requests: list[str],
) -> None:
    server, records = recon_lab
    config = lab_config(tmp_path / "lab.toml", server.server_port)
    result = runner.invoke(
        app,
        ["scan", f"http://127.0.0.1:{server.server_port}{path}", "--config", str(config), "--json"],
    )
    payload = json.loads(result.stdout)
    assert result.exit_code == 1 and not payload["ok"]
    assert payload["assets"][0]["status"] == "partial"
    assert payload["assets"][0]["reason"] == reason and records == requests


def test_output_conflict_fails_before_transport_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = lab_config(tmp_path / "lab.toml", 8765)
    output = tmp_path / "existing"
    output.mkdir()

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Transport must not be constructed before preflight succeeds")

    monkeypatch.setattr(recon, "Session", forbidden)
    result = runner.invoke(
        app,
        [
            "scan",
            "http://127.0.0.1:8765/",
            "--config",
            str(config),
            "--output",
            str(output),
            "--json",
        ],
    )
    assert result.exit_code == 1 and json.loads(result.stdout)["reason"] == "report_io"
    assert list(output.iterdir()) == []


def test_invalid_batch_fails_before_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = lab_config(tmp_path / "lab.toml", 8765)
    targets = tmp_path / "targets.txt"
    targets.write_text(
        "http://127.0.0.1:8765/\nhttp://user:SECRET@outside.invalid/\n", encoding="utf-8"
    )

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("No transport for an invalid batch")

    monkeypatch.setattr(recon, "Session", forbidden)
    result = runner.invoke(
        app, ["scan", "--targets-file", str(targets), "--config", str(config), "--json"]
    )
    assert result.exit_code == 2 and json.loads(result.stdout)["reason"] == "invalid_target"
    assert "SECRET" not in result.stdout


@pytest.mark.parametrize("language", ["en", "id"])
def test_scan_denied_json_without_authorization(tmp_path: Path, language: str) -> None:
    config = tmp_path / "passive.toml"
    result = runner.invoke(app, ["init", "--path", str(config)])
    assert result.exit_code == 0
    result = runner.invoke(
        app,
        ["--lang", language, "scan", "https://example.invalid/", "--config", str(config), "--json"],
        env={"FORCE_COLOR": "1"},
    )
    payload = json.loads(result.stdout)
    assert result.exit_code == 1 and payload["reason"] == "not_authorized"
    assert payload["language"] == language and not payload["ok"]
    assert "\x1b" not in result.stdout


def test_scan_missing_input_is_json_usage_error() -> None:
    result = runner.invoke(app, ["scan", "--json"])
    assert result.exit_code == 2 and json.loads(result.stdout)["reason"] == "invalid_targets"


@pytest.mark.parametrize("include_titles", [False, True])
def test_sensitive_title_real_lab(
    recon_lab: tuple[ThreadingHTTPServer, list[str]], tmp_path: Path, include_titles: bool
) -> None:
    server, _ = recon_lab
    config = lab_config(tmp_path / "lab.toml", server.server_port)
    args = [
        "scan",
        f"http://127.0.0.1:{server.server_port}/sensitive",
        "--config",
        str(config),
        "--json",
    ]
    if include_titles:
        args.append("--include-titles")
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    titles = [o["value"] for o in payload["assets"][0]["observations"] if o["kind"] == "http.title"]
    assert titles == (["[redacted]"] if include_titles else [])
    assert "LAB_SECRET_DO_NOT_PERSIST" not in result.stdout and "Set-Cookie" not in result.stdout
