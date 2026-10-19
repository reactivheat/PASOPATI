import ipaddress
import json
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import dns.message
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest
from test_discovery import candidates_file, configuration, new_budget
from typer.testing import CliRunner

import pasopati.discovery as discovery
from pasopati.cli import app
from pasopati.config import Config, ScopeConfig
from pasopati.core.errors import PolicyError
from pasopati.discovery_options import Source
from pasopati.discovery_sources import prepare_discovery
from pasopati.dns_client import DNSResolver

runner = CliRunner()


@pytest.fixture
def dns_lab(
    local_sockets: None, monkeypatch: pytest.MonkeyPatch
) -> Iterator[list[tuple[str, int]]]:
    records: list[tuple[str, int]] = []
    failures: list[Exception] = []
    stopping = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        server.settimeout(0.1)
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["127.0.0.1"]
        resolver.port = server.getsockname()[1]
        monkeypatch.setattr(dns.resolver, "Resolver", lambda: resolver)

        def answer() -> None:
            while not stopping.is_set():
                try:
                    wire, endpoint = server.recvfrom(65535)
                except TimeoutError:
                    continue
                try:
                    query = dns.message.from_wire(wire)
                    question = query.question[0]
                    name, kind = question.name.to_text(), question.rdtype
                    records.append((name, kind))
                    response = dns.message.make_response(query)
                    if name == "fail.example.invalid.":
                        response.set_rcode(dns.rcode.SERVFAIL)
                    elif name in {
                        "api.example.invalid.",
                        "empty.example.invalid.",
                        "alias.example.invalid.",
                    }:
                        if name != "empty.example.invalid." and kind == dns.rdatatype.A:
                            owner = name
                            if name == "alias.example.invalid.":
                                response.answer.append(
                                    dns.rrset.from_text(name, 60, "IN", "CNAME", "other.invalid.")
                                )
                                owner = "other.invalid."
                            response.answer.append(
                                dns.rrset.from_text(owner, 60, "IN", "A", "8.8.8.8")
                            )
                    else:
                        response.set_rcode(dns.rcode.NXDOMAIN)
                    server.sendto(response.to_wire(), endpoint)
                except Exception as exc:
                    failures.append(exc)

        worker = threading.Thread(target=answer, daemon=True)
        worker.start()
        try:
            yield records
        finally:
            stopping.set()
            worker.join(timeout=3)
            assert not worker.is_alive() and not failures


@pytest.mark.parametrize(
    "name,expected",
    [("api", "answer"), ("empty", "no_address"), ("missing", "nxdomain"), ("alias", "answer")],
)
def test_real_dns_answer_types(dns_lab: list[tuple[str, int]], name: str, expected: str) -> None:
    answer = DNSResolver().query(f"{name}.example.invalid", "A", 1)
    assert answer.status == expected and len(dns_lab) == 1
    if expected == "answer":
        assert answer.addresses == (ipaddress.ip_address("8.8.8.8"),) and answer.ttl == 60
    assert dns_lab[0][0] == f"{name}.example.invalid."


def test_real_servfail_is_not_nxdomain(dns_lab: list[tuple[str, int]]) -> None:
    with pytest.raises(PolicyError, match="dns_failed"):
        DNSResolver().query("fail.example.invalid", "A", 1)


def test_real_dns_query_lifetime(local_sockets: None, monkeypatch: pytest.MonkeyPatch) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
        silent.bind(("127.0.0.1", 0))
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["127.0.0.1"]
        resolver.port = silent.getsockname()[1]
        monkeypatch.setattr(dns.resolver, "Resolver", lambda: resolver)
        started = time.monotonic()
        with pytest.raises(PolicyError, match="timeout"):
            DNSResolver().query("api.example.invalid", "AAAA", 0.05)
        assert time.monotonic() - started < 1


def test_discovery_cli_real_dns_and_reports(dns_lab: list[tuple[str, int]], tmp_path: Path) -> None:
    config = tmp_path / "dns.toml"
    config.write_text(
        'schema_version=1\nprofile="safe"\nauthorized=true\n[scope]\n'
        'allow_domains=["example.invalid","*.example.invalid"]\n',
        encoding="utf-8",
    )
    output = tmp_path / "new-report"
    candidates = candidates_file(tmp_path)
    result = runner.invoke(
        app,
        [
            "--lang",
            "id",
            "discover",
            "subdomains",
            "example.invalid",
            "--source",
            "file",
            "--candidates-file",
            str(candidates),
            "--config",
            str(config),
            "--resolve",
            "--output",
            str(output),
            "--json",
        ],
        env={"FORCE_COLOR": "1"},
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "2" and payload["ok"]
    assert payload["discovery"]["dns_queries_used"] == payload["requests_used"] == len(dns_lab) == 5
    assert payload["assets"][0]["reason"] == "dns_resolved"
    assert {name for name, _ in dns_lab if not name.startswith("pasopati-")} == {
        "api.example.invalid."
    }
    assert json.loads((output / "report.json").read_text(encoding="utf-8")) == payload
    text = (output / "report.txt").read_text(encoding="utf-8")
    assert "BUKAN berarti aman" in text and "\x1b" not in result.stdout + text
    assert str(tmp_path) not in result.stdout


def test_provider_pipeline_uses_real_guarded_http_fixture(
    local_sockets: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    requests: list[str] = []

    class Provider(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            body = b'[{"id":123,"name_value":"api.example.invalid\\n*.example.invalid"}]'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "SECRET=DO_NOT_PERSIST")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Provider) as server:
        worker = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        worker.start()
        try:
            # Test-only replacement of fixed provider destination; no public CLI override exists.
            endpoint = f"http://127.0.0.1:{server.server_port}/"
            monkeypatch.setattr(discovery, "CRTSH_ENDPOINT", endpoint)
            private = Config(
                profile="safe",
                authorized=True,
                scope=ScopeConfig(
                    allow_cidrs=("127.0.0.1/32",), ports=(server.server_port,), allow_private=True
                ),
            )
            monkeypatch.setattr(discovery, "provider_config", lambda config: private)
            config = configuration(True)
            plan = prepare_discovery(
                "example.invalid", (Source.CRTSH,), allow_provider_queries=True
            )
            report = discovery.run_discovery(config, plan, budget=new_budget(config))
            assert report.ok and len(report.assets) == 2 and report.requests_used == 1
            assert requests == ["/?q=%25.example.invalid&output=json"]
            assert report.discovery is not None and report.discovery.dns_queries_used == 0
            assert "DO_NOT_PERSIST" not in json.dumps(report.to_dict())
        finally:
            server.shutdown()
            worker.join(timeout=3)
            assert not worker.is_alive()


@pytest.mark.parametrize("language", ["en", "id"])
def test_offline_discovery_cli(language: str, tmp_path: Path) -> None:
    config = tmp_path / "passive.toml"
    config.write_text(
        'schema_version=1\nprofile="passive"\nauthorized=false\n[scope]\n', encoding="utf-8"
    )
    path = candidates_file(tmp_path)
    result = runner.invoke(
        app,
        [
            "--lang",
            language,
            "discover",
            "subdomains",
            "example.invalid",
            "--source",
            "file",
            "--candidates-file",
            str(path),
            "--config",
            str(config),
            "--json",
        ],
        env={"FORCE_COLOR": "1"},
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["requests_used"] == 0 and payload["language"] == language
    assert not payload["discovery"]["resolve_requested"] and "\x1b" not in result.stdout


@pytest.mark.parametrize(
    "extra,reason,code",
    [
        ([], "invalid_discovery", 2),
        (["--source", "crtsh"], "provider_consent_required", 2),
        (["--source", "crtsh", "--allow-provider-queries"], "not_authorized", 1),
        (["--source", "file"], "invalid_discovery", 2),
    ],
)
def test_discovery_preflight_json(tmp_path: Path, extra: list[str], reason: str, code: int) -> None:
    config = tmp_path / "passive.toml"
    config.write_text(
        'schema_version=1\nprofile="passive"\nauthorized=false\n[scope]\n', encoding="utf-8"
    )
    result = runner.invoke(
        app,
        ["discover", "subdomains", "example.invalid", "--config", str(config), "--json", *extra],
    )
    assert result.exit_code == code and json.loads(result.stdout)["reason"] == reason


def test_existing_output_blocks_before_provider_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "safe.toml"
    config.write_text(
        'schema_version=1\nprofile="safe"\nauthorized=true\n[scope]\n'
        'allow_domains=["example.invalid"]\n',
        encoding="utf-8",
    )
    output = tmp_path / "existing"
    output.mkdir()

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("No client on preflight failure")

    monkeypatch.setattr(discovery, "Session", forbidden)
    result = runner.invoke(
        app,
        [
            "discover",
            "subdomains",
            "example.invalid",
            "--source",
            "crtsh",
            "--allow-provider-queries",
            "--config",
            str(config),
            "--output",
            str(output),
            "--json",
        ],
    )
    assert result.exit_code == 1 and json.loads(result.stdout)["reason"] == "report_io"


def test_cli_root_keeps_network_runtime_lazy(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import pasopati.cli; "
            "assert 'pasopati.transport' not in sys.modules; "
            "assert 'pasopati.dns_client' not in sys.modules",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
