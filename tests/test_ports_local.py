import json
import socket
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import dns.message
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest
from typer.testing import CliRunner

import pasopati.port_inventory as inventory
from pasopati.cli import app
from pasopati.config import Config, ScopeConfig

runner = CliRunner()


@contextmanager
def tcp_lab(host: str = "127.0.0.1") -> Iterator[tuple[int, int, threading.Event]]:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    failures: list[Exception] = []
    stopping, observed = threading.Event(), threading.Event()
    with (
        socket.socket(family, socket.SOCK_STREAM) as listener,
        socket.socket(family, socket.SOCK_STREAM) as refused,
    ):
        listener.bind((host, 0))
        refused.bind((host, 0))  # Reserved but not listening; no port-allocation race.
        listener.listen(4)
        listener.settimeout(0.1)

        def accept() -> None:
            while not stopping.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                try:
                    with connection:
                        connection.settimeout(2)
                        assert connection.recv(1) == b"", "TCP inventory must send no payload"
                    observed.set()
                except Exception as exc:
                    failures.append(exc)

        worker = threading.Thread(target=accept, daemon=True)
        worker.start()
        try:
            yield listener.getsockname()[1], refused.getsockname()[1], observed
        finally:
            stopping.set()
            worker.join(timeout=3)
            assert not worker.is_alive() and not failures


@pytest.mark.parametrize("language", ["en", "id"])
def test_real_tcp_cli_reports_open_and_refused_without_payloads(
    local_sockets: None, tmp_path: Path, language: str
) -> None:
    with tcp_lab() as (opened, refused, observed):
        config = tmp_path / "lab.toml"
        config.write_text(
            'schema_version=1\nprofile="safe"\nauthorized=true\n[scope]\n'
            'allow_cidrs=["127.0.0.1/32"]\nallow_private=true\n'
            f"ports=[{opened},{refused}]\n",
            encoding="utf-8",
        )
        output = tmp_path / "reports"
        result = runner.invoke(
            app,
            [
                "--lang",
                language,
                "ports",
                "127.0.0.1",
                "--ports",
                f"{opened},{refused}",
                "--config",
                str(config),
                "--output",
                str(output),
                "--json",
            ],
            env={"FORCE_COLOR": "1"},
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["schema_version"] == "3" and payload["language"] == language
        assert payload["requests_used"] == 2 and payload["tcp"]["dns_queries_used"] == 0
        assert [
            [o["value"] for o in a["observations"] if o["kind"] == "tcp.state"]
            for a in payload["assets"]
        ] == [["open"], ["refused"]]
        assert json.loads((output / "report.json").read_text(encoding="utf-8")) == payload
        assert "tcp.state" in (output / "report.txt").read_text(encoding="utf-8")
        assert "\x1b" not in result.stdout and str(tmp_path) not in result.stdout
        assert observed.wait(2)


def test_real_tcp_uses_local_dns_snapshot_without_hostname_connect(
    local_sockets: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    with (
        tcp_lab() as (opened, refused, observed),
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server,
    ):
        server.bind(("127.0.0.1", 0))
        server.settimeout(4)
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers, resolver.port = ["127.0.0.1"], server.getsockname()[1]
        monkeypatch.setattr(dns.resolver, "Resolver", lambda: resolver)
        records: list[tuple[str, int]] = []
        failures: list[Exception] = []

        def answer() -> None:
            try:
                for _ in range(2):
                    wire, endpoint = server.recvfrom(65535)
                    query = dns.message.from_wire(wire)
                    question = query.question[0]
                    records.append((question.name.to_text(), question.rdtype))
                    response = dns.message.make_response(query)
                    if question.rdtype == dns.rdatatype.A:
                        response.answer.append(
                            dns.rrset.from_text("example.invalid.", 0, "IN", "A", "127.0.0.1")
                        )
                    server.sendto(response.to_wire(), endpoint)
            except Exception as exc:
                failures.append(exc)

        worker = threading.Thread(target=answer, daemon=True)
        worker.start()
        try:
            config = Config(
                profile="safe",
                authorized=True,
                scope=ScopeConfig(
                    allow_domains=("example.invalid",),
                    allow_cidrs=("127.0.0.1/32",),
                    ports=(opened, refused),
                    allow_private=True,
                ),
            )
            report = inventory.run_port_inventory(config, ("example.invalid",), (opened, refused))
            assert report.ok and report.requests_used == 4
            assert report.tcp is not None and report.tcp.dns_queries_used == 2
            assert records == [
                ("example.invalid.", dns.rdatatype.A),
                ("example.invalid.", dns.rdatatype.AAAA),
            ]
            assert observed.wait(2)
        finally:
            worker.join(timeout=5)
            assert not worker.is_alive() and not failures


def test_real_ipv6_tcp_loopback(local_sockets: None) -> None:
    # Skip only when the actual local IPv6 stack cannot bind, not on collector failures.
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", 0))
    except OSError as exc:
        pytest.skip(f"IPv6 loopback unavailable: errno={exc.errno}")
    with tcp_lab("::1") as (opened, _, observed):
        config = Config(
            profile="safe",
            authorized=True,
            scope=ScopeConfig(allow_cidrs=("::1/128",), ports=(opened,), allow_private=True),
        )
        report = inventory.run_port_inventory(config, ("::1",), (opened,))
        assert report.ok and report.assets[0].target == f"[::1]:{opened}"
        assert report.assets[0].evidence[-1].connected_address == "::1"
        assert observed.wait(2)


@pytest.mark.parametrize(
    "extra,reason,code",
    [
        ([], "invalid_ports", 2),
        (["--ports", "1-65535"], "invalid_ports", 2),
        (["--ports", "80"], "not_authorized", 1),
    ],
)
def test_ports_preflight_json(tmp_path: Path, extra: list[str], reason: str, code: int) -> None:
    config = tmp_path / "passive.toml"
    config.write_text(
        'schema_version=1\nprofile="passive"\nauthorized=false\n[scope]\n', encoding="utf-8"
    )
    result = runner.invoke(
        app, ["ports", "example.invalid", "--config", str(config), "--json", *extra]
    )
    assert result.exit_code == code and json.loads(result.stdout)["reason"] == reason


def test_ports_existing_output_and_invalid_batch_precede_clients(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("No network client on preflight failure")

    monkeypatch.setattr(inventory, "NumericTCPConnector", forbidden)
    monkeypatch.setattr(inventory, "ScopedDNS", forbidden)
    config = tmp_path / "safe.toml"
    config.write_text(
        'schema_version=1\nprofile="safe"\nauthorized=true\n[scope]\nallow_domains=["example.invalid"]\n',
        encoding="utf-8",
    )
    output = tmp_path / "existing"
    output.mkdir()
    args = ["ports", "example.invalid", "--ports", "80", "--config", str(config), "--json"]
    result = runner.invoke(app, [*args, "--output", str(output)])
    assert result.exit_code == 1 and json.loads(result.stdout)["reason"] == "report_io"
    path = tmp_path / "hosts.txt"
    path.write_text("example.invalid\nhttps://SECRET.invalid\n", encoding="utf-8")
    result = runner.invoke(app, [*args, "--targets-file", str(path)])
    assert result.exit_code == 2 and json.loads(result.stdout)["reason"] == "invalid_hosts"
    assert "SECRET" not in result.stdout


def test_root_keeps_tcp_runtime_lazy(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import pasopati.cli; assert 'pasopati.tcp' not in sys.modules; "
            "assert 'pasopati.port_inventory' not in sys.modules",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
