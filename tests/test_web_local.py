import hashlib
import json
import shutil
import socket
import ssl
import subprocess
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from test_transport_local import LocalResolver, local_config
from typer.testing import CliRunner

import pasopati.transport as transport
from pasopati.cli import app
from pasopati.recon import run_recon
from pasopati.reports import render_json
from pasopati.transport import Session


class WebHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    received: list[str] = []

    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.received.append(self.path)
        if self.path == "/close":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        self.send_response(302 if self.path == "/redirect" else 200)
        if self.path == "/redirect":
            self.send_header("Location", "/final")
        body = b'<title>SECRET</title><a href="https://outside.invalid/SECRET">not followed</a>'
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx/SECRET")
        self.send_header("X-Powered-By", "PHP/SECRET")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'nonce-SECRET'")
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Set-Cookie", "SECRET=DO_NOT_PERSIST; HttpOnly")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def https_lab(
    local_sockets: None, tmp_path: Path
) -> Iterator[tuple[ThreadingHTTPServer, Path, str]]:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL unavailable for ephemeral local HTTPS fixture")
    cert, key, config = tmp_path / "cert.pem", tmp_path / "key.pem", tmp_path / "openssl.cnf"
    config.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="utf-8")
    result = subprocess.run(
        [
            openssl,
            "req",
            "-config",
            str(config),
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=lab.example.invalid",
            "-addext",
            "subjectAltName=DNS:lab.example.invalid,DNS:SECRET.other.invalid,IP:127.0.0.1",
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text(encoding="ascii"))).hexdigest()
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    WebHandler.received = []
    with ThreadingHTTPServer(("127.0.0.1", 0), WebHandler) as server:
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        worker.start()
        try:
            yield server, cert, digest
        finally:
            server.shutdown()
            worker.join(timeout=3)
            assert not worker.is_alive()


def test_real_verified_tls_and_web_headers_have_provenance(
    https_lab: tuple[ThreadingHTTPServer, Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    server, cert, digest = https_lab
    trusted = ssl.create_default_context(cafile=str(cert))
    monkeypatch.setattr(transport, "tls_context", lambda: trusted)
    config = local_config(server.server_port)
    report = run_recon(
        config,
        (f"https://lab.example.invalid:{server.server_port}/redirect",),
        inspect_web=True,
        session=Session(config, resolver=LocalResolver()),
    )
    assert report.ok and report.requests_used == 2 and report.web is not None
    assert report.web.endpoints_observed == 2
    assert WebHandler.received == ["/redirect", "/final"]
    evidence = {e.id: e for e in report.assets[0].evidence}
    for observation in report.assets[0].observations:
        if observation.kind == "tls.leaf_sha256":
            assert (
                observation.value == digest
                and evidence[observation.evidence_id].source == "tls_handshake"
            )
        if observation.kind == "tls.san_dns_count":
            assert observation.value == 2
        if observation.kind == "http.version":
            assert observation.value == "HTTP/1.1"
    values = {o.kind: o.value for o in report.assets[0].observations}
    assert values["tls.verified"] is True and values["hsts.received_over_https"] is True
    assert values["http.advertised_methods"] == ("GET", "HEAD")
    assert "SECRET" not in render_json(report) and "DO_NOT_PERSIST" not in render_json(report)


def test_real_tls_survives_http_close_without_fabricated_status(
    https_lab: tuple[ThreadingHTTPServer, Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    server, cert, digest = https_lab
    trusted = ssl.create_default_context(cafile=str(cert))
    monkeypatch.setattr(transport, "tls_context", lambda: trusted)
    config = local_config(server.server_port)
    report = run_recon(
        config,
        (f"https://lab.example.invalid:{server.server_port}/close",),
        inspect_web=True,
        session=Session(config, resolver=LocalResolver()),
    )
    assert not report.ok and report.assets[0].status == "partial"
    values = {o.kind: o.value for o in report.assets[0].observations}
    assert values["tls.leaf_sha256"] == digest and values["tls.verified"] is True
    assert (
        "http.status" not in values
        and report.web is not None
        and report.web.endpoints_observed == 0
    )


@pytest.mark.parametrize("failure", ["hostname", "untrusted"])
def test_real_failed_tls_is_not_verified_or_retried(
    https_lab: tuple[ThreadingHTTPServer, Path, str], monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    server, cert, _ = https_lab
    host = "other.example.invalid" if failure == "hostname" else "lab.example.invalid"
    if failure == "hostname":
        trusted = ssl.create_default_context(cafile=str(cert))
        monkeypatch.setattr(transport, "tls_context", lambda: trusted)
    config = local_config(server.server_port)
    report = run_recon(
        config,
        (f"https://{host}:{server.server_port}/",),
        inspect_web=True,
        session=Session(config, resolver=LocalResolver()),
    )
    assert not report.ok and report.assets[0].reason == "tls_verification_failed"
    assert report.requests_used == 1 and not WebHandler.received
    assert not any(e.source == "tls_handshake" for e in report.assets[0].evidence)
    assert not any(o.kind.startswith("tls.") for o in report.assets[0].observations)
    assert "SECRET" not in render_json(report)


@pytest.mark.parametrize("language", ["en", "id"])
def test_real_cli_tls_with_configured_trust_never_logs_keys(
    https_lab: tuple[ThreadingHTTPServer, Path, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    language: str,
) -> None:
    server, cert, digest = https_lab
    # Exercise the actual production context, not a monkeypatched insecure verification path.
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    keylog = tmp_path / "forbidden-keylog.txt"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    config = tmp_path / "safe.toml"
    config.write_text(
        'schema_version=1\nprofile="safe"\nauthorized=true\n[scope]\nallow_cidrs=["127.0.0.1/32"]\nallow_private=true\n'
        + f"ports=[{server.server_port}]\n",
        encoding="utf-8",
    )
    output = tmp_path / "reports"
    result = CliRunner().invoke(
        app,
        [
            "--lang",
            language,
            "scan",
            f"https://127.0.0.1:{server.server_port}/",
            "--web-details",
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
    assert payload["language"] == language and payload["schema_version"] == "4"
    assert payload["requests_used"] == 1 and payload["web"]["endpoints_observed"] == 1
    assert any(
        o["kind"] == "tls.leaf_sha256" and o["value"] == digest
        for o in payload["assets"][0]["observations"]
    )
    assert json.loads((output / "report.json").read_text(encoding="utf-8")) == payload
    assert "tls.verified" in (output / "report.txt").read_text(encoding="utf-8")
    assert not keylog.exists() and "\x1b" not in result.stdout and "SECRET" not in result.stdout
