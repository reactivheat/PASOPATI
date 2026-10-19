import http.client
import ipaddress
import shutil
import socket
import ssl
import subprocess
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pytest

import pasopati.transport as transport
from pasopati.config import Config, ScopeConfig
from pasopati.core.errors import PolicyError
from pasopati.profiles import get_profile
from pasopati.targets import Address, Target
from pasopati.transport import Deadline, Session, SocketConnector, SystemClock


class LocalResolver:
    def resolve(self, host: str, timeout: float) -> tuple[Address, ...]:
        assert host in {"lab.example.invalid", "other.example.invalid"}
        return (ipaddress.ip_address("127.0.0.1"),)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    records: list[dict[str, str]] = []

    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.records.append(dict(self.headers.items()))
        if self.path in {"/redirect", "/secret-hop", "/outside"}:
            port = cast(ThreadingHTTPServer, self.server).server_port
            destination = {
                "/redirect": "/ok",
                "/outside": f"http://outside.invalid:{port}/",
                "/secret-hop": f"http://other.example.invalid:{port}/ok",
            }
            self.send_response(302)
            self.send_header("Location", destination[self.path])
            self.send_header("Set-Cookie", "test-secret=must-not-forward")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        body = b"x" * 65537 if self.path in {"/huge", "/chunked"} else b"local-only"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Connection", "close")
        if self.path == "/chunked":
            self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            if self.path == "/chunked":
                self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
            else:
                self.wfile.write(body)
        except OSError:
            pass  # Expected when the bounded client closes an oversized response.

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "999999999")
        self.send_header("Connection", "close")
        self.end_headers()


@pytest.fixture
def lab(local_sockets: None) -> Iterator[ThreadingHTTPServer]:
    Handler.records = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        assert not worker.is_alive()


def local_config(port: int) -> Config:
    return Config(
        profile="safe",
        authorized=True,
        scope=ScopeConfig(
            allow_domains=("lab.example.invalid", "other.example.invalid"),
            allow_cidrs=("127.0.0.1/32",),
            ports=(port,),
            allow_private=True,
        ),
    )


@pytest.mark.parametrize("path", ["/ok", "/redirect", "/secret-hop"])
def test_real_http_and_redirects(
    lab: ThreadingHTTPServer, path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://external-proxy.invalid:1")
    client = Session(local_config(lab.server_port), resolver=LocalResolver())
    result = client.fetch(f"http://lab.example.invalid:{lab.server_port}{path}")
    assert result.body == b"local-only" and result.status == 200
    assert Handler.records[0]["Host"] == f"lab.example.invalid:{lab.server_port}"
    assert all(
        "Cookie" not in record
        and "Authorization" not in record
        and record["Accept-Encoding"] == "identity"
        for record in Handler.records
    )


@pytest.mark.parametrize(
    "path,reason",
    [
        ("/outside", "not_allowlisted"),
        ("/huge", "body_too_large"),
        ("/chunked", "body_too_large"),
    ],
)
def test_real_response_denial(lab: ThreadingHTTPServer, path: str, reason: str) -> None:
    client = Session(local_config(lab.server_port), resolver=LocalResolver())
    with pytest.raises(PolicyError, match=reason):
        client.fetch(f"http://lab.example.invalid:{lab.server_port}{path}")


def test_head_does_not_read_body(lab: ThreadingHTTPServer) -> None:
    result = Session(local_config(lab.server_port), resolver=LocalResolver()).fetch(
        f"http://lab.example.invalid:{lab.server_port}/", "HEAD"
    )
    assert result.body == b""


def test_fixture_cannot_connect_external(local_sockets: None) -> None:
    with socket.socket() as connection, pytest.raises(AssertionError, match="External"):
        connection.connect(("8.8.8.8", 443))


def test_tls_pinned_numeric_connection_and_default_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = Mock()
    context = Mock()
    # A synthetic successful TLS handshake is followed by an intentional response failure.
    context.wrap_socket.return_value = connection
    monkeypatch.setattr(socket, "socket", lambda *args: connection)
    context_factory = Mock(return_value=context)
    monkeypatch.setattr(transport, "tls_context", context_factory)
    monkeypatch.setattr(http.client, "HTTPResponse", Mock(side_effect=OSError("stop")))
    target = Target("lab.example.invalid", "https", 443)
    clock = SystemClock()
    with pytest.raises(OSError):
        SocketConnector().open(
            target,
            ipaddress.ip_address("127.0.0.1"),
            "GET",
            Deadline(clock.monotonic() + 10, clock),
            get_profile("safe"),
        )
    connection.connect.assert_called_once_with(("127.0.0.1", 443))
    context_factory.assert_called_once_with()
    context.wrap_socket.assert_called_once_with(connection, server_hostname="lab.example.invalid")
    request = connection.sendall.call_args.args[0]
    assert b"Host: lab.example.invalid\r\n" in request
    assert b"Cookie:" not in request and b"Authorization:" not in request
    assert connection.close.called


def test_real_verified_tls(
    lab: ThreadingHTTPServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL unavailable for generating ephemeral local TLS certificate")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    openssl_config = tmp_path / "openssl.cnf"
    openssl_config.write_text("[req]\ndistinguished_name = dn\n[dn]\n", encoding="utf-8")
    process = subprocess.run(
        [
            openssl,
            "req",
            "-config",
            str(openssl_config),
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
            "subjectAltName=DNS:lab.example.invalid",
        ],
        check=False,
        capture_output=True,
        timeout=30,
    )
    assert process.returncode == 0, process.stderr.decode(errors="replace")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    lab.socket = server_context.wrap_socket(lab.socket, server_side=True)
    trusted = ssl.create_default_context(cafile=str(cert))
    assert trusted.check_hostname and trusted.verify_mode == ssl.CERT_REQUIRED
    monkeypatch.setattr(transport, "tls_context", lambda: trusted)
    client = Session(local_config(lab.server_port), resolver=LocalResolver())
    assert client.fetch(f"https://lab.example.invalid:{lab.server_port}/").body == b"local-only"
    # The same trusted certificate must NOT authenticate another hostname.
    with pytest.raises(PolicyError, match="network_failed"):
        client.fetch(f"https://other.example.invalid:{lab.server_port}/")


def test_tls_context_does_not_persist_key_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = tmp_path / "tls-secrets.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(log))
    context = transport.tls_context()
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert context.keylog_filename is None and not log.exists()
