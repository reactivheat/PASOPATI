import ipaddress
import socket
import threading
import time

import dns.message
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest

from pasopati.core.errors import PolicyError
from pasopati.transport import DNSResolver


def test_real_dns_a_aaaa_on_local_fixture(
    local_sockets: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        failures: list[Exception] = []

        def answer() -> None:
            try:
                for _ in range(2):
                    wire, endpoint = server.recvfrom(65535)
                    query = dns.message.from_wire(wire)
                    kind = query.question[0].rdtype
                    address = "8.8.8.8" if kind == dns.rdatatype.A else "2606:4700:4700::1111"
                    response = dns.message.make_response(query)
                    response.answer.append(
                        dns.rrset.from_text("example.invalid.", 1, "IN", kind, address)
                    )
                    server.sendto(response.to_wire(), endpoint)
            except Exception as exc:
                failures.append(exc)

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["127.0.0.1"]
        resolver.port = server.getsockname()[1]
        monkeypatch.setattr(dns.resolver, "Resolver", lambda: resolver)
        worker = threading.Thread(target=answer, daemon=True)
        worker.start()
        try:
            addresses = DNSResolver().resolve("example.invalid", 1)
            assert addresses == (
                ipaddress.ip_address("8.8.8.8"),
                ipaddress.ip_address("2606:4700:4700::1111"),
            )
        finally:
            worker.join(timeout=3)
        assert not worker.is_alive() and not failures


def test_real_dns_lifetime_bounds_unresponsive_local_server(
    local_sockets: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["127.0.0.1"]
        resolver.port = server.getsockname()[1]
        monkeypatch.setattr(dns.resolver, "Resolver", lambda: resolver)
        start = time.monotonic()
        with pytest.raises(PolicyError, match="timeout"):
            DNSResolver().resolve("example.invalid", 0.05)
        assert time.monotonic() - start < 1
