import ipaddress
import socket
import threading
from unittest.mock import Mock

import dns.exception
import dns.resolver
import pytest

from pasopati.config import Config, ScopeConfig
from pasopati.core.errors import PolicyError
from pasopati.profiles import Profile
from pasopati.targets import Address, Target
from pasopati.transport import Deadline, DNSResolver, Exchange, Session


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.waits: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.waits.append(seconds)
        self.now += seconds


class FakeResolver:
    def __init__(self, addresses: tuple[str, ...] = ("8.8.8.8",)) -> None:
        self.addresses = tuple(ipaddress.ip_address(a) for a in addresses)
        self.calls: list[tuple[str, float]] = []

    def resolve(self, host: str, timeout: float) -> tuple[Address, ...]:
        self.calls.append((host, timeout))
        return self.addresses


class FakeExchange:
    def __init__(
        self, status: int = 200, body: bytes = b"ok", headers: dict[str, str] | None = None
    ) -> None:
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.closed = False

    def header(self, name: str) -> str | None:
        return self.headers.get(name)

    def read(self, size: int) -> bytes:
        chunk, self.body = self.body[:size], self.body[size:]
        return chunk

    def close(self) -> None:
        self.closed = True


class FakeConnector:
    def __init__(self, exchanges: list[FakeExchange] | None = None) -> None:
        self.exchanges = exchanges if exchanges is not None else [FakeExchange()]
        self.calls: list[tuple[Target, Address, str, float]] = []

    def open(
        self, target: Target, address: Address, method: str, deadline: Deadline, profile: Profile
    ) -> Exchange:
        self.calls.append((target, address, method, deadline.end))
        return self.exchanges.pop(0)


def config(**kwargs: object) -> Config:
    return Config(
        profile="safe",
        authorized=True,
        scope=ScopeConfig(
            allow_domains=("example.invalid", "other.invalid"), exclude_cidrs=("9.9.9.9/32",)
        ),
    )


def session(
    exchanges: list[FakeExchange] | None = None, addresses: tuple[str, ...] = ("8.8.8.8",)
) -> tuple[Session, FakeConnector, FakeClock]:
    connector = FakeConnector(exchanges)
    clock = FakeClock()
    return (
        Session(config(), resolver=FakeResolver(addresses), connector=connector, clock=clock),
        connector,
        clock,
    )


@pytest.mark.parametrize(
    "configuration,reason",
    [
        (Config(), "not_authorized"),
        (Config(authorized=True), "passive_profile"),
    ],
)
def test_authorization_before_dns(configuration: Config, reason: str) -> None:
    resolver, connector = FakeResolver(), FakeConnector()
    with pytest.raises(PolicyError, match=reason):
        Session(configuration, resolver=resolver, connector=connector).fetch(
            "https://example.invalid"
        )
    assert not resolver.calls and not connector.calls


@pytest.mark.parametrize(
    "addresses,reason",
    [
        (("8.8.8.8", "127.0.0.1"), "address_forbidden"),
        (("8.8.8.8", "9.9.9.9"), "excluded"),
        ((), "dns_failed"),
    ],
)
def test_all_dns_answers_checked_before_connect(addresses: tuple[str, ...], reason: str) -> None:
    client, connector, _ = session(addresses=addresses)
    with pytest.raises(PolicyError, match=reason):
        client.fetch("https://example.invalid")
    assert not connector.calls


def test_pins_ip_and_preserves_original_host() -> None:
    client, connector, _ = session()
    result = client.fetch("https://example.invalid/path")
    assert result.body == b"ok"
    assert connector.calls[0][0].host == "example.invalid"
    assert connector.calls[0][1] == ipaddress.ip_address("8.8.8.8")
    assert len(connector.calls) == 1


@pytest.mark.parametrize(
    "location,reason",
    [
        ("https://outside.invalid/", "not_allowlisted"),
        ("http://other.invalid/", "https_downgrade"),
        ("file:///etc/passwd", "invalid_target"),
        ("https://user:password@other.invalid", "invalid_target"),
        ("https://example.invalid/", "redirect_loop"),
    ],
)
def test_redirect_fail_closed(location: str, reason: str) -> None:
    redirect = FakeExchange(302, headers={"Location": location})
    client, connector, _ = session([redirect])
    with pytest.raises(PolicyError, match=reason):
        client.fetch("https://example.invalid/")
    assert len(connector.calls) == 1
    assert redirect.closed


def test_redirect_shares_rate_budget_deadline_and_closes() -> None:
    exchanges = [FakeExchange(302, headers={"Location": "/next"}), FakeExchange()]
    client, connector, clock = session(exchanges.copy())
    assert client.fetch("https://example.invalid").body == b"ok"
    assert client.requests_used == 2 and clock.waits == [1.0]
    assert {call[3] for call in connector.calls} == {10.0}
    assert connector.calls[-1][0].path == "/next"
    assert all(exchange.closed for exchange in exchanges)


def test_redirect_limit() -> None:
    exchanges = [FakeExchange(302, headers={"Location": f"/{i}"}) for i in range(4)]
    client, connector, _ = session(exchanges.copy())
    with pytest.raises(PolicyError, match="redirect_limit"):
        client.fetch("https://example.invalid")
    assert len(connector.calls) == 4 and client.requests_used == 4
    assert all(e.closed for e in exchanges)


def test_rebinding_between_hops_is_revalidated() -> None:
    resolver = FakeResolver()
    responses = iter([(ipaddress.ip_address("8.8.8.8"),), (ipaddress.ip_address("127.0.0.1"),)])
    resolver.resolve = lambda host, timeout: next(responses)  # type: ignore[method-assign]
    connector = FakeConnector([FakeExchange(302, headers={"Location": "/next"})])
    client = Session(config(), resolver=resolver, connector=connector, clock=FakeClock())
    with pytest.raises(PolicyError, match="address_forbidden"):
        client.fetch("https://example.invalid")
    assert len(connector.calls) == 1


@pytest.mark.parametrize("size,allowed", [(65536, True), (65537, False)])
def test_streamed_body_limit_and_cleanup(size: int, allowed: bool) -> None:
    response = FakeExchange(body=b"x" * size)
    client, _, _ = session([response])
    if allowed:
        assert len(client.fetch("https://example.invalid").body) == size
    else:
        with pytest.raises(PolicyError, match="body_too_large"):
            client.fetch("https://example.invalid")
    assert response.closed


def test_compression_rejected() -> None:
    response = FakeExchange(headers={"Content-Encoding": "gzip"})
    client, _, _ = session([response])
    with pytest.raises(PolicyError, match="encoding_denied"):
        client.fetch("https://example.invalid")
    assert response.closed


def test_budget_is_shared_across_fetches() -> None:
    client, connector, clock = session([FakeExchange() for _ in range(50)])
    for _ in range(50):
        client.fetch("https://example.invalid")
    with pytest.raises(PolicyError, match="budget_exhausted"):
        client.fetch("https://example.invalid")
    assert len(connector.calls) == 50 and client.requests_used == 50
    assert len(clock.waits) == 49


def test_deadline_includes_body_and_cleanup() -> None:
    response = FakeExchange()
    client, _, clock = session([response])

    def slow_read(size: int) -> bytes:
        clock.now = 11.0
        return b"x"

    response.read = slow_read  # type: ignore[method-assign]
    with pytest.raises(PolicyError, match="timeout"):
        client.fetch("https://example.invalid")
    assert response.closed


def test_concurrency_semaphore_is_shared_and_bounded() -> None:
    client, _, _ = session()
    gate = threading.Barrier(3)
    release = threading.Event()

    def occupy() -> None:
        with client.slot(Deadline(100.0, client.clock)):
            gate.wait(timeout=3)
            assert release.wait(timeout=3)

    workers = [threading.Thread(target=occupy) for _ in range(2)]
    for worker in workers:
        worker.start()
    try:
        gate.wait(timeout=3)
        with pytest.raises(PolicyError, match="timeout"), client.slot(Deadline(0.01, client.clock)):
            pass
    finally:
        release.set()
        for worker in workers:
            worker.join(timeout=3)
            assert not worker.is_alive()


def test_resolver_enforces_lifetime_without_system_getaddrinfo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = Mock()
    resolver.nameservers = ["127.0.0.1"]
    record = Mock()
    record.to_text.return_value = "8.8.8.8"
    resolver.resolve.side_effect = [[record], []]
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: resolver)
    assert DNSResolver().resolve("example.invalid", 3) == (ipaddress.ip_address("8.8.8.8"),)
    assert resolver.resolve.call_count == 2
    for call in resolver.resolve.call_args_list:
        assert 0 < call.kwargs["lifetime"] <= 3
        assert call.kwargs["search"] is False
        assert call.args[0] == "example.invalid."
    resolver.resolve.side_effect = dns.exception.Timeout  # exception class, no untyped constructor
    with pytest.raises(PolicyError, match="timeout"):
        DNSResolver().resolve("example.invalid", 0.01)


def test_method_denial_never_connects() -> None:
    client, connector, _ = session()
    with pytest.raises(PolicyError, match="method_denied"):
        client.fetch("https://example.invalid", "POST")
    assert not connector.calls


def test_total_deadline_stops_trickling_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = FakeClock()
    wire = iter(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    connection = Mock()

    def trickle(buffer: bytearray) -> int:
        clock.now += 1
        buffer[0] = next(wire)
        return 1

    connection.recv_into.side_effect = trickle
    monkeypatch.setattr(socket, "socket", lambda *args: connection)
    client = Session(config(), resolver=FakeResolver(), clock=clock)
    with pytest.raises(PolicyError, match="timeout"):
        client.fetch("http://example.invalid")
    assert clock.now == 10
    assert connection.close.called


def test_connector_timeout_is_translated() -> None:
    client, connector, _ = session()

    def failed(*args: object, **kwargs: object) -> Exchange:
        raise TimeoutError("must not leak")

    connector.open = failed  # type: ignore[method-assign]
    with pytest.raises(PolicyError, match="^timeout$"):
        client.fetch("https://example.invalid")
