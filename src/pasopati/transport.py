"""Bounded internal HTTP transport. No scanner CLI, cookies, proxies, or persistence."""

import http.client
import io
import ipaddress
import socket
import ssl
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol, cast
from urllib.parse import urljoin

from pasopati.config import Config
from pasopati.core.errors import PolicyError
from pasopati.dns_client import DNSResolver as DNSResolver
from pasopati.limits import Clock as Clock
from pasopati.limits import Deadline as Deadline
from pasopati.limits import RequestBudget
from pasopati.limits import SystemClock as SystemClock
from pasopati.profiles import Profile, get_profile
from pasopati.scope import Scope
from pasopati.targets import Address, Target, parse_target


class Resolver(Protocol):
    def resolve(self, host: str, timeout: float) -> tuple[Address, ...]: ...


class Exchange(Protocol):
    @property
    def status(self) -> int: ...
    def header(self, name: str) -> str | None: ...
    def read(self, size: int) -> bytes: ...
    def close(self) -> None: ...


class Connector(Protocol):
    def open(
        self, target: Target, address: Address, method: str, deadline: Deadline, profile: Profile
    ) -> Exchange: ...


class _DeadlineReader(io.RawIOBase):
    def __init__(self, connection: socket.socket, deadline: Deadline, read_timeout: float) -> None:
        super().__init__()
        self.connection = connection
        self.deadline = deadline
        self.read_timeout = read_timeout

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: object) -> int:
        self.connection.settimeout(self.deadline.remaining(self.read_timeout))
        count = self.connection.recv_into(cast(bytearray, buffer))
        self.deadline.remaining()
        return count


class _ResponseSocket:
    def __init__(self, connection: socket.socket, deadline: Deadline, read_timeout: float) -> None:
        self.connection = connection
        self.deadline = deadline
        self.read_timeout = read_timeout

    def makefile(self, mode: str) -> io.BufferedReader:
        return io.BufferedReader(_DeadlineReader(self.connection, self.deadline, self.read_timeout))


class HTTPExchange:
    def __init__(self, connection: socket.socket, response: http.client.HTTPResponse) -> None:
        self.connection = connection
        self.response = response

    @property
    def status(self) -> int:
        return self.response.status

    def header(self, name: str) -> str | None:
        values = self.response.headers.get_all(name, [])
        if len(values) > 1 and name.lower() in {"location", "content-type", "content-encoding"}:
            raise PolicyError("invalid_response")
        return ", ".join(values) if values else None

    def read(self, size: int) -> bytes:
        return self.response.read1(size)

    def close(self) -> None:
        try:
            self.response.close()
        finally:
            self.connection.close()


def tls_context() -> ssl.SSLContext:
    """System trust and hostname verification, without SSLKEYLOGFILE side effects."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    return context


class SocketConnector:
    """Numeric socket.connect only; TLS still verifies the original hostname."""

    def open(
        self, target: Target, address: Address, method: str, deadline: Deadline, profile: Profile
    ) -> Exchange:
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        connection = socket.socket(family, socket.SOCK_STREAM)
        response: http.client.HTTPResponse | None = None
        try:
            phase_end = deadline.clock.monotonic() + min(
                profile.connect_timeout, deadline.remaining()
            )
            connection.settimeout(deadline.remaining(profile.connect_timeout))
            if address.version == 6:
                connection.connect((str(address), target.port or 443, 0, 0))
            else:
                connection.connect((str(address), target.port or 80))
            if target.scheme == "https":
                context = tls_context()
                left = min(deadline.remaining(), phase_end - deadline.clock.monotonic())
                if left <= 0:
                    raise PolicyError("timeout")
                connection.settimeout(left)
                connection = context.wrap_socket(connection, server_hostname=target.host)
            connection.settimeout(deadline.remaining(profile.read_timeout))
            request = (
                f"{method} {target.path} HTTP/1.1\r\nHost: {target.authority}\r\n"
                "User-Agent: PASOPATI\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
            )
            connection.sendall(request.encode("ascii"))
            adapter = _ResponseSocket(connection, deadline, profile.read_timeout)
            response = http.client.HTTPResponse(cast(socket.socket, adapter), method=method)
            response.begin()
            deadline.remaining()
            return HTTPExchange(connection, response)
        except BaseException:
            try:
                if response is not None:
                    response.close()
            finally:
                connection.close()
            raise


@dataclass(frozen=True)
class Resolution:
    """All returned addresses passed policy; no connection is implied yet."""

    url: str
    addresses: tuple[str, ...]
    dns_performed: bool


@dataclass(frozen=True)
class Hop:
    """Transient response provenance; callers MUST sanitize before displaying/storing."""

    url: str
    resolved_addresses: tuple[str, ...]
    connected_address: str
    status: int
    location: str | None
    headers: tuple[tuple[str, str], ...]


OBSERVED_HEADERS = (
    "Content-Type",
    "Server",
    "X-Powered-By",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


@dataclass(frozen=True)
class FetchResult:
    status: int
    body: bytes
    content_type: str | None
    hops: tuple[Hop, ...] = ()
    body_truncated: bool = False


class Session:
    """One shared budget, rate gate and concurrency bound for all callers/hops."""

    def __init__(
        self,
        config: Config,
        *,
        resolver: Resolver | None = None,
        connector: Connector | None = None,
        clock: Clock | None = None,
        budget: RequestBudget | None = None,
    ) -> None:
        self.config = config
        self.profile = get_profile(config.profile)
        self.scope = Scope(config)
        self.resolver = resolver or DNSResolver()
        self.connector = connector or SocketConnector()
        self.clock = clock or (budget.clock if budget is not None else SystemClock())
        if budget is not None and (
            budget.profile != self.profile or budget.clock is not self.clock
        ):
            raise PolicyError("invalid_config", 2)
        self.budget = budget or RequestBudget(self.profile, self.clock)

    @property
    def requests_used(self) -> int:
        return self.budget.used

    @contextmanager
    def slot(self, deadline: Deadline) -> Iterator[None]:
        with self.budget.slot(deadline):
            yield

    def _reserve(self, deadline: Deadline) -> None:
        self.budget.reserve(deadline)

    def fetch(
        self,
        url: str,
        method: str = "GET",
        *,
        observe: Callable[[Resolution | Hop], None] | None = None,
        sample_body: bool = False,
    ) -> FetchResult:
        if not self.config.authorized:
            raise PolicyError("not_authorized")
        if not self.profile.network_enabled:
            raise PolicyError("passive_profile")
        if method not in self.profile.methods:
            raise PolicyError("method_denied")
        deadline = Deadline(self.clock.monotonic() + self.profile.total_timeout, self.clock)
        current = parse_target(url, require_url=True)
        seen: set[str] = set()
        hops: list[Hop] = []
        with self.slot(deadline):
            for hop in range(self.profile.max_redirects + 1):
                decision = self.scope.target(current)
                if not decision.allowed:
                    raise PolicyError(decision.reason)
                if current.url in seen:
                    raise PolicyError("redirect_loop")
                seen.add(current.url)
                self._reserve(deadline)
                addresses: tuple[Address, ...]
                dns_performed = False
                try:
                    addresses = (ipaddress.ip_address(current.host),)
                except ValueError:
                    dns_performed = True
                    try:
                        addresses = self.resolver.resolve(
                            current.host, deadline.remaining(self.profile.connect_timeout)
                        )
                    except TimeoutError as exc:
                        raise PolicyError("timeout") from exc
                    except OSError as exc:
                        raise PolicyError("dns_failed") from exc
                deadline.remaining()
                if not addresses:
                    raise PolicyError("dns_failed")
                for address in addresses:
                    decision = self.scope.address(address)
                    if not decision.allowed:
                        raise PolicyError(decision.reason)
                if observe is not None:
                    observe(
                        Resolution(current.url, tuple(str(a) for a in addresses), dns_performed)
                    )
                exchange: Exchange | None = None
                try:
                    exchange = self.connector.open(
                        current, addresses[0], method, deadline, self.profile
                    )
                    deadline.remaining()
                    status = exchange.status
                    redirect = status in {301, 302, 303, 307, 308}
                    location = exchange.header("Location") if redirect else None
                    headers = tuple(
                        (name.lower(), value)
                        for name in OBSERVED_HEADERS
                        if (value := exchange.header(name)) is not None
                    )
                    hop_result = Hop(
                        current.url,
                        tuple(str(a) for a in addresses),
                        str(addresses[0]),
                        status,
                        location,
                        headers,
                    )
                    hops.append(hop_result)
                    if observe is not None:
                        observe(hop_result)
                    if redirect:
                        if not location:
                            raise PolicyError("invalid_response")
                        if hop == self.profile.max_redirects:
                            raise PolicyError("redirect_limit")
                        try:
                            destination = parse_target(
                                urljoin(current.url, location), require_url=True
                            )
                        except ValueError as exc:
                            raise PolicyError("invalid_target", 2) from exc
                        if current.scheme == "https" and destination.scheme != "https":
                            raise PolicyError("https_downgrade")
                        current = destination
                        continue
                    encoding = exchange.header("Content-Encoding")
                    if encoding and encoding.strip().lower() != "identity":
                        raise PolicyError("encoding_denied")
                    body = bytearray()
                    truncated = False
                    if method != "HEAD":
                        while True:
                            deadline.remaining()
                            chunk = exchange.read(
                                min(8192, self.profile.max_body_bytes + 1 - len(body))
                            )
                            deadline.remaining()
                            if not chunk:
                                break
                            body.extend(chunk)
                            if len(body) > self.profile.max_body_bytes:
                                if not sample_body:
                                    raise PolicyError("body_too_large")
                                del body[self.profile.max_body_bytes :]
                                truncated = True
                                break
                    return FetchResult(
                        status, bytes(body), exchange.header("Content-Type"), tuple(hops), truncated
                    )
                except TimeoutError as exc:
                    raise PolicyError("timeout") from exc
                except (OSError, http.client.HTTPException) as exc:
                    raise PolicyError("network_failed") from exc
                finally:
                    if exchange is not None:
                        exchange.close()
        raise PolicyError("redirect_limit")
