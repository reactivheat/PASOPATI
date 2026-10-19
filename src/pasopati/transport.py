"""Bounded internal HTTP transport. No scanner CLI, cookies, proxies, or persistence."""

import http.client
import io
import ipaddress
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol, cast
from urllib.parse import urljoin

import dns.exception
import dns.resolver

from pasopati.config import Config
from pasopati.core.errors import PolicyError
from pasopati.profiles import Profile, get_profile
from pasopati.scope import Scope
from pasopati.targets import Address, Target, parse_target


class Clock(Protocol):
    def monotonic(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


@dataclass(frozen=True)
class Deadline:
    end: float
    clock: Clock

    def remaining(self, limit: float | None = None) -> float:
        remaining = self.end - self.clock.monotonic()
        if remaining <= 0:
            raise PolicyError("timeout")
        return min(remaining, limit) if limit is not None else remaining


class Resolver(Protocol):
    def resolve(self, host: str, timeout: float) -> tuple[Address, ...]: ...


class DNSResolver:
    """OS-configured DNS servers, explicit absolute queries, bounded A+AAAA lifetime."""

    def resolve(self, host: str, timeout: float) -> tuple[Address, ...]:
        end = time.monotonic() + timeout
        try:
            resolver = dns.resolver.Resolver()
            # Do not allow a nameserver hostname/DoH URL to introduce an unbounded lookup.
            for server in resolver.nameservers:
                ipaddress.ip_address(str(server))
            addresses: set[Address] = set()
            for kind in ("A", "AAAA"):
                left = end - time.monotonic()
                if left <= 0:
                    raise PolicyError("timeout")
                answer = resolver.resolve(
                    host + ".", kind, lifetime=left, search=False, raise_on_no_answer=False
                )
                addresses.update(ipaddress.ip_address(record.to_text()) for record in answer)
            if not addresses:
                raise PolicyError("dns_failed")
            return tuple(sorted(addresses, key=lambda a: (a.version, int(a))))
        except dns.exception.Timeout as exc:
            raise PolicyError("timeout") from exc
        except (dns.exception.DNSException, OSError, ValueError) as exc:
            raise PolicyError("dns_failed") from exc


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
        if len(values) > 1:
            raise PolicyError("invalid_response")
        return values[0] if values else None

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
class FetchResult:
    status: int
    body: bytes
    content_type: str | None


class Session:
    """One shared budget, rate gate and concurrency bound for all callers/hops."""

    def __init__(
        self,
        config: Config,
        *,
        resolver: Resolver | None = None,
        connector: Connector | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.config = config
        self.profile = get_profile(config.profile)
        self.scope = Scope(config)
        self.resolver = resolver or DNSResolver()
        self.connector = connector or SocketConnector()
        self.clock = clock or SystemClock()
        self._slots = threading.BoundedSemaphore(self.profile.concurrency)
        self._lock = threading.Lock()
        self._used = 0
        self._next_request = 0.0

    @property
    def requests_used(self) -> int:
        with self._lock:
            return self._used

    @contextmanager
    def slot(self, deadline: Deadline) -> Iterator[None]:
        if not self._slots.acquire(timeout=deadline.remaining()):
            raise PolicyError("timeout")
        try:
            yield
        finally:
            self._slots.release()

    def _reserve(self, deadline: Deadline) -> None:
        # Lock acquisition itself is part of the operation deadline.
        if not self._lock.acquire(timeout=deadline.remaining()):
            raise PolicyError("timeout")
        try:
            if self._used >= self.profile.request_budget:
                raise PolicyError("budget_exhausted")
            delay = max(0.0, self._next_request - self.clock.monotonic())
            if delay >= deadline.remaining():
                raise PolicyError("timeout")
            if delay:
                self.clock.sleep(delay)
            deadline.remaining()
            self._used += 1
            self._next_request = self.clock.monotonic() + 1.0 / self.profile.requests_per_second
        finally:
            self._lock.release()

    def fetch(self, url: str, method: str = "GET") -> FetchResult:
        if not self.config.authorized:
            raise PolicyError("not_authorized")
        if not self.profile.network_enabled:
            raise PolicyError("passive_profile")
        if method not in self.profile.methods:
            raise PolicyError("method_denied")
        deadline = Deadline(self.clock.monotonic() + self.profile.total_timeout, self.clock)
        current = parse_target(url, require_url=True)
        seen: set[str] = set()
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
                try:
                    addresses = (ipaddress.ip_address(current.host),)
                except ValueError:
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
                exchange: Exchange | None = None
                try:
                    exchange = self.connector.open(
                        current, addresses[0], method, deadline, self.profile
                    )
                    deadline.remaining()
                    if exchange.status in {301, 302, 303, 307, 308}:
                        location = exchange.header("Location")
                        if not location:
                            raise PolicyError("invalid_response")
                        if hop == self.profile.max_redirects:
                            raise PolicyError("redirect_limit")
                        destination = parse_target(urljoin(current.url, location), require_url=True)
                        if current.scheme == "https" and destination.scheme != "https":
                            raise PolicyError("https_downgrade")
                        current = destination
                        continue
                    encoding = exchange.header("Content-Encoding")
                    if encoding and encoding.strip().lower() != "identity":
                        raise PolicyError("encoding_denied")
                    body = bytearray()
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
                                raise PolicyError("body_too_large")
                    return FetchResult(
                        exchange.status, bytes(body), exchange.header("Content-Type")
                    )
                except TimeoutError as exc:
                    raise PolicyError("timeout") from exc
                except (OSError, http.client.HTTPException) as exc:
                    raise PolicyError("network_failed") from exc
                finally:
                    if exchange is not None:
                        exchange.close()
        raise PolicyError("redirect_limit")
