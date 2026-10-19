"""Unprivileged numeric TCP connect only: no payload, reads, or service guesses."""

import errno
import ipaddress
import socket
from typing import Protocol

from pasopati.core.errors import PolicyError
from pasopati.limits import Deadline
from pasopati.targets import Address


class TCPConnector(Protocol):
    def connect(self, address: Address, port: int, deadline: Deadline, timeout: float) -> None: ...


class NumericTCPConnector:
    def connect(self, address: Address, port: int, deadline: Deadline, timeout: float) -> None:
        if not isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)) or (
            type(port) is not int or not 1 <= port <= 65535
        ):
            raise PolicyError("invalid_target", 2)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        connection = socket.socket(family, socket.SOCK_STREAM)
        try:
            connection.settimeout(deadline.remaining(timeout))
            if address.version == 6:
                connection.connect((str(address), port, 0, 0))
            else:
                connection.connect((str(address), port))
        finally:
            # Also closes on KeyboardInterrupt. No send/recv/shutdown protocol traffic.
            connection.close()


def connect_outcome(error: OSError) -> tuple[str, int | None]:
    """Only explicit OS refusal means refused. Timeout never means closed/filtered."""
    code = getattr(error, "winerror", None) or error.errno
    code = code if type(code) is int and 0 <= code <= 65535 else None
    if isinstance(error, TimeoutError) or code in {errno.ETIMEDOUT, 10060}:
        state = "timeout"
    elif isinstance(error, ConnectionRefusedError) or code in {errno.ECONNREFUSED, 10061}:
        state = "refused"
    elif code in {errno.EHOSTUNREACH, errno.ENETUNREACH, 10051, 10065}:
        state = "unreachable"
    elif code in {errno.ECONNRESET, 10054}:
        state = "reset"
    elif isinstance(error, PermissionError) or code in {
        errno.EACCES,
        errno.EPERM,
        errno.EMFILE,
        errno.ENFILE,
        errno.ENOBUFS,
        errno.ENOMEM,
        errno.EAFNOSUPPORT,
        10013,
        10024,
        10047,
        10055,
    }:
        state = "local_error"
    else:
        state = "error"
    return state, code
