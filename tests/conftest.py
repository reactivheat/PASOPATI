"""Keep tests offline and all diagnostic writes inside pytest temporary paths."""

import ipaddress
import socket
from pathlib import Path
from typing import Any, NoReturn

import pytest

import pasopati.doctor as doctor_module

_REAL_SOCKET = socket.socket
_REAL_GETADDRINFO = socket.getaddrinfo


def pytest_configure(config: pytest.Config) -> None:
    """pytest creates basetemp itself but requires its parent to exist on fresh clones."""
    if config.option.basetemp is not None:
        Path(config.option.basetemp).parent.mkdir(parents=True, exist_ok=True)


@pytest.fixture
def local_sockets(monkeypatch: pytest.MonkeyPatch, offline_environment: None) -> None:
    """Opt-in integration fixture: socket calls remain restricted to numeric loopback."""

    def check_address(address: object) -> None:
        if not isinstance(address, tuple) or not isinstance(address[0], str):
            raise AssertionError("Numeric loopback endpoints only")
        if not ipaddress.ip_address(address[0]).is_loopback:
            raise AssertionError("External network access forbidden")

    class LoopbackSocket(_REAL_SOCKET):
        def connect(self, address: object) -> None:
            check_address(address)
            super().connect(address)  # type: ignore[arg-type]

        def connect_ex(self, address: object) -> int:
            check_address(address)
            return super().connect_ex(address)  # type: ignore[arg-type]

        def bind(self, address: object) -> None:
            check_address(address)
            super().bind(address)  # type: ignore[arg-type]

        def sendto(self, *args: Any, **kwargs: Any) -> int:
            check_address(kwargs.get("address", args[-1] if args else None))
            return super().sendto(*args, **kwargs)

    monkeypatch.setattr(socket, "socket", LoopbackSocket)
    monkeypatch.setattr(socket, "getfqdn", lambda name="": "localhost")

    def numeric_only(host: str, port: int, *args: object, **kwargs: object) -> object:
        check_address((host, port))
        return _REAL_GETADDRINFO(host, port, flags=socket.AI_NUMERICHOST)

    monkeypatch.setattr(socket, "getaddrinfo", numeric_only)


@pytest.fixture(autouse=True)
def offline_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def no_network(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("Tests must not access the network")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(doctor_module, "default_config_dir", lambda: tmp_path / "config")
