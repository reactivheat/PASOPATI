"""Keep tests offline and all diagnostic writes inside pytest temporary paths."""

import socket
from pathlib import Path
from typing import NoReturn

import pytest

import pasopati.doctor as doctor_module


@pytest.fixture(autouse=True)
def offline_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def no_network(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("Tests must not access the network")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(doctor_module, "default_config_dir", lambda: tmp_path / "config")
