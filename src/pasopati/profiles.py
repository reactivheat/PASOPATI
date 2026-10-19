"""Immutable built-in policies, not operational scanners."""

from dataclasses import dataclass
from types import MappingProxyType

from pasopati.core.errors import PolicyError


@dataclass(frozen=True)
class Profile:
    name: str
    network_enabled: bool
    methods: tuple[str, ...]
    request_budget: int
    requests_per_second: float
    concurrency: int
    max_redirects: int
    connect_timeout: float
    read_timeout: float
    total_timeout: float
    max_body_bytes: int


PROFILES = MappingProxyType(
    {
        "passive": Profile("passive", False, (), 0, 0.0, 1, 0, 3.0, 5.0, 10.0, 65536),
        "safe": Profile("safe", True, ("GET", "HEAD"), 50, 1.0, 2, 3, 3.0, 5.0, 10.0, 65536),
    }
)


def get_profile(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise PolicyError("unknown_profile", 2) from exc
